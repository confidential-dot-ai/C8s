# Disposable SNP recovery image

This local qualification image tests the missing hardware primitive: seal a
random sentinel, destroy the guest, and recover the same sentinel on the same
chip. It does not run CDS or hold a CA key. It changes no production image,
catalog entry, launcher, host setting or deployment workflow.

The measured runtime contains the probe binary, a fixed systemd service, and
the existing confos verity root/kernel/IGVM boot chain. Cloud-init is disabled;
console login, rescue/emergency shells, SSH and the QEMU guest-agent service
are masked in the image. Do not compose it with `dev`, `ssh`, general-purpose
or workload profiles. Only the SNP platform and 2-vCPU variant are built.

## Local build

Use the builder and mkosi revisions in `.github/build-pins.json`, its pinned
Ubuntu snapshot and SNP firmware. The builder requires a Linux mount/user
namespace environment, its Rust toolchain, mkosi and systemd-nspawn. No workflow
dispatch or CI is needed. Stage new source files before building so the local
source receipt includes them.

```sh
CONFOS_DIR=/path/to/pinned/confidential-os-builder \
PROBE_BUILD_DIR=/path/to/dedicated/probe-build images/cds-snp-probe/build
```

`--stage-only` builds the static Go binary and records its SHA-256, source
parent/diff, Go version and builder pins. It does **not** produce a measured VM
image. To finish in a local build container, copy this directory's `snp-probe/`
profile and the staged `extra/` into that container and run the same pinned
builder with `--platform snp --smp 2 --memory 4G`, `--profile-dir` and `--extra`.
Record the firmware digest, final `manifest.json`, all artifact digests and
the build log. A failed build must not emit a qualification result.

## Hardware exchange

The launch file is public, fixed across seal/recovery and delivered through
the existing read-only `opkeydata` path. Its exact bytes must match SNP
HOST_DATA; the measured initrd and probe both check that binding. The expected
launch digest comes from the independently built manifest, never from a guest
response. The dedicated fixture renderer uses the SDK's opaque launch-file
format. This file carries no key or command; the image has no SSH service.

The probe listens on TCP 8445. It accepts only bounded `seal`/`open` messages
for disposable sentinels; it has no file, shell, arbitrary report-signing or
secret-release endpoint. One actor owns the SNP device, with eight queued
operations, HTTP 429 backpressure and at most 32 accepted connections. Do not
expose a public Service; use the authenticated native VM port-forward.

```sh
virtctl --kubeconfig "$TEST_KUBECONFIG" -n "$TEST_NAMESPACE" \
  port-forward "vmi/$OWNED_VMI" 24445:8445

snp-probe request -operation seal -expect sealed \
  -measurement "$INDEPENDENT_SNP_MEASUREMENT" -launch-file ./launch.pub \
  -capsule-file ./sentinel.json > seal-receipt.json

# Destroy the owned VM; wait for its VMI UID to disappear. Recreate it with
# the identical measured image and launch file on the same pinned worker.
# Re-establish the authenticated port-forward to the NEW VMI UID.
snp-probe request -operation open -expect opened \
  -measurement "$INDEPENDENT_SNP_MEASUREMENT" -launch-file ./launch.pub \
  -capsule-file ./sentinel.json > same-chip-receipt.json

# Repeat on an independently selected SNP worker/chip, one VM at a time.
snp-probe request -operation open -expect rejected \
  -measurement "$INDEPENDENT_SNP_MEASUREMENT" -launch-file ./launch.pub \
  -capsule-file ./sentinel.json > other-chip-receipt.json
```

Each request creates a fresh nonce. The AMD-signed REPORT_DATA binds the full
request and response, including ciphertext and outcome. The host client
checks the independent image/configuration pins, non-debug/non-migratable
VMPL-0 policy, unmasked VCEK chip identity, report signature and issuer
revocation. A network error cannot count as the different-chip rejection.
Only an authentication failure after successful hardware key derivation counts
as rejection; a device or firmware error fails the run. Capsule files contain
only ciphertext and public metadata; creation refuses
overwrite. Neither plaintext sentinel nor derived key leaves the probe.

Compare the **verified chip hashes**, not only Kubernetes node names: same-node
placement alone does not prove same-socket execution. The seal and same-chip
receipts must have identical capsule/digest and chip hash, fresh nonces,
distinct firmware-signed guest report IDs and distinct VMI UIDs; the rejection
receipt must have a different chip hash and the exact original capsule in its
request. A control request before destruction must keep the live guest's
report ID while changing the request nonce.

## Isolation and cleanup

`test/pilot/cds-sealed-recovery/hardware/render.go` renders the native ConfAI
objects using the dependency pinned by the Cloud operator module. Compile it
from that module, without modifying its sources:

```sh
cd "$CLOUD_SOURCE/operator"
go build -o "$PROBE_BUILD_DIR/render" \
  "$C8S_SOURCE/test/pilot/cds-sealed-recovery/hardware/render.go"
```

`hardware/run.py` runs seal → live-guest control → destroy/recreate → same-chip
open → cleanup → different-chip rejection → cleanup, sequentially. It uses the existing Cloud
rehearsal HTTP/kubeconfig helper and records every creation intent and object
UID before advancing. Public disk/IGVM files travel through an owned temporary
population Pod into new claims; hashes must match before the Pod is removed
and the halted VM is started. It needs no registry push or Cloud API rollout.
This native hardware qualification is separate from the public API comparison.

Uploads have an explicit byte bound and emit extraction progress. The receiver
writes a fresh completion token only after successful extraction. The runner
reads it over a separate authenticated exec and then checks the artifact hashes;
it can close an upload client that is still waiting for a lost exit response.
Neither a client timeout nor a full-size destination file counts as completion.

```sh
python3 "$C8S_SOURCE/test/pilot/cds-sealed-recovery/hardware/run.py" run \
  --directory "$NEW_RUN_DIRECTORY" --cloud-repo "$CLOUD_SOURCE" \
  --kubeconfig "$TEST_KUBECONFIG" --kubectl "$KUBECTL" --virtctl "$VIRTCTL" \
  --image "$CONFOS_DIR/output/cds-snp-probe" \
  --renderer "$PROBE_BUILD_DIR/render" \
  --probe "$PROBE_BUILD_DIR/extra/usr/local/bin/snp-probe" \
  --tools-image "$PINNED_EXISTING_TOOLS_IMAGE" --nodes "$SNP_WORKER_A" "$SNP_WORKER_B"
```

If interrupted, use `cleanup` with the same directory, Cloud checkout,
kubeconfig and native tool arguments. Cleanup refuses replaced UIDs or changed
ownership. No service/host/namespace deletion is permitted. The runner checks
Node boot IDs and existing VMI readiness; it does not exercise customer
application traffic or establish nondisruptive fleet upgrades.

Prepare a run-specific manifest and durable ownership journal before creating
anything. Use one 2-vCPU/4-GiB guest at a time, exact worker UIDs, only new
test-owned storage, no hostPath writes, and a finite cleanup deadline. Preserve
an encrypted capsule and public receipts locally before destroying a guest.
The measured image powers off after 45 minutes. The fixture's `Manual` run
strategy requires explicit starts and keeps an expired guest off. This fallback
bounds guest runtime if the runner disappears; it does not delete the VM or
claims, which still require the ownership journal's cleanup command.
Never mutate shared image admission, deployments, KubeVirt configuration,
network policy, firmware, host scheduling or existing VMs to unblock this test.
If the existing launch path cannot admit the artifact, stop at the concrete
image/manifest and review that separate rollout.

Record all created object UIDs. Delete only those exact owned UIDs, then check
for remaining owned resources. Capture existing VM readiness, Node boot IDs
and relevant service health before/after; a surviving VMI UID alone is not an
availability check. Do not delete a shared namespace or a production cache.

## What a pass establishes

A successful run establishes a chip-bound disposable-secret recovery primitive
for the exact image/platform tested. It does not establish CA-key custody,
independent-host recovery of the same CDS key, a qualified minimum firmware
TCB, safe image retirement or the complete acceptance goal. The receipts keep
those claims false. Signature/issuer-CRL verification is distinct from an
approved minimum TCB policy. Old measured code may still derive its old key.

The storage protocol and its current-policy release gate are unchanged. See
[the custody design](../../docs/cds-sealed-custody-experiment.md) and
[current release policy](../../docs/cds-current-release-policy.md) for those
separate guarantees and the cold-history rollback assumption.
