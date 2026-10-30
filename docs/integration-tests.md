# Run the integration tests

Exercise C8s on a plain Linux or macOS host with no TEE hardware, so neither of
the first two harnesses proves a confidential property: docker-compose, for the
armTLS certificate flow (armTLS is C8s's mutual TLS whose certificates carry TEE
evidence), and kind, for a whole cluster. CI runs both as the **Integration**
and **Integration (cluster)** jobs; terms are defined in
[glossary.md](glossary.md).

The Pod CVM lanes at the end of this page add scheduler and runtime harnesses
to ordinary CI, plus explicit acceptance runs on Cloud and metal TDX, which do
prove hardware properties.

Prerequisites:

- Both harnesses: docker with Compose v2 (`docker compose`), make, OpenSSL
  (macOS LibreSSL lacks `x509 -ext`), and curl.
- The kind harness also: kind, kubectl, helm, go, and python3 with PyYAML.
  Podman works as kind's provider with `KIND_EXPERIMENTAL_PROVIDER=podman`, but
  `docker` must stay on PATH: the harness builds images and reaches into the
  node with it. CI pins helm and kind in
  `.github/actions/setup-kind-harness`.

Run both from the repository root:

```sh
make test-integration
make test-integration-cluster
```

The first starts a mock CDS — the service that verifies evidence and signs
workload certificates — and a mock attestation-api, the node-local service that
produces hardware evidence for CDS and every other component. It runs get-cert,
the sidecar that obtains a pod's certificate, through the real armTLS flow, and
checks that nginx serves HTTPS with the issued certificate. The second boots a
kind cluster, builds the component images, and runs
`c8s install --cvm-mode=bare-metal`. Each ends with its check count:

```text
=== All <N> integration checks passed ===
=== All <N> cluster integration checks passed ===
```

## What the kind harness substitutes

The TEE is replaced at exactly one point: evidence generation.
`test/mock-attestation` serves synthetic SNP reports with an all-zero launch
measurement on the node IP `:8400`, the address `bare-metal` consumers dial for
the node-baked attestation-api. It answers verification requests too, so no hop
proves a hardware property; what matches production is the pinning — that
measurement is the pinned CDS measurement, compared exactly as in production —
and every component delegating verification to the attestation-api works
unchanged.

The rest is real: the admission webhook and validating admission policies in a
real API server, the admission plugin registered against the node's containerd,
certificate issuance with sandbox identity, the armTLS mesh, workload adoption,
and uninstall. Allowlist and route writes are signed with the production
operator-token signer and verified by CDS; only the client-side evidence check
is skipped, so they travel plain `curl`.

The kind node image is pinned by digest in `test/integration/cluster/lib.sh`;
bump it with the kind release. A replacement needs a containerd whose NRI
supports `ValidateContainerAdjustment`, the call the plugin's environment and
mount enforcement runs in.

## What it does not cover

No TEE property is asserted. Hardware verification, measurements that mean
anything, encrypted volumes (`volumed` needs the node kernel's device mapper),
`c8s get-kubeconfig`, and the `c8s verify`, `c8s allowlist` and `c8s routes`
CLIs stay on the hardware CI lanes (`snp-metal-e2e`, `tdx-metal-e2e`,
`cvm-e2e`): those verify evidence in process with real hardware cryptography,
which synthetic evidence cannot pass.

## Keep the cluster for another driver

```sh
C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1 C8S_IT_WORKDIR=/tmp/c8s-it ./test/integration/cluster/run.sh
```

`C8S_IT_SETUP_ONLY=1` stops once the stack is installed, before the checks.
`C8S_IT_KEEP=1` leaves the kind cluster and the work directory (operator key,
`optoken`, image-store scan) in place, at `C8S_IT_WORKDIR`.

The run writes `$C8S_IT_WORKDIR/env`, which exports a `KUBECONFIG` for the kept
cluster whatever kubectl's current context is. Source
`test/integration/cluster/lib.sh` and then that file to drive the cluster with
the harness's own helpers (`cds_write`, `cds_get`, `node_exec`, `run_pod`, and
the rest). They open the shared CDS port-forward on demand with `cds_pf_start`,
record its pid in `$C8S_IT_WORKDIR/cds-pf.pid`, and `cds_pf_stop` ends it.
Delete the cluster with `kind delete cluster --name c8s-it`.

## When a run fails

- A pod stuck in `CreateContainerError` with `image not in allowlist` is the
  admission plugin doing its job: the image's containerd store digest is absent
  from the install-time allowlist, which the harness writes from the node's
  image store before install. Pre-pull the image in the
  `node_exec ctr -n k8s.io images pull` block near the top of `run.sh`.
- The mock-attestation Deployment is `Recreate` on purpose: two host-network
  pods cannot both bind `:8400` on a single-node cluster.

## Pod scheduler and runtime CI

The scheduler lane needs Go, Docker and kind. It creates a disposable cluster
with a private kubeconfig and runs the production admission webhook, provider
and virtual Node controller against the real API server, scheduler and
controller-manager. It checks normal scheduling, Node leases, frozen launch
intent before creation, lost-response recovery, verified readiness projection,
foreign-UID refusal, immutable workloads, controller restart, delayed deletion
and recreation with a new UID. Cloud and authenticated guest responses are test
adapters; this lane makes no hardware claim. The job also runs offline ownership
and recovery tests for the live Cloud runner.

Both scheduler and Cloud harnesses constrain kind's `kindnet` and `kube-proxy`
DaemonSets to the existing physical control-plane node before registering the
virtual node. Existing node selectors are preserved. Scheduler CI advertises
two Pod slots and verifies that two opted-in workloads can run concurrently,
with infrastructure DaemonSets excluded from those slots.

Run `make test-integration-pod-runtime` with Go, Python 3 and Docker supporting
privileged containers. The existing `Integration (Pod runtime)` CI job invokes
this command and requires all three checks:

1. Start authorization: one offline workload executes only after its exact NRI
   container, sandbox and process identity is consumed once. Seven cases reject
   execution: missing authority, policy denial, measurement failure, callback
   timeout, lost socket, plugin disconnect and replay.
2. Production NRI recovery: separate containerd and full plugin processes restart
   while the original sandbox and task remain alive. The test verifies the task's
   actual cgroup/process identity, complete admission history including a removed
   same-image workload, unchanged measurements and credential identity, and refusal
   of old permissions. Missing, malformed and interrupted recovery state must
   refuse startup.
3. Standalone kubelet recovery: the real kubelet owns a static Pod with a mesh
   sidecar and application. Restarting kubelet, containerd and the full plugin must
   preserve the staged manifest/configuration, Pod UID, running task identities,
   complete claims and measurements. The kubelet's `/pods` response is checked
   against its serving certificate and the actual containerd tasks.

The runner extracts digest-pinned RKE2 runtime/kubelet and CNI release binaries
for the Docker daemon's native architecture. It uses the production `c8s-runc`,
full NRI callbacks for recovery, real namespace protection, and memory-backed
recovery/credential volumes. The first check isolates the start-permission
boundary; the recovery checks use the complete configured plugin.

Measurement registers, CDS transport and credential issuance are fixtures.
Containerd uses the native snapshotter and cgroupfs. This lane does not exercise
the assignment endpoint, issue a real Pod certificate, or establish guest-airgap
byte equivalence, systemd ordering, overlay filesystem behavior or TDX/cloud
acceptance.

Both scheduler and runtime lanes require fresh result receipts and fail when
prerequisites or required assertions are missing. The runtime lane requires
`result.json`, `recovery-result.json` and `kubelet-recovery-result.json`, each bound
to the current invocation, plus successful cleanup. Evidence includes runtime,
kubelet and CNI binary hashes and bounded logs. The lanes remove only their owned
local resources; the runtime container has no host mounts or network access.
Set `C8S_PODPROVIDER_ARTIFACTS` or `C8S_POD_RUNTIME_ARTIFACTS` to a new evidence
directory. CI retains those artifacts for seven days.

## Pod Cloud acceptance

The live lane needs Go, Docker, kind, jq, Python 3 and GNU timeout, an authorized Cloud
credential, and an admitted matching production Pod/CDS image pair. Supply an
absolute JSON input path with these fields:

```json
{
  "source": "<40-character production source commit>",
  "cloudURL": "https://api.cloud.confidential.ai",
  "tokenFile": "/private/path/cloud-token",
  "image": "c8s-pod@<version>",
  "cdsImage": "c8s-pod-cds@<same-version>",
  "manifestFile": "/private/path/manifest.json",
  "manifestDigest": "sha256:<manifest digest>",
  "diskDigest": "sha256:<raw disk digest>",
  "cliFile": "/private/path/matching-linux-c8s",
  "cliSHA256": "<64-character digest>",
  "probeFile": "/private/path/linux-pod-mesh-probe",
  "probeSHA256": "<64-character digest>",
  "meshImage": "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:<digest>",
  "size": "s1.2x",
  "location": "us-west-1",
  "vCPUs": 2,
  "memoryMiB": 8192
}
```

Build the CLI from the production image's source and the probe from
`.github/scripts/pod-mesh-probe`, both for the Docker daemon's Linux architecture.
The manifest, raw disk, mesh image and source must come from the same paired
production publication. The runner checks file digests and catalog identity;
the caller supplies the publication provenance.

The new state directory must be under a host path shared with the Docker
daemon. For Colima or another Docker VM, use a path configured in that VM's
mounts, such as a shared checkout's `target/` directory; `/private/tmp` is not
necessarily shared. The runner compares a fresh host nonce and the runner's
SHA256 inside the container before starting any Cloud work. A failed mount
check leaves only local setup, which the cleanup command can remove.

```sh
export C8S_PODCLOUD_LIVE=1
export C8S_PODCLOUD_INPUT=/private/path/input.json
export C8S_PODCLOUD_STATE=/absolute/docker-shared-checkout/target/new-run
make test-integration-pod-cloud
```

The default `connected` scenario creates a private local kind cluster, one CDS
guest and two Pod guests. It starts production provider `Setup` compiled from
the checkout; the provider creates the Pod guests after normal Kubernetes scheduling. Acceptance
checks exact measured workloads, authenticated status,
readiness withdrawal and recovery, peer mesh traffic, HTTPS and DNS egress,
certificate renewal over at least 65 minutes, rejected unauthenticated traffic,
and deletion through the production provider. It reuses the connected native
lane's acceptance predicates. The run requires at least six Cloud vCPUs and
24 GiB of memory plus a CDS scratch disk; provisioning and cleanup add time to
the observation window.

Set `"scenario": "verification-timeout"` in the input to test bounded verification
failure separately. This scenario needs one CDS guest and one Pod guest (four
Cloud vCPUs and 16 GiB with the example shape). Its small HTTP workload becomes
ready independently of peer traffic. After real TDX verification and provider
readiness, it injects an unavailable verification result, restarts the provider
with a longer configured timeout, and holds a real verified response
until after the original persisted 600-second deadline. Acceptance requires
withdrawn readiness/endpoints, `GuestVerificationTimedOut`, and confirmed Cloud
termination before deleting the Kubernetes Pod. Provisioning and cleanup add
time to the ten-minute failure window. The injected fault is provider result
unavailability/latency; it does not simulate a hardware attestation failure.
The private `verification-timeout.json` records the deadline and observation times.

Set `"scenario": "warm-assignment"` to test generic boot and a warm allocation.
This needs a paired image containing the generic assignment guest, plus capacity
for CDS, one assigned Pod guest, and one idle replacement (six Cloud vCPUs and
24 GiB with the example shape). The provider starts with `maxPods=2` and
`warmTarget=1`. The driver verifies empty attested measurements and no Pod authority
before scheduling, then observes normal scheduling, a reciprocal UID-fenced claim,
and the exact signed assignment persisted before its real POST. It requires a
conflicting signed assignment to be rejected, authenticated readiness and exact
workload digests, stable assignment and certificate identity across provider
restart, and draining the unused allocation with `warmTarget=0`. Deletion must
confirm Cloud termination before releasing the assigned allocation. Identical
assignment retries are allowed before verified readiness; the evidence requires
one acknowledged acceptance and no further assignment POSTs after readiness.

This scenario uses the production reconciler and elected manager workers with
observing wrappers around real Cloud and assignment clients. It records ownership
of each allocation generation before creation, including unclaimed replacement
guests. The run's private evidence includes the signed assignment and must stay
private. Bounded `warm-read-*.json` receipts retain the first three and latest 21
sampled status observations, with verification errors, UTC times, the deadline,
and separately timed Cloud instance status. They use the existing verification
call and do not extend its deadline. `assignment-posts.json` records immutable
retry accounting. Existing scheduler integration tests separately cover competing claims,
lost assignment replies, stale writes, forced deletion and replacement generations.

Set `"scenario": "cds-outage"` to test retention of an authenticated CDS policy
update through a network outage and one application restart. It needs one CDS
guest and one Pod guest (four Cloud vCPUs and 16 GiB with the example shape),
plus the CDS scratch disk. For the `2026.10.30-1` publication, use
`c8s-pod@2026.10.30-1`, `c8s-pod-cds@2026.10.30-1` and source
`05211a8b106415a0aefd5f47bc40b266b0c1dacd`, with that publication's matching pins
and CLI. Use the same input, run and cleanup commands above and below.

The immutable tenant launch policy admits only the mesh. CDS also includes
baked component entries: before adding the app rule, the driver freezes its
complete authenticated export and verifies the exact mesh rule and absence of
any app admission. Adding or removing the app must preserve every other entry.
The signed app update precedes normal Kubernetes scheduling. The driver removes
only the run-owned CDS ingress on port 30808, waits for the change to apply, and
preserves status access. The app first proves CDS reachability, then requires
120 seconds of continuous connection failures before its one controlled exit.
Acceptance requires fresh admission during the outage, unchanged guest boot and mesh
identity, and exact measured digests. The driver restores the original ingress
and endpoint, authenticates the same CA, deletes the signed app rule and observes
at least 70 seconds without readmission, with Kubernetes readiness withdrawn.
Post-revocation acceptance also requires mesh readiness to remain withdrawn
for that interval. Its process identity and start time, and the guest boot
identity, must remain unchanged despite credential withdrawal.

Private evidence includes `cds-outage.json`, numbered `cds-observation-*.json`,
and policy/ingress intents and receipts. Authenticated observations are retained
before phase validation, including samples that fail. All 11 scenario assertions,
provider deletion and owned cleanup must pass. This tests CDS network outage and
served policy retention; guest service restart, CDS process restart and long-outage
certificate renewal require separate acceptance.

All scenarios compile the provider from the current checkout. Its commit,
dirty status and executable hash are recorded in `provider-build.json`; the
result's executable hash must match the runner that was built and executed.
The input `source` still identifies the paired guest/CLI publication. This lets
provider-only scenarios run before merging the provider or publishing new guest
images, without claiming coverage of guest features absent from the pinned image.
The `warm-assignment` scenario requires those guest features in its pinned image;
a successful static or timeout run does not establish warm-assignment acceptance.

Infrastructure DaemonSets in a real cluster must also exclude Pod-CVM virtual
nodes. Broad `Exists` tolerations can bypass their `NoSchedule` taint; critical
DaemonSet Pods can then preempt tenant Pods before the provider rejects their
missing opt-in. Apply node placement constraints to networking, kube-proxy and
host installers, including relevant C8s DaemonSets. The harness's kind-specific
hostname constraint is test setup, not automatic production configuration.
The live runner stops boot polling promptly if the submitted Pod disappears,
is replaced, is disrupted or deleted, or its provider record becomes terminal;
the private `boot-failed-<side>.json` preserves the bounded failure reason.

The state directory contains credentials and signed launch material. Keep it
private and never upload it as a CI artifact. Ownership is persisted before
Cloud creates. On interruption, retain the directory and resume cleanup:

```sh
export C8S_PODCLOUD_LIVE=1
export C8S_PODCLOUD_STATE=/absolute/docker-shared-checkout/target/existing-run
make cleanup-integration-pod-cloud
```

Cleanup uses the recorded identities and never starts another Cloud run. A
successful acceptance requires `result.json` with `passed: true` and a ledger
with `complete: true`, matching scenario, exact scenario assertions, and matching
provider executable identity; cleanup success alone does not prove acceptance.

## Connected Pod acceptance on TDX

The manual `tdx-metal-e2e.yml` input `pod_acceptance: true` starts a real CDS
server and two standalone Pod guests. The image, image manifest, disk, mesh
container and matching CLI source are pinned in
`test/tdxpod/fixtures/pod-connected/production-image.json`. Image profile
and component sources must agree. Update the complete pin set together after
a paired production image build; the harness does not accept a development
image or substitute a fake CDS. The lane tool (`test/tdxpod`) and the paired
CLI build with the dispatched commit's Go toolchain, so the pinned source's
`go` directive must not exceed the dispatched tree's.

```sh
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref podcvm/no-mesh-gate -f pod_acceptance=true
```

The two signed workloads test authenticated peer traffic, IPv4 HTTPS, system
DNS, TCP/UDP DNS, and guest/link-local connection denials. Authenticated Pod
status must show readiness withdrawing and recovering, followed by successful
checker exits after at least 65 minutes. The tool tracks the authenticated
`Ready` condition's `lastTransitionTime` beside app and mesh readiness, rejecting
hidden transitions between ready samples and further withdrawals after recovery.
A successful checker exit may withdraw aggregate Pod readiness once while the
app and mesh stay ready. Each verdict and its authenticated status are saved
before certificate probes or a readiness failure, including the final status
after the negative probes. Polling does not establish continuous readiness between
observations. Public mesh leaves must rotate late in
the observation window, with new serials and keys, stable Pod identities and
CA, and no application, checker or endpoint restarts. Certless, wrong-CA and
plaintext requests must be rejected, followed by fresh healthy Pod status.

Three run-owned Services allocate the addresses signed into the launch inputs.
Guest-to-guest traffic uses those Services. If runner network policy prevents
direct observations, the runner uses owned VMI port-forwards for attestation,
status and certificate probes. Keys remain in the private runner directory or
their intended guest. The test uses one shared read-only root import, a private
server scratch disk, and approximately 8 vCPUs and 32 GiB of guest memory.

The `pod-connected-acceptance-<run>-<attempt>` artifact retains image identity,
authenticated attestations/status, public certificates, negative-probe receipts,
bounded boot logs and cleanup results for seven days. Acceptance requires both
the exact expected-digest checks and the timed observations. Failure artifacts
include bounded CLI errors and separately labeled diagnostic attestations;
those diagnostic reports cannot satisfy acceptance. Completion requires
`result.json` with `passed: true` and `cleanup.json` with `complete: true`, plus
a successful workflow. Cleanup always removes owned resources; `keep_cvm` does
not apply. Select exactly one Pod mode per dispatch.

This lane validates static Pods on native KubeVirt TDX hardware. Cloud API
provisioning and Kubernetes provider assignment, discovery and deletion remain
separate acceptance work. Guest exclusion checks observe connection denial;
the privileged Linux suite supplies controlled listener and source-NAT checks.

## Pod guest service recovery on TDX

The manual `pod_recovery: true` mode uses a separately measured test image over
production source `05211a8b106415a0aefd5f47bc40b266b0c1dacd`. First
[build the recovery fixture](../node-guest-image/README.md#measured-pod-recovery-fixture).
It needs the native TDX launcher, KubeVirt/CDI and approximately eight vCPUs and
32 GiB of guest memory. Select this mode alone; leave `c8s_ref` empty and use the
same workflow ref/commit as the fixture build. A changed harness commit requires
a new fixture build.

Download the successful build's artifact and supply its exact `image.json`
bytes and independently calculated SHA256. Preserve the trailing newline; do
not reserialize the receipt or infer image digests from tags.

```sh
fixture_ref='<branch-or-tag-at-the-fixture-build-commit>'
build_run='<successful-fixture-build-run-id>'
gh run download "$build_run" --repo confidential-dot-ai/C8s \
  --name "pod-recovery-fixture-$build_run" --dir recovery-build
receipt_sha256="$(python3 -c \
  'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("recovery-build/image.json").read_bytes()).hexdigest())')"
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref "$fixture_ref" -f pod_recovery=true \
  -F pod_recovery_receipt=@recovery-build/image.json \
  -f pod_recovery_receipt_sha256="$receipt_sha256"
```

The driver freshly attests and assigns two generic Pod guests beside a real CDS.
After an externally observed baseline, the immutable controller performs its
fixed, once-per-boot sequence: status service, kubelet, then containerd and
kubelet. Its bounded read-only receipt is fetched over an attested connection;
there is no remote restart API. Acceptance requires the expected service/NRI
process changes, unchanged boot, assignment, admission history and running task
identities, recovered authenticated readiness and stable workload/CA identity.
The app, mesh and checker must all remain running, with unchanged container
starts and task PID/birth identities. Bounded waits accommodate the workload's
intentional readiness dip before a restart and during final external observation.
The final readiness wait is at most four minutes, capped by the existing
observation and run deadlines; identity, admission history and process continuity
remain required throughout.
Recovery finishes while the checker is still live; the connected lane separately
validates its 65-minute soak and certificate renewal.

The `pod-service-recovery-<run>-<attempt>` artifact retains image identity,
authenticated baseline/completion receipts, failed authenticated observations and
cleanup evidence for seven days.
A pass requires `result.json` with `passed: true`, `cleanup.json` with
`complete: true` and a successful workflow. Owned cleanup always runs;
`keep_cvm` does not apply. Local tests or a successful fixture build alone do
not establish hardware acceptance. This lane covers production runtime
components under the measured overlay; it does not establish guest-restart
acceptance for the exact `2026.10.30-1` image or Cloud provider lifecycle.

## Diagnosing Pod runtime startup on TDX

The manual input `pod_runtime_diagnostic: true` uses separate immutable pins in
`test/tdxpod/fixtures/pod-connected/development-image.json` and the same lane
tool, real CDS and two-Pod provisioning. It collects bounded systemd unit,
journal, CRI and containerd-plugin observations through the run-owned Pod
consoles. Private raw console transcripts are not uploaded; public evidence
contains fixed projections with sensitive records omitted. UID checks bind
observations and cleanup to the resources created by that run.

Runtime diagnostics use their own serialized workflow queue and request eight
CPUs and 32 GiB of guest memory, plus virtualization overhead. Scheduling is
bounded; unavailable capacity fails the run and triggers cleanup. Terminal
control sequences are removed before parsing the projected console records;
framing failures retain counts only, without publishing raw console text.

```sh
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref podcvm/no-mesh-gate -f pod_runtime_diagnostic=true
```

The development image has different measurements and bypasses `c8s-runc` through
`60-dev-runc.toml`. Its outcome is diagnostic-only and cannot satisfy production
acceptance. The runner does not perform the timed acceptance observations.
The `pod-runtime-diagnostic-<run>-<attempt>` artifact retains public observations
and the cleanup receipt for three days. A complete diagnostic run requires
`captureComplete: true` and cleanup `complete: true`; neither means the Pod
workload passed. Cleanup always runs, and `keep_cvm` does not apply.

## Diagnosing a Pod boot on a commit's dev image

The manual `tdx-metal-e2e.yml` input `pod_diagnostic: true` boots the
`rke2-tdx-dev` image published for one commit (root autologin on the serial
console, its own measurement) with the Pod fixture signed by the CLI built from
that same commit, so the serial log shows which unit or admission step stops a
Pod that the production image only reports as Pending. `pod_image_source`
names that commit by full SHA; empty means the dispatched commit. The source
must be that commit or one of its ancestors, checked before toolchain setup or
building the paired CLI. For another lineage, dispatch a matching branch or
historical workflow ref that contains this lane. The lane resolves
`rke2-tdx-dev-<sha7>` and `rke2-tdx-dev-cdi-<sha7>` from the registry
at run time and fails by naming the missing tag, with the manual image build
command that publishes it. The fixture Pod carries no mesh endpoint; the guest
injects the measured one.
The job builds the paired CLI from `pod_image_source` and the lane tool
(`test/tdxpod`) from the dispatched commit with the source commit's Go toolchain,
so the dispatched tree's `go` directive must not exceed the source's.
It uses the existing TDX launcher, a private root import and run-owned VM and
launch Secret. Cleanup always runs; `keep_cvm` does not retain diagnostic VMs.
The `pod-boot-diagnostic-<run>-<attempt>` artifact contains the first and last
256 KiB of the serial log per sample (`NNN-serial`, `NNN-serial-tail`; a dev
image forwards its journal to ttyS0, so the tail carries the latest service
output), bounded launcher logs, image identity, native status and the cleanup
receipt. It omits
private signing keys and expires after seven days.

```sh
gh workflow run c8s-image-manual.yml --repo confidential-dot-ai/C8s \
  --ref <branch at the commit> -f dev=true -f c8s_ref=<sha7>
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref <branch with this lane> -f pod_diagnostic=true -f pod_image_source=<full sha>
```

This mode diagnoses boot only. It deliberately uses an unavailable CDS and a
separately measured development image; it does not establish production-image,
mesh, internet or DNS acceptance. The normal node lane and automatic exact-image
acceptance keep their existing validation.
