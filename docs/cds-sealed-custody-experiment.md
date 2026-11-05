# CDS custody recovery experiment

This experiment keeps the object WAL and its existing commit point. It asks
whether a few independently protected copies of the recovery keys can remove
the need for a separate stateful key service. It builds on
[immutable enrollment](cds-recovery-acceptance.md); it does not replace that
pilot or qualify a production Raft migration.

The [current-release-policy increment](cds-current-release-policy.md) implements
the mandatory WAL-based check described below and tests both storage variants.
The static-sealing counterexample and hardware boundaries remain relevant.

The candidate is: **encrypted WAL, replaceable CDS compute, and independently
sealed recovery copies**. Each copy contains the same WAL encryption key and
release-signing seed, encrypted under a different protected wrapping key.
There is no new election or issuance ledger. The existing authority retains
its per-cluster bounded admission actor. Sealing adds no shared mutable state.

## Implemented and checked locally

`internal/cdsrecovery/capsule.go` adds the sealing primitive. AES-256-GCM binds
each encrypted copy to its cluster, launch configuration, object prefix and
the exact signed enrollment. Restoring validates the enrollment and key
commitment again. Temporary plaintext buffers are cleared; this is memory
hygiene, not proof that a host administrator cannot extract process memory.

The new tests cover:

| Check | Local evidence |
| --- | --- |
| Recovery after authority exit | A fresh subprocess restores the keys and issues a recipient-bound grant. The parent clears its WAL/signing-key buffers before starting it. |
| One recovery anchor lost | The next subprocess uses the other independently wrapped copy and recovers the same key. |
| Every anchor lost | Recovery fails; it does not invent new keys or authorize new Genesis. |
| Wrong cluster/configuration/prefix, changed enrollment or ciphertext | Restore refuses the input. |
| Approved CDS image upgrade | An explicitly selected newly signed enrollment permits the new image with the same WAL key and recovery-only authority. |
| Old image under that new enrollment | Key release is refused. |
| Old capsule **and old enrollment** replayed together | **Release still succeeds. This is a counterexample, not a retirement guarantee.** |

The wrapping keys survive in the test parent's memory and attestation is a
software fixture. These tests prove subprocess recovery and binding behavior,
not chip-backed recovery, secure upgrades of a custody image, independent-host
HA or operator exclusion. The previous ten-arm CDS acceptance result remains
separate; these new tests do not re-run that entire suite.

## The retirement boundary

A signature proves that a policy was approved, not that it is still current.
Sealing an old policy does not make it expire. Destroying the latest guest or
deleting its capsule cannot revoke a copy the operator retained.

The smallest next protocol candidate is to check current authorized policy
against the **existing committed WAL history** before any release. That check
must be mandatory in every image that ever receives a persistent root; it
cannot be retrofitted into already released old images. It must fail closed
when freshness cannot be established and define its ordering with concurrent
revocation. A cached policy, an operator-selected old head, or a new unsigned
policy object is not enough. This increment deliberately does not wire the
capsule into production startup or add an optional, bypassable policy callback.

Even an online policy check does not erase a key previously released to an
image. If the goal includes preventing compromised retired custody code from
deriving an old hardware key, software checks inside that old image do not
establish it. That stronger requirement needs enforcement outside the retired
image, or an explicit change of the recovery/security contract. We have not
shown a provider-free solution to that requirement here.

Storage remains trusted for durable, linearizable head reads and CAS, as in
the baseline. Whole-history rollback against a cold cluster is not solved by
capsules. Reusing that existing authority for freshness is a design candidate,
not a newly proven guarantee.

## Native SNP probe

`test/pilot/cds-sealed-recovery/snp-probe` is an opt-in Linux command using the
existing `go-sev-guest` dependency and `/dev/sev-guest`. It seals only a newly
generated disposable 32-byte sentinel. It accepts no CDS key, provider
credentials, software key source or key-release requests.

It checks a fresh report nonce, VMPL 0, the independently supplied SNP
measurement, a non-debug/non-migratable policy and the exact launch-file
HOST_DATA binding **before** requesting a VCEK-derived key. It selects all six
available binding fields: policy, image ID, family ID, measurement, GuestSVN
and TCB version. The last two inputs are preserved in the authenticated
capsule so an increase in running SVN does not silently select a new key.

SNP does **not** include HOST_DATA in its hardware key derivation. This tool
checks it in software and includes configuration in its HKDF/AEAD context.
That is useful only if the complete approved measured program enforces the
check and prevents arbitrary workloads or a guest shell from using the device.
A generic VM sharing a firmware measurement is insufficient. See Google's
[derived-key limitations](https://github.com/google/go-sev-guest/blob/main/LIMITATIONS.md)
and the AMD [SNP ABI](https://docs.amd.com/v/u/en-US/56860_PUB_SEV_SNP).

The original single-process primitive does not verify the report certificate chain or prove
the guest's entire boot/workload boundary. Its output always reports
`attestation_chain_verified`, `operator_exclusion_verified`,
`version_retirement_verified` and `full_acceptance_passed` as **false**.
It prints only public bindings and the random sentinel's digest. No plaintext
secret or derived key is written to a file or stdout. Capsule creation refuses
overwrite; recovery accepts bounded, unambiguous JSON.

The [dedicated measured-image experiment](../images/cds-snp-probe/README.md)
adds a bounded actor-owned exchange and an independent host client that checks
AMD report signatures and issuer revocation. It binds a fresh request and its
complete result into REPORT_DATA, including failed opens. Those checks still
do not establish operator exclusion, a minimum TCB policy or image retirement.

Build locally:

```sh
go build -o /tmp/cds-snp-probe ./test/pilot/cds-sealed-recovery/snp-probe
```

Inside an explicitly owned SNP pilot guest with the approved measured image
and its exact launch file, run:

```sh
./cds-snp-probe -mode seal -capsule-file /run/probe-capsule.json \
  -measurement "$PILOT_SNP_MEASUREMENT" -launch-file /run/approved-launch.yaml
```

Save only the encrypted capsule and public receipt outside the guest. Destroy
that owned guest, create a replacement on the **same physical chip** with the
same approved image and configuration, restore the capsule, and run:

```sh
./cds-snp-probe -mode open -capsule-file /run/probe-capsule.json \
  -measurement "$PILOT_SNP_MEASUREMENT" -launch-file /run/approved-launch.yaml
```

The sentinel digest must match. Moving that capsule to another physical chip
should fail. A second protected copy of the *same recovery material* must be
enrolled on another chip through an attested transfer before claiming host
loss tolerance. The sentinel probe does not implement that transfer. A new
measured custody image likewise needs an approved transfer/reseal before the
old image is retired; copying its ciphertext does not perform an upgrade.

At least one enrolled chip and its capsule must survive. Losing every such
root is outside this design's recovery envelope. Three VMs on the same chip
can test VM failure, but do not provide three independent recovery roots.

## Hardware qualification status

The read-only HIL1 node inventory advertises SNP capacity on three nodes and
TDX capacity on others. Those advertisements do not prove derived-key support,
chip independence, correct image measurement or protected device access.
The workspace itself has no SNP guest device. Subsequent isolated HIL1 runs
qualified the sentinel primitive in measured SNP guests: same-chip recovery
after VM destruction and different-chip refusal both passed, with signed
reports and issuer-revocation checks. The exact inputs and remaining limits are
recorded in [SNP recovery qualification](cds-snp-recovery-qualification.md).

Native TDX sealing is specified by Intel's
[module specification, section 12.8](https://cdrdv2-public.intel.com/865787/intel-tdx-module-base-spec-348549007.pdf)
using `TDG.MR.KEY.GET`, gated by `TDX_FEATURES0.SEALING`. We have not established
that our installed modules and guest interfaces support it. This branch adds
no TDX emulation, SGX sidecar, host installation or Azure dependency.

The hardware fixture uses an isolated measured image and native VM launch path,
with an ownership journal, expiry, exact-UID cleanup and production boundaries.
Every resource from the completed attempts was removed. No shared production
rollout was performed; the Cloud PR #1149 release remains outside this experiment.

Local checks (no CI):

```sh
go test -race -count=1 ./internal/cdsrecovery ./test/pilot/cds-sealed-recovery/snp-probe
go vet ./internal/cdsrecovery ./test/pilot/cds-sealed-recovery/snp-probe
```

The result narrows the candidate: independent sealed copies can simplify
durable custody. Current-policy enforcement passes local protocol tests and the
hardware sealing primitive now passes separately. Their integration, multi-chip
enrollment and firmware/image lifecycle still require qualification. This is
not yet the full production acceptance result.
