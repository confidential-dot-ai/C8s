# SNP recovery qualification

The dedicated recovery probe image was built locally on 2026-11-04. This is
qualification work for the [sealed-custody design](cds-sealed-custody-experiment.md),
not a production CDS replacement. It uses a disposable random sentinel, never
a CA key or an existing cluster's data.

## What is built

The measured guest runs only the bounded SNP probe service. One actor owns
the hardware device; eight queued operations and 32 accepted connections bound
its work. Overload returns HTTP 429. Cloud-init, SSH, guest-agent and console
shell services are disabled. A measured timer powers the guest off after
45 minutes; its fixture requires explicit starts and does not restart it.

The image uses the pinned confos verity/UKI/IGVM chain, two vCPUs and 4 GiB.
The local builder's transport patch removes three unavailable package-mirror
entries while retaining the exact official Ubuntu snapshot URLs and package
versions. Download hashes and normal TLS verification remain enabled. No CI,
registry publication, shared image admission or host configuration change is
part of this build.

| Input or output | Revision or SHA-256 |
|---|---|
| Image source revision | `9a2f179b3b38b132301c089cbce738dc3045c37f` |
| confos revision | `133aeae5e006ee11a72b2a7200a9fb173a1c85ef` |
| Builder transport patch | `3e1424232f572f1f4cccabc52ee9b208fccff23a8632c0cec8f9686ff98cdb1a` |
| Manifest | `644f8daab376e5468fa174641a64763143c5a1b6d0bdf5333e6db46490452c33` |
| Probe binary | `6205afc24a0f0c75970078517c916ac7c78ee652484bdb72dd70e6e60d1b0ebb` |
| Root disk | `9a98d2bb8b368efcf3273dcca20da231fdcd0e7e025c6e5fd6335cee87529377` |
| IGVM | `e70f3df21c8689bd897a9ac62610590b08db2a3999cbab78de231fc31852db61` |
| UKI | `3c3f2e57e530f4849cd4ffd651c48348b06f41d17ea2104569b8784572f77631` |
| Firmware | `53c3bdc6654708a7b23f5db36c0548de4975322e5838e90bd258e082394bf8c0` |

Independent inspection checked manifest hashes, GPT checksums, EROFS integrity,
the embedded kernel and probe, root verity hash, locked root login, service
masks, and enabled probe/expiry units. These are build checks, not hardware
attestation results. Build instructions and the exact exchange are in the
[image README](../images/cds-snp-probe/README.md).

## Native upload validation

The native fixture has successfully transferred the disk and IGVM into its
own claims and independently verified both SHA-256 values against this build.
The connection delivered complete files but did not finish the streaming exec
clients. The runner now requires a fresh receiver-completion token read through
a separate authenticated exec before closing a stuck client; hash verification
still gates VM creation. Fourteen local lifecycle tests include this failure mode,
a receiver finishing after a client connection fails, invalid archives, replaced
ownership, and lost API responses during cleanup.

That attempt stopped before VM creation because a baseline VM from a concurrent
temporary workload had been deleted. Its normal shutdown events were retained
for investigation; the workers and remaining baseline VMs stayed ready. All
owned claims, backing volumes, public launch data and the population Pod were
removed. This establishes the artifact transfer path, not the hardware recovery
primitive or unchanged-fleet acceptance.

## Required hardware evidence

The sequential fixture must seal, open in the same live guest as a control,
destroy that guest, recover in a new guest on the same chip, and reject the
same capsule on a different chip. Each result must carry a fresh AMD-signed
report binding the complete request and response to the independently built
image and exact launch file. Distinct VMI UIDs and firmware guest report IDs
establish recreation; verified chip hashes establish physical placement.

Only AES-GCM authentication failure after successful hardware key derivation
counts as a different-chip rejection. A timeout, missing device, bad report,
firmware error or unexpected launch configuration fails the test.

Every attempt records creation intent before API writes and removes only its
owned resource UIDs, including waiting for its backing volumes to disappear.
Node identity/readiness and existing VM readiness are checked around the run.
Unexpected VMI loss or readiness regression stops the test. The runner captures
each VMI's controller owner and separately checks the owning VM when a baseline
VMI disappears or becomes unready. Only a matching owner with an API deletion
timestamp, or an absent owning VM, is classified as an external deletion.
Unknown or replaced owners and surviving owners without deletion intent still
stop the test. These observations never mutate the external resources.

External deletions are preserved in the journal and keep its post-cleanup
`unchanged` claim false, even if the hardware primitive succeeds. That result
does not establish fleet-wide availability or customer application latency.

## Remaining acceptance work

Even a complete sentinel pass would qualify only this exact hardware primitive.
The CDS acceptance goal still needs the same protected recovery key enrolled
on independent physical roots, complete loss and reconstruction of CDS,
current-policy release, acknowledged revocation and spent-token rejection.
Minimum firmware TCB, image upgrades and retirement, and policy signing outside
the infrastructure operator's control need separate qualification.

Storage remains the trusted ordering and freshness authority. This probe does
not detect an authentic whole-history rollback by storage, revoke a key already
released, or prevent old vulnerable measured code from deriving its old key.
Losing every enrolled physical root remains outside the recovery envelope.

`full_acceptance_passed` and `production_ready` remain false.
