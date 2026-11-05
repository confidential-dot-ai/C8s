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
Its measured service listens on port 6443, already permitted by the native
KubeVirt API Pods' egress policy. One owned ingress policy permits only those
Pods to reach the probe; no shared network policy changes.
The local builder's transport patch removes three unavailable package-mirror
entries while retaining the exact official Ubuntu snapshot URLs and package
versions. Download hashes and normal TLS verification remain enabled. No CI,
registry publication, shared image admission or host configuration change is
part of this build.

| Input or output | Revision or SHA-256 |
|---|---|
| Image source revision | `547a5f66aa1056c20e427392f616dd4a312829fc` |
| confos revision | `133aeae5e006ee11a72b2a7200a9fb173a1c85ef` |
| Builder transport patch | `3e1424232f572f1f4cccabc52ee9b208fccff23a8632c0cec8f9686ff98cdb1a` |
| Manifest | `22b34240e0678b47c5f8b352dd7ad6dda68c212fa4ea66fdbe63a5cec818e026` |
| Probe binary | `6205afc24a0f0c75970078517c916ac7c78ee652484bdb72dd70e6e60d1b0ebb` |
| Root disk | `5398317be87a04863c583cea172f2c62c9b568158fb3ff02bb75bbcf371fb251` |
| IGVM | `e00c6fa515f484734fbffda2daa9c7b80460052b5e5c4e424ecbde6236e114ca` |
| UKI | `c66bf0168cc52829d12cf66261ffbdf88975def0e28de47006b9e4865c7a324b` |
| Kernel | `bd22510c1c083effce81c838aae74739298e3dd4ae6683d2a8ab6208dc2a0216` |
| Kernel fragment | `65ff8b7fafae1159e709bb644b5442deb30d532e81d2c2f5d58bc3edc17d623f` |
| Firmware | `53c3bdc6654708a7b23f5db36c0548de4975322e5838e90bd258e082394bf8c0` |

Independent inspection checked manifest hashes, GPT checksums, EROFS integrity,
the embedded kernel and probe, root verity hash, locked root login, service
masks, enabled probe/expiry units and DHCP networking. The resolved kernel
configuration enables the required UART driver and disables serial SysRq while
retaining the hardened debugfs setting. Inspection also reads actual EROFS
inode permissions: public DHCP/unit files must be root-owned `0644`, and their
parent directories `0755`. These are build checks, not hardware
attestation results. Build instructions and the exact exchange are in the
[image README](../images/cds-snp-probe/README.md).

## Native launch evidence

The native fixture has successfully transferred the disk and IGVM into its
own claims and independently verified both SHA-256 values against the selected build.
The connection delivered complete files but did not finish the streaming exec
clients. The runner now requires a fresh receiver-completion token read through
a separate authenticated exec before closing a stuck client; hash verification
still gates VM creation. Failed completion reads retry within the original
deadline. Twenty local lifecycle tests include this failure mode,
a receiver finishing after a client connection fails, invalid archives, replaced
ownership, explicit VM stops, and lost API responses during cleanup.
An interrupt test also exercises a real child-process wait: SIGINT/SIGTERM
raise `SystemExit`, since `InterruptedError` can be swallowed by subprocess as
a retriable OS interruption. Cleanup still runs through the outer `finally`.

The port-6443 attempt reached KubeVirt Ready but never returned a signed probe
response. Its native port-forward failed with `no route to host`. KubeVirt
readiness therefore establishes VM launch, not guest boot or successful recovery.
That attempt's cleanup and baseline checks passed: no owned resources remained
and no unexpected readiness regression was observed.

A subsequent attempt was canceled during population, before VM launch, after
inspection found that a console parameter alone cannot enable the hardened
kernel's disabled UART driver. All five staged resources and their backing
volumes were removed. Concurrent external VM deletions were recorded separately;
they were not treated as an unchanged fleet. The corrected qualification kernel
enables serial diagnostics, disables serial SysRq input, and retains the hardened
debugfs setting. Console login stays masked. These diagnostics are appropriate
only for this disposable sentinel image.

The next native trace established guest boot, SNP driver initialization and the
initrd HOST_DATA check, then exposed the networking failure. The private source
checkout supplied a root-owned `0600` DHCP file, but networkd runs as
`systemd-network` without discretionary-access bypass capabilities. The image
finalizer now sets explicit permissions on that public file and the probe units.
No shared network, host or production image configuration was changed. All
resources from that failed attempt were removed before retrying.

The corrected image's serial trace shows DHCP address acquisition and probe
startup in approximately nine seconds. The first tunnel request preceded that
readiness. KubeVirt's client stopped accepting connections after its failed
guest dial while leaving the process alive. The runner now replaces that
tunnel on retries, retaining its original deadline and requiring the same
verified response. A regression test reproduces the still-alive but unusable
forwarder. Boot logs are diagnostic observations, not signed recovery evidence.

The next attempt reached the probe, but AMD verification requested an `Unknown`
product's certificate endpoint and failed. All owned resources were removed;
the final node and VM readiness observations matched the baseline. The host
client now requires an independently expected product line, uses it to verify
v2 certificate product extensions, and rejects mismatching or unknown signed
CPUID in newer reports. Signature, embedded AMD root trust and issuer revocation
checks remain mandatory. This host-only change does not require rebuilding or
replacing the measured guest image. Both selected workers advertise Genoa;
that inventory is a selection hint, not attestation evidence.

The report then identified CPUID `0xaa0f02` (family 19h, model A0h), which
upstream go-sev-guest does not classify. The application's existing pinned
attestation-go verifier already supports these Zen4c parts, fetching their
VCEKs under Genoa and anchoring them to bundled AMD roots. The probe now reuses
that verifier for v3+ reports, with mandatory revocation checking and no change
to signed report bytes. The expected-product check recognizes the same narrow
model range; unrelated unknown products still fail. AMD's
[KDS specification, table 4](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf)
documents Siena's shared Genoa root keys. The failed attempt's owned resources
were removed and its final health observations matched the baseline.

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
A matching owner with explicit `runStrategy: Halted` is separately recorded as
an external stop. A `Stopped` status alone is insufficient. Unknown or replaced
owners and surviving owners without either explicit intent still stop the test.
These observations never mutate the external resources.

External stops and deletions are preserved in the journal and keep its post-cleanup
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
