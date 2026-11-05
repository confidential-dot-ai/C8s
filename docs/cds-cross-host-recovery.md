# CDS recovery using a surviving physical host

This increment extends the [same-chip SNP experiment](cds-snp-integrated-recovery.md).
It keeps the existing encrypted history, CDS FSM, WALAuthority and commit point.
Raft remains the default HA backend. No shared cloud rollout or CI is required.

## Protocol and boundary

The original custodian derives its authority on host A. An approved guest on
host B boots the completed launch that pins that authority. It creates a fresh
X-Wing recipient and binds it to an SNP report. The original custodian verifies
the exact image, launch, report signature, issuer revocation, VMPL and non-debug,
non-migratable policy before sending the original authority seed and capsule
wrapping key through the existing signed encrypted channel.

Host B seals that material under its own SNP-derived root. The encrypted copy
binds the full measured launch and saved TCB/GuestSVN. Its public attested receipt
identifies the original authority and the independently derived hardware root.
The untrusted runner durably saves only ciphertext and public evidence before
destroying the enrollment guests. It never receives either private key.

A replacement on B opens that copy and delegates to the same approved CDS
launch. CDS then restores WALAuthority, which replays the existing committed
policy and checks freshness before each CDS recovery-key grant. The copy adds
no policy database, election, release ledger, or permission to create Genesis.
Firmware operations retain the bounded actor; one admitted phase owns transfer
and sealing state. No new application mutex or unbounded task queue is added.

Enrollment here is the fixed-image bootstrap fixture, not a production API for
changing custody membership. It does not qualify custody-image retirement or
enrollment into arbitrary new images. Retired code and whole-history rollback
remain the boundaries documented in the existing policy design. At least one
enrolled chip and its encrypted copy must survive.

## Acceptance sequence

Run the owned native runner with `--cross-host --nodes <source> <destination>`.
Both nodes must be approved SNP workers, with different chip identities verified
from signed reports. There are at most two active test VMs at once.

1. Enroll the original authority on A and its protected recovery copy on B.
2. Destroy both enrollment guests; retain the sealed copy outside their memory.
3. Start custody and three real CDS processes on A; create identity and secret
   state, consume a token, and acknowledge a policy revocation.
4. Destroy both source VMs and require both VMIs to be absent.
5. Exclude A in the runner before any recovery VM is created. No node is stopped,
   cordoned, reconfigured or otherwise mutated to simulate this loss.
6. Start custody and CDS on B. Require the original CA, explicit rejection of
   the still-valid spent token, preserved revocation, and a positive control
   using the original workload leaf and original secret after new authorization.
7. Remove every owned resource with UID preconditions and audit their absence.

The three CDS processes still share one guest. This tests loss of the original
physical recovery anchor; it is not a three-host serving-capacity or availability
qualification. The conditional-object fixture persists ciphertext on the runner
and is not a measurement of a deployed object-storage service.

## Status

Local cryptographic tests pass for independently wrapped copies, loss of one
root, wrong-root refusal, substituted launch/authority/TCB/SVN and damaged copies.
The affected Go race checks and vet pass, as do 31 native-runner checks including
rejection of original-host recovery placement before any resource creation.
The runner retries only transient HTTP 502/503/504 GET failures, at most three
attempts; it preserves write reconciliation and never retries authorization errors.
The cross-host hardware result is pending; full acceptance, operator-exclusion
qualification and production readiness remain false.

After the cross-host proof, the next increments are approved image transitions
and TDX qualification, followed by the matched three-backend workload comparison.
Storage round-trip counts, cold replay/checkpoint lag, tail latency and bounded
backpressure must be measured without relaxing revocation or freshness checks.
