# CDS recovery acceptance

The target is: lose every CDS replica, start approved replacements, recover
the same identity, reject spent requests and revoked access, and keep the CA
key inaccessible to the infrastructure operator.

The follow-up [sealed-custody experiment](cds-sealed-custody-experiment.md)
tests authority subprocess loss and independently wrapped recovery copies,
and records the old-enrollment replay counterexample. That experiment is the
current provider-free direction; production hardware custody remains unqualified.
The later [integrated SNP proof](cds-snp-integrated-recovery.md) passed same-CA
recovery, unexpired replay rejection and preserved revocation after both CDS and
custody VMs were destroyed. Its scope is one physical chip and one approved
image, with a trusted conditional-object fixture.

The [current-policy increment](cds-current-release-policy.md) adds mandatory
committed-policy checks for the new recovery authority. The runner now includes
fourteen backend/scenario combinations; the ten-arm result recorded below
remains the historical result for the earlier increment.

This increment builds on sealed recovery at `20bd0df8`. It removes the test
authority's mutable initialization flag and adds a reusable release authority
with immutable policy and bounded admission. It does not qualify hardware
custody or replace production Raft.

## One immutable enrollment

At initial enrollment, the custodian verifies the first process over pinned
armTLS and signs a public record containing:

- The cluster, measured launch digest and object prefix.
- The approved image pins and replica origins.
- A hash of the first process's ephemeral recovery request.
- A commitment to the existing WAL encryption key.

The custodian must persist this record before releasing any key. It contains
no WAL or CA private key. Changing its pins, origins, cluster, initial process
or key commitment invalidates its signature. Missing or invalid enrollment
fails closed; authority startup never creates replacement enrollment.
Restore also requires the custodian's independently selected cluster and
configuration, so another validly signed enrollment cannot choose its scope.

An ordinary release accepts only an enrolled origin. The authority fetches
and verifies that process itself. Only the original request can receive
Genesis permission; every replacement receives recovery permission. This
decision survives authority restart without an issued-grant ledger, mutable
initialization flag or storage-head probe. Redelivery to the original process
remains safe after a lost response.

Multiple authority instances can use the same protected keys and signed
record without coordinating grant issuance. That is a property of this
stateless decision, not evidence that the external key custodian is HA. There
is still one CDS commit point and the existing WAL replay path.

Each cluster gets its own existing request-gate actor: four active releases,
at most sixteen admitted requests including queued work, and immediate
backpressure above that limit. IO runs outside the admission actor. Policy is
immutable; shutdown cancels work, drains permits and clears private key copies.
No global application mutex or cross-cluster queue was added.

Initial enrollment is a trusted administrative operation, separate from
recovery. A custodian must not enroll a second initial process for an existing
cluster merely because its head is missing. Losing the initial process before
Genesis requires an explicit creation decision; it is not automatic recovery.
Policy updates and software-version transitions are not implemented here.

## One local command

```sh
test/pilot/cds-recovery-acceptance/run-local.sh /tmp/cds-recovery-acceptance-001
```

Use a fresh output directory. Go, Python 3, Linux loopback networking and the
existing workload fixture's inventory port are required. The command runs
local race suites and vet, then fourteen release-process scenarios sequentially:
rotation and workload tests for Raft, object WAL, transactional metadata, and
both storage variants with sealed recovery, and both with current-policy
recovery. It also runs adversarial recovery.
It uses no CI or cloud resources. Test processes are cleaned up by the harness.

The report records test events and source state. Missing, failed or skipped
required tests cannot qualify a run. The signed enrollment is restored from
disk after all CDS processes are killed; the authority object is destroyed and
reconstructed. Its secret keys remain in the fixture custodian's memory.
This is not an independently killed hardware key-service process.

`acceptance.json` deliberately distinguishes `local_protocol_result` from
`full_acceptance_passed`. The latter stays **false** in this runner, even if
every functional test passes. It never turns software attestation or a
private file into proof that a host administrator cannot extract a key.

## What is still required for the last clause

The managed Kubernetes trust record separates the infrastructure operator from
the customer approving CDS policy. A production binding must keep both the
key and the authority's approved code/policy beyond the infrastructure
operator's control. Giving that operator permission to change the release
policy would defeat the requirement even if the key itself were encrypted.

The custody qualification must use real TEE evidence and a separately
controlled, durable root. It must test rejection of unapproved code, changed
launch policy, an attacker-chosen recipient key, and an operator attempt to
relax the release policy. Then repeat total CDS loss while the root survives,
and test root-service failure/recovery separately. None of those hardware
claims is established by the local fixture.

The earlier Azure key-release investigation is no longer the selected path.
The follow-up experiment uses native hardware sealing as its candidate, with
no provider dependency. Approved code, exact launch bindings, policy
administration, debug/migration settings and root recovery still require
qualification; changing the root mechanism does not remove those requirements.

Storage still supplies durable, linearizable head reads and CAS. Signed
enrollment does not detect a complete old WAL history presented to a cold
cluster. General storage rollback protection and provider-independent failure
tests remain separate requirements. The current singleton custody specification
also still requires a new CA after restart; changing that contract needs its
own review before production migration.

## Pilot within production Rancher

There is no separate non-production environment. The next cloud run must use
disposable, explicitly owned resources in the existing production Rancher
environment. A namespace or Kubernetes Secret does not exclude a Rancher
administrator from key access. The custody boundary must come from the
approved confidential guest and its protected durable root.

The smallest proposed footprint is three run-owned CDS test VMs,
one owned custody-test CVM, a synthetic workload client, and an isolated object
prefix. Run the backend arms sequentially. Three CDS VMs on the same host are
acceptable for VM-loss checks; independent-host HA remains a separate test.
The custody root must survive deleting every CDS VM and must not be stored
as a plaintext Kubernetes Secret, ConfigMap, PVC, launch file or runner input.
Public enrollment and sealed grants may pass through Rancher.

Before launching, the authority library needs a measured runtime and a real
protected key-source binding. Local fixture keys cannot be promoted into that
role. The current environment has no configured access to such a root, and
the production Rancher setting does not supply one automatically.

The existing Cloud rehearsal tracks exact instance/native UIDs, idempotent
create intents, a 90-minute expiry, scoped discovery/peering and cleanup. Reuse
that ownership model. Do not modify shared OVN/Raft, hosts, default network
policy or the existing CDS VM, and never run broad namespace deletion. Verify
the run-owned resources are gone and the existing production boot identities
are unchanged after cleanup.

The launch prerequisite [Cloud #1149](https://github.com/confidential-dot-ai/cloud/pull/1149)
was still open and unmerged when checked on 2026-11-04. Its pinned image
predates sealed recovery and its envelope validator requires the legacy key
commitment. It needs refreshing, conflict resolution and explicit release
approval before the native Cloud path can launch this mode. This branch does
not merge it, launch VMs, create a key service, or change shared production.

## Recorded local result

On 2026-11-04, the complete local command passed all ten backend/scenario
combinations, adversarial recovery, four package race suites and vet. The
protected storage arms restored the same identity, spent tokens and
acknowledged revocations after all CDS processes were killed and the authority
was reconstructed from its persisted enrollment. Unapproved measurements,
changed launch bindings, modified enrollment and another signed cluster
identity were refused. Per-cluster saturation and shutdown checks passed.
The report also refused inputs with missing or skipped required checks.

`local_protocol_result` was `passed`; `full_acceptance_passed` and
`production_qualified` remained `false`. No hardware custody claim, CI run,
production deployment or cloud-resource mutation is included in that result.
