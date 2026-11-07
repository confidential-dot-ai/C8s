# Combined HA and hardware-protected recovery

This is the single active CDS replacement branch. See the
[development map](cds-development-map.md) for the earlier pilots, superseded
drafts, and the current qualification boundary.

The next acceptance proof combines the [completed three-host HA fixture](cds-three-host-qualification.md)
with hardware custody. The local combined test passes with real CDS and etcd
processes and software custody. **The combined native hardware run is pending.**
The separate HA and SNP/TDX custody results do not establish this combined result.

The acceptance condition is: lose every CDS replica and the source custody VM,
start approved replacements, recover the same CA, reject the original still-valid
spent token, preserve revocation, and successfully use the original client leaf
and secret after explicit reauthorization. The controller never provisions a raw
state key, CA key, or custody wrapping key.

## What changes

This branch changes opt-in qualification code, not production defaults. The
current-state CDS backend still delegates serialization to a transactional
metadata service. The fixture uses three etcd members and three adapters; etcd
uses Raft internally. CDS itself has no Raft participant or application WAL in
this arm. Small encrypted state is inline in metadata. This run is not a
large-object storage or latency qualification.

The existing bounded phase actor in each measured TDX guest now owns recovery
state. It creates an ephemeral native TDX custody recipient, consumes an encrypted
grant from the pinned SNP custodian, and restores the existing `CurrentAuthority`.
That authority still checks current committed CDS policy before granting each
replica its state key. There is no new production release protocol or separate
recovery policy database.

The signed registration and encrypted authority capsule are published once in the
same metadata namespace. A second write-once record holds an encrypted acceptance
witness: the original CA fingerprint, client leaf/private key, secret and spent
token. The witness is test-client state, not an additional production credential
service. Both records require exact version and size checks. Unavailable reads
never mean absence, and an uncertain commit is never automatically resubmitted.

The existing SNP acceptance service adds one fixed `delegate-three` operation.
Exactly three distinct recipients must each pass the existing native TDX quote,
collateral, baked image and launch checks. Each gets its own encrypted grant; a
failure returns no partial batch. This runs inside the existing one-phase-per-boot
actor and keeps its request/backpressure limits. No caller-provided image policy,
verification clock or plaintext custody input is added.

## Native fixture

[`protected.py`](../test/pilot/cds-three-host/protected.py) extends the existing
three-host runner and reuses its placement, attested client, fault and cleanup
checks. It requires three qualified TDX workers and two distinct SNP custody
workers; control-plane placement remains prohibited.
Both resource journals use the combined fixture's existing 75-minute cleanup
deadline. The custody guest's 45-minute per-boot shutdown timer and the live
replay token's validity are unchanged.

1. Start three dedicated etcd members and three metadata adapters.
2. Enroll the hardware authority on one SNP chip, then seal a recoverable copy
   on the second independently attested SNP chip. Only the authority's public
   key may change in the enrolled launch document. Stop both custody guests.
3. Populate all six CDS disks before creating the replay witness. All initial
   and replacement guests use one fixed, fully measured TDX image. This is not a
   mixed-image rolling-upgrade test.
4. Start three CDS guests, obtain three independent custody grants, enroll the
   state key inside guest 0, commit Genesis, and provision the other two guests.
   Run the existing 24-issuance/24-release burst.
5. Isolate one owned CDS guest; require its refusal and survivor service. Then
   partition the owned metadata members, independently observe no leader at all
   three, and require both CDS refusal and recovery-key-release refusal. Heal.
6. Commit revocation and the encrypted witness containing a still-valid spent
   token. Destroy all three CDS VMs and the source custodian. Independently
   confirm all original CDS VM/VMI paths and launcher pods absent before recording
   the loss barrier; require the source custody launcher absent too.
7. Cold-start the backup custodian on the second chip and three fresh CDS VMIs.
   Require fresh recipient keys and the original registration/capsule hash.
   Restore through the same committed metadata and verify the acceptance condition.
   A token with less than 30 seconds remaining fails the test; expiry is not replay
   protection evidence. Revoke again after the positive control.
8. Clean both ownership journals using ordinary UID-scoped deletion, then perform
   an independent read-only absence audit including VMIs, pods and backing PVs.
   HA resources use `cloud.confidential.ai/cds-ha-owner`; custody resources use
   `cloud.confidential.ai/qualification-owner`. The audit checks each journal's
   exact label and owner, and the source-custodian loss barrier uses the custody
   label. A surviving launcher under either label prevents a clean result.

The source custody host is excluded from recovery. Metadata survives the CDS
outage; simultaneous loss of every metadata copy is outside this claim. The
same three TDX workers host replacement incarnations, so this proves loss of
replica memory, not loss of every compute host or every trust root.

The controller retains bounded transport retries only where non-dispatch is
known or initialization is idempotent. It never resubmits an uncertain workload,
custody batch or metadata commit. Failed or partial cleanup retains its journals.
Read-only metadata tunnel setup allows at most three 15-second startup attempts
for transient failures. Each attempt revalidates the owned pod's UID, and a
failed local process is stopped and reaped before retrying. Access denial and
ownership changes fail immediately; no CDS request is sent during tunnel setup.
The run cannot be resumed as a passing experiment; use a new directory after
cleanup. `cleanup` and `audit` support the retained directory.

Build a new three-host agent image and native custody image from this branch.
The custody image must bake the new TDX image's exact recipient manifest. Rebuild
the independent custody verifier and phase client too: the batch is covered by
the signed receipt transcript. Do not reuse older measured images that lack the
new fixed phases. `python3 test/pilot/cds-three-host/protected.py --help` lists the
required frozen binaries, manifests, worker names and ownership directory.

## Local validation and limits

`TestHACurrentRecoveryAfterTotalCDSLoss` starts three real etcd members, three
real TLS metadata adapters, and three real CDS release processes. It exercises
the native agent's encrypted checkpoint and restore code with a software custody
root and mock attestation. It loses an etcd leader and adapter, acknowledges
revocation, then kills every CDS process and restarts every adapter. Recovery
without metadata quorum and a previous-incarnation grant are refused. Recovery
with quorum preserves the same CA, live-token replay rejection, revocation and
the original leaf/secret positive control. Fresh CDS database paths are used.

Run locally with Go 1.27.3, the repository workspace, etcd 3.7.3, and:

```sh
CDSHA_ETCD_BIN=/path/to/etcd CDSHA_RELEASE=1 CDSHA_TRANSACTIONAL_COMPARE=1 \
  go test -tags integration -count=1 -timeout 10m -v ./test/integration/cdsha \
  -run '^TestHACurrentRecoveryAfterTotalCDSLoss$'
```

`CDSHA_TRANSACTIONAL_COMPARE=1` retains the existing comparison's explicit
10,000 request rate/burst allowance; it does not change backend timeouts.
The local test does not prove operator exclusion, native hardware custody,
physical host separation, live availability SLOs or production readiness.
The [local evidence record](../test/pilot/cds-three-host/results/2026-11-06-ha-protected-local.json)
contains source and binary hashes, test outcomes, and the pending native checks.

The metadata provider remains the trusted current-state/freshness authority.
Encryption does not prevent its operator from denying service, and this proof
does not establish protection against a malicious rollback of every authoritative
metadata copy. Hardware custody depends on the approved measured code, firmware,
attestation collateral and survival of an enrolled custody chip/copy. This fixture
does not qualify production custody membership, key rotation or image retirement.

The earlier fixture's possible network impact remains part of the qualification
context.
The [network follow-up](../test/pilot/cds-three-host/results/2026-11-06-fixture-network-follow-up.json)
preserves both the user's teardown timeline and the saved pinger timestamps;
their differing time bases remain unresolved. Resource absence does not exclude
residual OVN/OVS effects. The resumed native run observes existing pinger logs
before, during and after its owned fixture, and stops on new packet loss or
repeated degraded observations. The preflight requires six directed links,
at least eight samples per link, no loss, a latest sample no older than 90 seconds,
and no sample mean above 50 ms in the six-minute window. During the run,
[`NetworkWatch`](../test/pilot/cds-three-host/network_watch.py) stops immediately
on any observed new lost packet, on two consecutive **fresh** latest samples above
50 ms for the same link, or on two unavailable/stale observations. Re-reading one
sample in overlapping windows does not count twice. Log rotation may shorten the
window while fresh samples continue; all captured window peaks remain evidence.
These thresholds are qualification guardrails, not a published cluster SLO or
proof that the fixture has no effect on production traffic.
A stopped attempt retains its evidence and must
complete cleanup before a fresh run. Host changes, OVS execution, OVN Raft-file
reads, CI and a shared rollout are outside this qualification.
