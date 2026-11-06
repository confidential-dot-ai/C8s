# Replicated current-state metadata qualification

This branch builds on the completed native SNP and TDX current-state pilots.
The qualification order is:

1. Replace the unreplicated SQLite metadata fixture with a dedicated three-member
   etcd service and prove the current-state contract under faults.
2. Place three CDS guests on three distinct qualified compute workers, with
   independently verified placement. No control-plane placement or host changes.
3. Run the same partition, failover, replay, revocation and rolling-upgrade
   scenarios against the current-state backend and the existing Raft control.

No default backend, shared deployment, production identity or existing guest is
changed. CI is not used. Only owned, expiring fixtures may be faulted or removed.

## Metadata contract

The opt-in `cds-metadata-pilot --etcd-endpoints` mode serves the existing
`/v1/state/read` and `/v1/state/commit` protocol. Three stateless adapters can
share the same etcd cluster; no local journal, elected adapter or replay is
needed. Every record remains encrypted by CDS. Values larger than the existing
inline limit retain the immutable object path.

Each request maps to one etcd v3 transaction. Reads use current, linearizable
ranges in one transaction. Writes compare every read version and publish all
changed records atomically. A record version is etcd's monotonically increasing
per-key version; this API exposes neither deletion nor leases. All endpoints
must return the independently pinned etcd cluster ID and authenticate with
dedicated mutual TLS credentials. Wrong identities fail closed.

The adapter sends a mutation once. A lost response is an unknown result, never
a definite conflict or a reason for automatic resubmission. Only a successful
transaction response with failed comparisons means conflict. Reads may try the
other configured members within a fixed four-second deadline. Each configured
CDS cluster has its own actor-managed admission: 16 active, 64 total requests.
Request owners perform network IO; the admission actor does not. No global
application mutex protects network work.

Etcd provides the consensus protocol internally. The selected CDS backend
continues to have no Raft node, application WAL, preferred writer or replay
procedure. This delegates consensus rather than eliminating it. The trusted
metadata boundary includes etcd administrators and its underlying durable
storage. Whole-cluster rollback or a dishonest metadata service remains outside
the freshness contract; encryption cannot establish freshness by itself.

The [etcd API guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/)
specify durability and strict serializability for KV operations, and explicitly
describe uncertain outcomes after timeouts. Stale `serializable` ranges and
watches are not used for authorization.

## Qualification status

Local race tests passed against real etcd processes, including ambiguous commit
responses, concurrent snapshots, wrong-cluster refusal before mutation, leader
loss, quorum loss and recovery. The CLI and existing metadata client race tests,
`go vet`, and six fixture safety tests passed.

The [second cloud run](../test/pilot/cds-ha-metadata/results/2026-11-05-ha-metadata.json)
passed on three distinct compute workers: 64 independent commits, one winner
among 16 CAS contenders, service from the surviving majority, refusal by the
partitioned member, and refusal of reads and writes without quorum. All 65
acknowledged records were verified through each of the three adapters after
recovery. An independent read-only audit confirmed all 32 resource paths absent.

Observed quorum-ready times were 9.017 seconds initially, 36.127 seconds after
healing one member, and 33.458 seconds after healing quorum loss. These are
single-run observations, not availability targets. The [first attempt](../test/pilot/cds-ha-metadata/results/2026-11-05-ha-metadata-attempt-01.json)
failed its 35-second recovery observation and is retained as a failed result.
The second attempt used the same runtime binary with a 90-second observation
bound and additional private failure diagnostics.

This completes the metadata stage only. Three separately placed CDS guests and
the Raft/current-state upgrade comparison are the next stages; their success
and production readiness are not implied by this result.

A [subsequent repeat](../test/pilot/cds-ha-metadata/results/2026-11-06-ha-metadata-attempt-03.json)
on November 6 failed the independent-write batch after the conditional race
passed. The worker pinger remained clean, but the runner did not retain each
request's status, so the cause and number of acknowledged writes are unknown.
All 29 owned resources were removed; an independent audit confirmed 32 paths
absent. This repeat does not qualify the next CDS run. The runner now saves
every status, elapsed time and transport-error type before asserting a batch's
result. Its workload, concurrency, deadlines and single-send rule are unchanged;
eight local fixture tests pass, including preservation of uncertain outcomes
without retry and stopping after a failed conditional race.
