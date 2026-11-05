# Confirm a fresh read before judging cached readiness

The atomic-write comparison found HTTP 503 responses during operator and worker
bursts. Some came from the readiness precheck, before the request attempted its
mandatory read confirmation. A timed-out operation clears the storage actor's
cached watermark; a subsequent request could therefore be refused even when a
new authority read would succeed. Background polling eventually repairs this,
but polling should not be a prerequisite for a request's own fresh read.

The protected-route gate now confirms the read first, then checks serving
eligibility. A failed confirmation still denies the request. Successful
synchronization cannot excuse an unjoined, retired or stopped replica. Recovery
and diagnostic routes retain their existing bypass.

This changes the order of two existing checks. It introduces no lease, cache,
actor, mutex, retry or longer deadline. Both Raft quorum confirmation and the
storage backends' current-head checks remain mandatory. The existing request
admission and actor budgets still bound requests waiting on authority I/O.

The focused regression covers expired readiness restored by confirmation,
continued ineligibility after synchronization, and eligibility lost during the
confirmation. Existing tests cover ready replicas whose authority cannot be
reached, and diagnostic routes that remain reachable without it.

This is a candidate availability correction prompted by the frozen comparison,
not a claim that every observed 503 had the same cause. The original comparison
remains on `pilot/cds-atomic-operator-write`; follow-up measurements must identify
this different source and binary explicitly.

## Follow-up results, 2026-11-05

The [complete follow-up measurements](../test/pilot/cds-sealed-recovery/results/2026-11-05-refresh-before-serving.json)
use published source `1410325ff8f56258f638203958dd79294b256bcf`, tree
`fd2fe8e15a7415ea0f59dc5613b80a4024f33209`. Raft and both storage arms used
CDS binary SHA-256
`a28ba58bcebc43817ab3eaf676d1708770d4c2e8fee5f8630414e1a5847b9cbb`.
The [original comparison and its failures](cds-atomic-operator-write.md#results-2026-11-05)
remain separate. The follow-up retains 100-ms object operations, 2-ms metadata
operations, concurrency 16, the same admission budgets and all existing
timeouts. Timed requests have no client retry.

Both storage backends passed their complete follow-up:

| Workload/check | Object WAL | Transactional metadata |
| --- | --- | --- |
| Independent paths, one history | 64/64; 3.16 writes/s; p95 6.73 s | 64/64; 7.56 writes/s; p95 3.08 s |
| One policy under contention | 64/64; 3.21 writes/s; p95 5.50 s | 64/64; 7.39 writes/s; p95 3.48 s |
| Four independent clusters | 64/64; aggregate 7.45 writes/s | 64/64; aggregate 19.65 writes/s |
| Worker certificate/secret-release bursts | 96/96 flows | 96/96 flows |
| Replay, replacement, same CA, preserved secrets, revocation | Passed | Passed |
| Cross-cluster credentials and admission bounds | Passed | Passed |

Every one of the 384 acknowledged storage writes used one committed command
and completed the replay checks. Each independent cluster completed two
12-worker issuance-and-release bursts, reusing worker keys in the renewal
round. No tested release started after revocation acknowledgement succeeded.
Cross-cluster operator credentials were rejected, as were foreign metadata
credentials. These certificate flows are not the separate managed-Kubernetes
node-token enrollment API.

The object arm's original combined-write run had stopped in the second
cluster's worker burst and acknowledged 52/64 independent-path writes. The
follow-up completed all clusters and all 64 independent-path writes. This is
evidence for the small gate correction; one repetition does not establish an
availability SLO or attribute every prior failure to that check.

The changed HTTP package passed its full race suite and vet. HTTP parity passed
with atomic writes disabled and enabled. Both storage backends passed the
interrupted-image upgrade with total CDS process loss, preserving the same CA,
spent tokens, revoked policy and original leaf/secret. Retired images and stale
provisioning grants remained refused. These are software-attestation recovery
tests, not a new native custody qualification.

Raft acknowledged all 192 measured writes, but its complete acceptance run
failed. In one independent cluster, the replacement exited when startup
workload seeding encountered a leader change; two survivors kept serving. In
the independent-path case, a secret-challenge probe received HTTP 503 because
read confirmation was unavailable. Those checks remain failed, not evidence of
lost acknowledged state or permission to release stale secrets. The parent
comparison's full Raft race-suite failures also remain unresolved; this change
does not claim a clean full Raft regression suite.

An independent final audit inspected 132 processes, with no unreadable entries
and no processes under either comparison's executable directories. Only the
three preexisting rehearsal containers remained. No cloud resources, production
configuration or CI workflow runs were created by this work.

The engineering result is one durable operator command and a request gate that
uses its own fresh read before cached readiness. No new coordination service,
mutex, retry or longer deadline was needed for these changes. Transactional
metadata remains the faster candidate in this local latency profile. Native
custody-image upgrades, TDX key recovery, a replicated HA metadata deployment
and sustained real-network workloads still require qualification before a
production Raft replacement.
