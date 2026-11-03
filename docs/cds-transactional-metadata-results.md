# CDS transactional metadata results

Measured locally on 2026-11-03. This evaluates the third architecture described in the [runbook](cds-transactional-metadata-pilot.md). It preserves one ordered history per cluster; it is not a partitioned CDS implementation.

Keep the object-WAL pilot as the baseline. The metadata arm improved throughput
when its requests had less added latency, but the equal-latency control showed
no clear advantage. A final comparison with identical immediate-revocation
acceptance rules caught one stale secret release from Raft; both storage-backed
arms passed those checks. The broader matrix also had availability failures,
so this is evidence for further evaluation, not a production promotion result.

## Primary matrix

Each cell attempted 64 signed HTTP writes at concurrency 16. Each workload/backend/latency setting was scheduled three times, rotating backend order. The arms used the same release CDS binary and three CDS processes. Metadata ran in a separate executable with durable SQLite transactions. The object service was an in-memory conditional-object fixture. Added delays are synthetic and additional to real network, TLS, SQLite and execution costs.

The run scheduled 30 cells. One Raft cell failed before load, leaving 1,856 attempted writes; 1,852 succeeded and four returned HTTP 503. Twenty-seven cells completed replay, process-loss recovery, value checks and revocation. Two additional cells stopped during verification. The overall comparison test exited nonzero; this is not an all-green benchmark.

Table throughput and p95 are medians of the measured runs, including runs whose later verification failed. Ranges show run-to-run throughput variation. Latencies describe successful requests; raw data also records p95 across all outcomes. “Verified” counts completed post-load checks, and does not imply every timed write succeeded.

| Workload | Backend | Added object / metadata latency | Success / attempted | Median writes/s (range) | Median run p95 | Verified cells |
|---|---|---|---:|---:|---:|---:|
| Independent secrets | Raft | — | 192/192 | 231.18 (213.73–316.25) | 54.0 ms | 3/3 |
| Independent secrets | Object WAL | 0 ms / — | 192/192 | 140.81 (125.26–162.24) | 159.1 ms | 3/3 |
| Independent secrets | Object WAL | 25 ms / — | 192/192 | 6.48 (6.45–6.91) | 3667.8 ms | 2/3 |
| Independent secrets | Transactional metadata | 0 ms / 0 ms | 192/192 | 116.45 (111.18–134.02) | 190.9 ms | 3/3 |
| Independent secrets | Transactional metadata | 25 ms / 0 ms | 192/192 | 14.89 (13.44–14.92) | 1839.7 ms | 3/3 |
| One policy | Raft | — | 128/128 | 107.08 (66.49–147.67) | 146.7 ms | 1/3 |
| One policy | Object WAL | 0 ms / — | 192/192 | 98.62 (71.85–109.41) | 273.5 ms | 3/3 |
| One policy | Object WAL | 25 ms / — | 192/192 | 6.68 (6.19–6.73) | 3787.5 ms | 3/3 |
| One policy | Transactional metadata | 0 ms / 0 ms | 192/192 | 83.25 (50.12–91.14) | 287.0 ms | 3/3 |
| One policy | Transactional metadata | 25 ms / 0 ms | 188/192 | 14.02 (3.43–14.74) | 2123.4 ms | 3/3 |

Raw data: [primary matrix](../test/pilot/cds-load/results/2026-11-03-metadata-comparison.json).

## Controls

Equal added latency removed most of the apparent metadata advantage. The metadata
control added 25 ms to both services, with 64 requests at concurrency 16 and one
repetition per workload. Both cells completed all 64 writes and their checks.
The object-WAL values below are the three-run primary medians, not a new paired
sample. These short exploratory runs do not establish statistical equivalence.

| Workload | Object WAL, object +25 ms | Metadata, object +25 / metadata +0 ms | Metadata, both +25 ms |
|---|---:|---:|---:|
| Independent secrets | 6.48 writes/s | 14.89 writes/s | 6.37 writes/s |
| One policy | 6.68 writes/s | 14.02 writes/s | 6.60 writes/s |

A serial control used concurrency 1, 64 writes, one repetition, and no added
latency. All six cells completed their writes and checks. Raft's independent
case recorded 21 HTTP 503 responses during safe post-fault probes before recovery;
this was not a run without availability errors.

| Workload | Raft writes/s | Object WAL writes/s | Metadata writes/s |
|---|---:|---:|---:|
| Independent secrets | 9.46 | 42.48 | 35.31 |
| One policy | 9.56 | 39.27 | 33.37 |

The direct-writer smoke test completed both workloads on object WAL and metadata
(eight writes, concurrency 4, no added delay): four cells, 32/32 successful writes,
and all checks completed. Its small sample is a functional check of competing
publishers, not a capacity result.

Raw controls: [equal added latency](../test/pilot/cds-load/results/2026-11-03-metadata-matched-latency.json),
[serial](../test/pilot/cds-load/results/2026-11-03-metadata-serial.json),
[direct writers](../test/pilot/cds-load/results/2026-11-03-metadata-direct-smoke.json).

## Final comparison with identical revocation requirements

The final harness requires HTTP 403 on every replica for secret reads started
after revocation acknowledgement, with no Raft lease exception. It also fails
a cell on any unsuccessful timed write while continuing to verify acknowledged
requests. A follow-up used 16 writes, concurrency 16, one repetition, object
delay 0/25 ms, and metadata delay 0 ms: ten cells, 160/160 successful writes.

| Backend | Cells | Replay and writer-loss checks | Immediate revocation |
|---|---:|---:|---:|
| Raft | 2 | 2/2 passed | 1/2 passed |
| Object WAL | 4 | 4/4 passed | 4/4 passed |
| Transactional metadata | 4 | 4/4 passed | 4/4 passed |

Raft's independent-secrets cell returned **HTTP 200 from replica 2 after the
revocation write was acknowledged**. The test counted one stale release and
failed immediately. This is compatible with its existing cached read-confirmation
window; it fails the stronger common requirement. The baseline implementation
was not modified. The test exited nonzero, with nine cells completing every
check. No post-fault probe errors were recorded in this short follow-up.

This is a local observation, not a proof under all partitions. It demonstrates
that treating the current implementations as offering identical revocation
guarantees would be incorrect. Raw data:
[strict comparison](../test/pilot/cds-load/results/2026-11-03-metadata-strict.json).

## Failures and limits

- Metadata, one-policy workload, 25 ms object / 0 ms metadata, repetition 2: 60/64 writes succeeded. Four returned 503 with unknown commit outcomes after operation deadlines. Successful-request p95 was 10.69 s and throughput was 3.43 writes/s. The acknowledged requests passed the subsequent checks. No client retries were used to turn these failures into successes.
- Object WAL, independent secrets, 25 ms, repetition 3: all 64 writes succeeded, but a post-restart secret read timed out awaiting HTTP response headers. Verification did not complete.
- Raft, one policy, repetition 1: all 64 writes succeeded, but a replay probe received 503 because its replica was not serving. Verification did not complete.
- Raft, one policy, repetition 2: bootstrap did not reach three serving replicas within one minute; no load requests were attempted.
- One metadata independent-secrets case recorded a 503 during a safe post-fault probe and recovered within the configured retry budget. These probe errors are separate from timed business-write failures.

These observations do not establish that acknowledged state was lost, and incomplete checks cannot establish its preservation either. No replay acceptance, incorrect returned secret value or stale secret release was observed in the completed primary-matrix checks. The later strict run did observe the stale release described above. The workspace uses shared resources and a four-CPU cgroup quota; observed timeouts/election failures are not attributed conclusively to the storage architecture.

The primary matrix and these controls ran before the harness was tightened to
require immediate revocation for every arm. They allowed Raft its existing
up-to-five-second cached read-confirmation window, but recorded **zero stale
release reads** in every completed check. The final harness has no such exception:
any successful release started after acknowledged revocation fails the cell.
Its raw results identify `revocation_contract` explicitly. A passing local
observation does not upgrade Raft's implementation guarantee or test all network
partitions. The architectures also have different durability costs, so this is
not a production comparison with equivalent failure domains.

## Interpretation

At 25 ms added object latency with no added metadata delay, median successful throughput was about 2.3x higher for independent secrets and 2.1x higher for one-policy writes with transactional metadata. The failing metadata policy repetition is included in the range and prevents treating that median as a reliability result. With no injected delay, metadata was slower than object WAL in both workloads.

The equal-latency control supports attributing the gain to faster metadata
access, rather than SQL transactions intrinsically scaling better. These results
do not demonstrate per-key horizontal scaling, a production capacity limit, or
a reason to replace the baseline. SQLite provides durable process restart on one
machine, not metadata-host HA; production comparison would need a replicated
metadata backend and the intended cloud network.

## Validation

- Race checks passed for metadatapilot, objectwal, cdsconfig, cdsobject and CDS command integration; changed cloud launch-contract race checks passed.
- Targeted vet checks passed for the new service, client and changed CDS packages.
- Release-process storage and workload parity passed for Raft, object WAL and transactional metadata. This covers issuance, secret release, concurrent creation, token replay, writer replacement, full CDS restart for the durable backends, authority outage and revocation.
- Separate process tests passed for lost metadata commit replies, metadata SIGKILL and durable restart, cold CDS replay, and rejection of new writes while immutable-object storage was unavailable. An already-current replica could still read with a fresh metadata confirmation.
- The primary comparison and final strict comparison exited nonzero for the failures listed above. Broad repository tests and production TDX/cloud fault tests were not run.

Initial harness runs are retained in the workspace review directory: one exposed front-door rate limits during verification; another initially treated transient 503s as missing state. The final harness gives every arm the same explicit front-door budget and records bounded retries only for safe post-fault probes. Server deadlines and measured business-write retry behavior were not changed.
