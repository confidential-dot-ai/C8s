# CDS actor and batching pilot results

Measured on 2026-11-03. Each cell is one short run of 48 signed HTTP policy writes across three local release-mode CDS processes. Each successful write commits operator-token consumption and a policy update. The load generator retries no writes. The test harness is race-instrumented; child processes use the normal release build.

## Local comparison at concurrency 16

| Backend | Added latency per object request | Success | Writes/s | p95 successful HTTP write | GET attempts | PUT attempts | CAS conflicts |
|---|---:|---:|---:|---:|---:|---:|---:|
| raft | 0 ms | 48/48 | 131.70 | 143 ms | 0 | 0 | 0 |
| object-single-direct | 0 ms | 48/48 | 80.84 | 472 ms | 314 | 256 | 32 |
| object-single-direct | 25 ms | 48/48 | 4.35 | 5867 ms | 486 | 424 | 115 |
| object-single-direct | 100 ms | 40/48 | 1.28 | 14226 ms | 454 | 382 | 110 |
| object-batch-direct | 0 ms | 48/48 | 56.74 | 642 ms | 266 | 208 | 42 |
| object-batch-direct | 25 ms | 48/48 | 8.12 | 2872 ms | 293 | 256 | 78 |
| object-batch-direct | 100 ms | 48/48 | 2.15 | 10242 ms | 337 | 274 | 87 |
| object-batch-preferred | 0 ms | 48/48 | 94.23 | 250 ms | 324 | 102 | 0 |
| object-batch-preferred | 25 ms | 48/48 | 7.77 | 3017 ms | 324 | 92 | 0 |
| object-batch-preferred | 100 ms | 48/48 | 1.73 | 13673 ms | 400 | 102 | 0 |

Raw data: [local-comparison.json](../test/pilot/cds-load/results/2026-11-03-local.json); full logs are retained in the workspace review artifacts. Serial cells are included in the raw data. Counters include background polls and checkpoints within the observation window. They are attempted API calls, not an AWS bill.

The preferred writer eliminated measured CAS conflicts and reduced PUTs substantially. It did not consistently reduce latency: at 100 ms per object request, the batched direct variant achieved 2.15 writes/s versus 1.73 for the preferred writer, with p95 10.24 s versus 13.67 s. Forwarding and retained-history checks add reads and hops. The unbatched direct variant had eight HTTP 503 outcomes at that setting; a timed-out mutation can have an unknown outcome. Both batched variants completed all 48 writes. All local cases subsequently recovered and converged.

These are closed-loop diagnostics, not production capacity estimates. Raft used loopback peer communication and cached read confirmations (up to five seconds); the object pilot used a fresh storage observation for each protected request. Equal hardware placement, network paths, freshness contracts, repeated larger samples, and workload-specific budgets are needed before selecting a production backend.

## Live S3 attempt

AWS Agent Toolkit and named profile `cds-pilot` were configured. Tests used a dedicated versioned S3 bucket in `us-east-2`, HTTPS-only bucket policy, SSE-S3 and existing public-access blocking. A temporary role allowed GetObject/PutObject only under `runs/`, ListBucket on that bucket, and no deletion. Production CDS continued receiving credentials through attested provisioning, not the host chain.

A ten-request probe completed five conditional PUTs and five GETs, approximately 350–445 ms each from this workspace, and rejected a stale CAS with HTTP 412. See [s3-request-probe.json](../test/pilot/cds-load/results/2026-11-03-s3-probe.json). These timings include this workspace’s proxy/network path; they are not measurements from compute in the S3 Region.

The full process comparison did not reach a valid object-backend measurement window. Direct variants lost replicas during simultaneous startup when measured-policy seeding exceeded the five-second commit deadline. Preferred-writer attempts encountered HTTP 503 responses. The failed full-run log is retained in the workspace review artifacts; the [follow-up bootstrap diagnostics](../test/pilot/cds-load/results/2026-11-03-s3-bootstrap.json) are included here. The original s3-comparison.json contains only its completed Raft cells; it must not be interpreted as a successful S3 matrix. The harness now records startup failures explicitly with attempted=0 and failed_stage=bootstrap.

Independent requests saw an S3 NoSuchKey response with an AWS request ID, followed by fast HTTP 503 responses without AWS request IDs; PyPI requests also returned 503. The failure origin is unresolved. Do not attribute these failures or latencies to S3 itself or use this run to select a backend. Deadlines and the commit protocol were not relaxed to make the test pass.

## Correctness checks

- Unit race checks passed for objectwal, cdsobject, cdsconfig and CDS command integration; the final WAL/transport changes passed the targeted race checks again.
- Release-process policy parity and full object-cluster restart/outage tests passed.
- Release-process workload parity passed for Raft and object WAL: certificate issuance, mutual-TLS secret release, token replay refusal, one-winner concurrent creation, writer generation change after process loss, total object-process restart, preserved CA/secrets/bindings/spent tokens, storage-outage refusal, and grant revocation.
- Deterministic actor/protocol tests cover bounded request/byte admission including active work, cancellation and shutdown races, individual results in group commit, lost replies behind later commits/checkpoints, overlapping writer fencing, duplicate forwarding, authentication, measured-address restrictions, overload without takeover, legacy-record recovery and replay-budget failure.
- go vet passed for changed C8s packages. The companion cloud launch-contract package passed its race tests. Diff whitespace checks passed.

The pre-existing full Raft unit suite had intermittent failures in earlier work; it was not rerun or claimed clean here. No code in internal/cdsha changed. Real TDX evidence, independent physical-host failures, lifecycle rotation, WAL garbage collection and production deployment remain outside this pilot.

## What to do next

Keep the actor/batching implementation for the pilot. Preserve both direct and preferred writer modes: the latter currently trades fewer writes and conflicts for more reads and forwarding latency. Repeat the S3 matrix on a stable, measured network path, ideally with both comparison arms placed in the intended cloud topology. Do not replace production Raft on these results.
