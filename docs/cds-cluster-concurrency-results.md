# Local concurrency validation — 2026-11-03

The changes are on `pilot/cds-cluster-concurrency`, based on common pilot commit
`7117600292dc688c7e32a3256e7e32f98cb0633e`. All testing below ran locally;
no production deployment or cloud VM fault was performed.

## Correctness results

| Check | Result |
| --- | --- |
| Race detector, 11 affected/backend packages | Passed, including the full Raft package after correcting an election-time nil-leader test poll |
| Metadata isolation across 16 configured clusters | One database blocked with 64 requests admitted; the other 15 committed successfully; cross-cluster credentials refused |
| Metadata fleet reopen | All 15 acknowledged heads and ETags retained; stale create attempts rejected |
| Six comparison cases: two workloads × three backends | 96/96 writes acknowledged; 96 replay checks; all six survived one CDS process loss and enforced immediate revocation; zero stale releases |
| Certificate issuance/re-issuance bursts | Two rounds of 12 issuances plus releases per backend: 72/72 under normal request rate limits |
| Rolling restart of all three replicas, each backend | CA identity, acknowledged secrets, spent operator tokens and revoked grants retained |
| Loss of every CDS process, object WAL and metadata arms | CA, secrets, policy, sandbox binding and replay history recovered; an existing leaf still worked |
| Metadata process crash / lost commit response | Failed closed while authority was unavailable; durable restart and cold CDS replay retained committed state |

The six comparison cells used release binaries, 16 operations per cell,
concurrency 4, one repetition and local storage without injected latency.
The broader workload test also passed for all three backends with the normal
per-source rate-limit defaults. Hardware attestation, inventory discovery and
object storage used fixtures; CDS, TLS, certificate issuance, secret handlers,
metadata process and process restarts were real.

The rolling test initially advanced from read readiness alone. A Raft
replacement can serve as a non-voter while its predecessor still owns a seat;
that sequence lost quorum when the next voter was stopped. The corrected
sequence waits for the **replacement member ID to hold its voter seat**, then
for `roll_safe`, before proceeding. Managed-Kubernetes rollouts need that
membership barrier as well as readiness. The corrected sequence passed with
both the comparison rate budget and normal request rate limits.

## Focused before/after microbenchmarks

Identical benchmark code ran against the base commit and the changed branch on
the same Linux/amd64 machine, Go 1.27.3, `GOMAXPROCS=4`, three 500 ms repetitions
per benchmark. Values below are medians of parallel throughput measurements,
not individual HTTP-request latency.

| Operation | Before | After | Allocations before → after |
| --- | ---: | ---: | ---: |
| Unchanged cached policy read | 10,258 ns/op | 5.827 ns/op | 501 B / 17 allocs → 0 B / 0 allocs |
| Independent limiter keys | 325.7 ns/op | 193.6 ns/op | 0 → 0 |

The policy benchmark uses an already-loaded document and excludes refresh,
attestation, signature checking, network/storage, and committed freshness
checks. It shows that the cached read avoids its previous SQL version query;
it is not an equivalent improvement in full CDS request latency. The limiter
benchmark uses 4,096 warm keys within a 10,000-entry cap.

## Remaining acceptance work

These results validate the concurrency changes locally. They do not select a
production storage backend or establish a fleet capacity limit. Managed-k8s
node-token enrollment/renewal, mixed-version upgrades, real hardware attestation,
independent host failures and a replicated metadata service remain to test.
The current Raft arm still has volatile replica state; the SQLite metadata
pilot still depends on one host and its disk. The three-backend cloud rehearsal
remains pending approval for Cloud PR #1149's shared production release.
