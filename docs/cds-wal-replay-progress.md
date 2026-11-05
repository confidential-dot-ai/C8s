# Bounded progress during interrupted WAL recovery

The 100-ms object-latency comparison exposed a cold-start failure: a replacement
with no checkpoint could not fetch its whole linked WAL inside the existing
five-second operation timeout. Each retry fetched the same tail again, discarded
the partial walk, and never reached Genesis. Two surviving replicas continued
serving, but the third remained unavailable.

The existing WAL actor now retains decoded immutable records that have already
passed reference-hash, AEAD, format and index validation. The cache is keyed by
the entire immutable reference and shares the existing replay limits: at most
4096 records and the configured byte budget (64 MiB by default). Timeouts retain
progress. A successful replay, a replacing snapshot or a terminal integrity
error releases it. No lock, background worker, persisted format or new service is
added.

Every attempt still reads the current commit head. The entire reference chain
must connect to the applied state before commands are applied or freshness is
advertised. Cached immutable content cannot make an old commit head current.
The five-second timeout and request-admission limits are unchanged.

The deterministic regression gives each attempt enough GETs for the head and
three new records, then commits a revocation during interrupted recovery. The
replacement must progress across attempts, fetch the latest head each time,
apply all thirteen commands in order, and release the cache. A second regression
fills the byte budget across retries and requires a new checkpoint to replace
that retained work without exceeding the budget.

This correction addresses recovery progress. The frozen comparison's burst
timeouts at 100-ms object latency are separate performance/availability results;
they are not relabeled as successes by this change.

## Validation, 2026-11-05

The [complete corrected-run measurements](../test/pilot/cds-sealed-recovery/results/2026-11-05-wal-replay-progress.json)
use published code `0409729b12cb3e45c91d664f8943e7cb70e2c761`, tree
`407485843127734bdbd09a86ad087a4287a61811`. All process regressions used
the same CDS binary, SHA-256
`d14d987e7b64712bb255d39df365ff473af5620b405276b899f31fa55ede97c4`.
The object GET/PUT delay remained 100 ms and metadata delay remained 2 ms.
Admission bounds and production deadlines were unchanged.

| Corrected regression | Object WAL | Transactional metadata |
| --- | --- | --- |
| Four independent clusters, 64 writes total | Passed, 64/64 acknowledged | Passed, 64/64 acknowledged |
| Cold replacement in every cluster | Passed, 7.4–8.6 seconds | Passed, 6.8–10.4 seconds |
| Independent paths in one history, 64 writes | Passed, 64/64 acknowledged | Passed, 64/64 acknowledged |
| One hot policy, 64 writes | Passed, 64/64 acknowledged | Passed, 64/64 acknowledged |
| Interrupted image upgrade and total process loss | Passed | Passed |

All 384 acknowledged writes across the scale and single-history regressions
completed their replay checks; every case preserved its CA and verified
revocation. No tested release after revocation acknowledgement succeeded. The
eight independent clusters also completed 192 certificate/secret-release
flows, including renewal with the same worker keys. Recovered actors reported
32–48 replay-cache hits in the four-cluster cases and released their retained
cache after successful synchronization.

The image regression uses real CDS processes, software attestation and a
fixture recovery root. Each backend recovered after total process loss during
an overlapping-image upgrade, then recovered again after retiring the old
image. It preserved the original CA, spent token, revoked policy and original
leaf/secret, and denied both a fresh grant to the retired image and a previous
incarnation's provisioning grant. This is not a native custody-image upgrade
qualification.

Race tests passed for `internal/objectwal`, `internal/cdsobject` and
`internal/cdsrecovery`; vet passed for all three. The new deterministic tests
verify progress across interrupted reads, a revocation arriving between
attempts, bounded retained work, and a checkpoint replacing that work. All
owned local test processes exited; an independent command-line audit found no
remaining processes under either comparison's executable directory. The three
preexisting local rehearsal containers were left running.

## What this establishes

The cold-recovery stall is corrected without adding a lock, service, persisted
protocol or larger timeout. The [original baseline](https://github.com/confidential-dot-ai/C8s/blob/pilot/cds-storage-scale-comparison/docs/cds-storage-scale-comparison.md)
and all its failures remain available separately. These are targeted
regressions: the single-history cases ran once each here, versus twice in the
baseline. They do not establish a capacity limit or erase the baseline's burst
timeouts.

Latency remains a production qualification task. In the corrected
single-history runs, object WAL's write p95 was 14.6–16.2 seconds and metadata's
was about 7.8 seconds under the injected object delay. Larger sustained loads,
real storage networking and real failure domains still need qualification.
The metadata fixture remains one SQLite service, native custody-image upgrades
are unqualified, and the tested TDX module did not advertise native sealing.
This change therefore supports continued development; it is not approval to
replace production Raft.
