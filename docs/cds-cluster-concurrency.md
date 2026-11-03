# CDS cluster concurrency pilot

`pilot/cds-cluster-concurrency` builds on the common three-backend pilot at
`7117600292dc688c7e32a3256e7e32f98cb0633e`. It changes admission and local
concurrency in the same CDS server used by Raft, object WAL and transactional
metadata. It does not change the committed command format, consensus ordering,
mesh identity, encryption or acknowledgment rules. The earlier pilot branches
remain comparison baselines.

## What changes

| Path | Change | Bound / ownership |
| --- | --- | --- |
| HTTP issuance and workload requests | An admission actor schedules permits; handlers keep their original HTTP goroutine | Per CDS process: 32 executing, 128 executing + queued |
| Operator policy/secret writes, pin decrees and provisioning | A separate admission actor; policy/secret writes also have a separate rate-limit key namespace | Per process: 4 executing, 32 executing + queued |
| Policy reads for issuance and secret release | Immutable snapshots published through atomic pointers; one refresh owner signals waiting callers | One cache per source; warm production reads take no application mutex or database round trip |
| Rate-limit maps | Randomized hashing into up to 64 independently locked LRU shards | Total entries stay within the configured maximum; unused space in another shard is not borrowed |
| Certificate-tracking metrics | 64 independently locked maps; metric scans release each shard before visiting the next | No whole-map lock on every renewal; gauges are approximate during concurrent updates |
| Shared metadata listener | Immutable namespace routing to separate database actors, credentials and admission budgets | 1–256 explicitly configured clusters; 64 HTTP slots and 64 mailbox entries per cluster |

Each CDS process still serves one measured cluster. A request cannot invent a
cluster ID and allocate an actor. In the shared metadata listener, the namespace
header selects a configured service, which checks its own token before admission.
Duplicate namespace or token configuration is rejected. Files are named by a
namespace hash; namespace text is never treated as a filesystem path.

These are atomic read paths, sharded bookkeeping and actor/message passing.
They are **not a claim that the entire system is formally lock-free**. Go
channels, rate buckets, SQLite, Raft and the deterministic CDS state machine
retain synchronization. Committed mutations of one cluster still have one
order. Hot-policy contention cannot be removed by independently applying
commands that depend on the same authorization state.

## Backpressure and correctness

Admission happens before handler body reads and verification. Overflow returns
HTTP 503 with `Retry-After: 1`; the metadata service retains HTTP 429. Canceled
requests remain charged until the actor retires their messages. Releases are
idempotent. Shutdown cancels executing HTTP contexts and drains their permits
before closing the CDS backend and stores. This limits application work after
HTTP headers; it is not a transport connection or TLS-handshake limit.

The backend freshness check runs **after** admission. A queued secret request
must obtain a current committed watermark when it starts executing. Cache
waiters recheck the source generation after a refresh completes, so a refresh
started before revocation cannot satisfy a later request with an older grant.
Local generations also advance after snapshot restore and store close, even
when a restored snapshot reuses the same persisted policy version. Refresh
failure fails closed instead of returning the last cached policy.

Health and readiness probes remain independent of workload permits. The exact
POST route for authenticated object-WAL forwarding retains its existing
bounded peer admission, avoiding a cycle where client handlers wait for peer
work that needs those same client permits. Raft's peer transport is separate.
Control capacity prevents issuance traffic from using every control slot; it
does not give control commands priority over an already committed log entry.

Per-cluster budgets isolate admission, not physical CPU, network or disk.
The metadata fleet uses independent SQLite databases on one host, and remains
**a non-HA comparison service**. Never run separate authorities for the same
namespace behind a load balancer. A replicated transactional metadata service
and failure-domain tests are still required for the production third backend.

## Run several metadata clusters locally

The existing single-cluster flags continue to work. For a shared listener, use
a mode-0600 manifest whose entries reference separate private token files:

```json
[
  {"namespace": "cds/cluster-a", "token_file": "/private/cluster-a.token"},
  {"namespace": "cds/cluster-b", "token_file": "/private/cluster-b.token"}
]
```

```sh
go build -o cds-metadata-pilot ./cmd/cds-metadata-pilot
./cds-metadata-pilot \
  --listen 127.0.0.1:9443 \
  --clusters-file /private/clusters.json --db-dir /durable/cds-metadata \
  --tls-cert /private/metadata.crt --tls-key /private/metadata.key
```

The manifest is static for the process lifetime. It is exclusive with `--db`,
`--namespace` and `--token-file`. Every cluster's measured CDS configuration must
use its matching prefix and endpoint; provision its own metadata token and WAL
key through the existing attested route. The metadata process receives no WAL
key, CA private key or secret plaintext. Allocate resources for the configured
cluster count: per-cluster limits are additive on the shared host.

## Validation and scope

```sh
go test -race -timeout 5m \
  ./internal/requestgate ./internal/snapshotcache ./internal/allowlist \
  ./internal/secrets ./internal/issuer ./internal/cmds/cds \
  ./internal/metadatapilot ./cmd/cds-metadata-pilot \
  ./internal/objectwal ./internal/cdsobject ./internal/cdsha

CDSHA_RELEASE=1 CDSHA_TRANSACTIONAL_COMPARE=1 \
CDSHA_COMPARE_BACKENDS=raft,object-batch-preferred,metadata-batch-preferred \
CDSHA_COMPARE_REQUESTS=16 CDSHA_COMPARE_REPEATS=1 \
CDSHA_COMPARE_CONCURRENCY=4 CDSHA_COMPARE_LATENCY_MS=0 \
go test -tags=integration -count=1 -timeout 18m -v \
  -run '^(TestTransactionalComparison|TestWorkloadBackendParity|TestMetadataProcessCrashAndAmbiguousCommit)$' \
  ./test/integration/cdsha
```

The targeted tests cover:

- A blocked metadata database with all 64 admission slots occupied while 15
  other cluster actors commit; cross-cluster credentials are refused; reopening
  all databases preserves acknowledged heads and conditional publication state.
- Overflow before request body reads, cancellation versus grants, concurrent
  close, independent cluster gates, reserved control capacity, and freshness
  after waiting in a workload queue.
- Concurrent policy refresh during revocation, restore with a reused persisted
  version, and fail-closed reads after close or refresh failure.
- Shard capacity during concurrent churn, hot-bucket retention and concurrent
  renewal/metric scans.
- The same three-process CDS build in all three backends: independent secret
  paths and one contended policy, operator replay, process loss, release and
  immediate post-acknowledgment revocation. The workload suite adds two bursts
  of 12 certificate issuances/releases and sequential replica restarts that
  retain CA identity, secrets, spent tokens and revocation. Object-based arms
  additionally exercise loss of every CDS process and cold recovery.

The process tests use local object storage and attestation/inventory fixtures.
Their timing is diagnostic, not a cloud scale result. Certificate issuance and
re-issuance exercise the current workload path; managed-Kubernetes node-token
join/renewal is on a separate implementation branch and remains an acceptance
test to integrate. Rolling restart tests recovery of this binary; they do not
establish mixed-version compatibility or a hardware-attested image upgrade.
The Raft arm's volatile storage still cannot promise recovery after losing all
replicas. No concurrency change turns a single host into separate failure
domains.

This branch does not authorize or perform a shared production release. Cloud
PR #1149 remains subject to the pending production-rollout approval.

Recorded local outcomes and benchmark limits are in the
[concurrency results](cds-cluster-concurrency-results.md).
