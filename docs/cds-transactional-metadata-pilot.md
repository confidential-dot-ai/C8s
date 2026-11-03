# CDS transactional metadata comparison

This third comparison arm keeps immutable encrypted WAL batches and snapshots
in object storage and moves the encrypted commit head into a small transactional
metadata service. It reuses the existing CDS state machine, actor admission,
batching, forwarding, writer fencing, replay and HTTP handlers. CDS remains the
attestation, certificate-issuance and secret-release authority.

The baseline branch is `pilot/cds-object-wal` at C8s
`cda2b7a90015ea3333dfb301bc4aef85dd1cf164` and cloud
`5b5e26c7d9ca275ea3406e7f48457332ebd82ea2`. This experiment is on
`pilot/cds-transactional-metadata` in both repositories. Selecting neither
pilot still selects Raft. Selecting object WAL without `metadataEndpoint`
retains the previous object-head protocol.

## Question this experiment answers

How does moving head reads and conditional publication to transactional metadata
affect two real CDS workloads: independent operator tokens/secret paths, and
concurrent replacement of one allowlist policy?

This first implementation deliberately preserves **one ordered history per CDS
cluster**. The metadata endpoint owns one encrypted head, and every mutation
still passes through it. It does not implement Pando-style per-key partitioning
or establish that independently keyed CDS writes scale horizontally. Moving
the coordination primitive and changing the CDS consistency model are separate
experiments. A later partitioned backend must preserve the policy dependencies
of token consumption, workload binding and secret release.

Scion describes immutable changesets and CAS on Spanner references; Pando
describes immutable blobs and transactional per-reference metadata. Both are
useful architectural precedents, rather than implementations used by this code:
[Scion](https://www.anthropic.com/research/redesigning-source-control),
[Pando](https://openai.com/index/scaling-git-at-openai/).

## Commit and recovery

1. Read the current encrypted head from metadata and replay its committed suffix.
2. Upload the encrypted immutable batch to object storage.
3. Send the encrypted successor head with the previous ETag to metadata.
4. A SQL transaction checks the ETag, updates the head, and appends a receipt
   containing the previous/new ETags and ciphertext digest. Its durable commit
   is the publication point.
5. CDS applies the committed commands and returns their individual results.

An unreferenced object remains an orphan. A lost metadata reply is an ambiguous
commit; the existing WAL recovery searches committed request IDs before another
publication. The HTTP client disables redirects and automatic PUT replay.
Writer identity/epoch and log tail remain in the same encrypted head, preserving
the existing takeover fencing. The receipt is diagnostic, not an alternative
source of truth or an exactly-once guarantee for separate business requests.

Metadata receives ciphertext and a separate authentication token, never the WAL
key, secret plaintext or CA private key. Its namespace is fixed at first database
creation and checked on every request. The measured launch file contains its
HTTPS endpoint; the bearer token is delivered through the existing attested CDS
provisioning route. No credential is loaded from a CDS host environment.

The metadata process has one bounded actor owning SQLite. HTTP admission covers
64 requests, including body reads and responses, with a 64 KiB head limit. Its
actor mailbox separately holds at most 64 commands. Canceled HTTP calls can
leave a queued payload until the actor discards it; at most 129 head payloads
can be retained across handlers, mailbox and the active command (about 8 MiB).
HTTP admission overflow returns 429. Atomic counters provide status without sharing the
database connection. This is message passing with backpressure, not a formal
lock-free claim about Go channels or SQLite.

SQLite uses WAL mode and `synchronous=FULL`, verified at startup. Acknowledged
commits survive process restart with the same database and filesystem. This is
**a single-machine comparison service, not an HA metadata deployment**. Loss of
that machine or its disk prevents progress; a production design needs a durable
replicated metadata backend and independent failure-domain testing. Encryption
also does not independently detect a whole old history served to a cold cluster.
Do not put independent SQLite databases behind one load-balanced endpoint: that
would create competing authorities. Additional frontends need the same
transactional authority, supplied by a replicated database in an HA design.

Every protected request still confirms a fresh head. Metadata failure therefore
fails closed. If only immutable-object storage is unavailable, an already-current
replica can serve after confirming metadata freshness; a replica needing missing
records cannot. New commands require a durable object before publication.

## Run the metadata service

Build `go build -o cds-metadata-pilot ./cmd/cds-metadata-pilot`. Supply a dedicated
durable directory, a valid TLS certificate/key, and an independent random bearer
token in a mode-0600 file. For example, generate the token with
`(umask 077; openssl rand -hex 32 > metadata.token)`.

```sh
./cds-metadata-pilot \
  --listen 127.0.0.1:9443 \
  --db /durable/cds-pilot/metadata.db \
  --namespace cds-metadata-pilot/RUN-ID \
  --token-file metadata.token \
  --tls-cert metadata.crt --tls-key metadata.key
```

Use a new cluster, namespace and measured launch document following the
[object-WAL runbook](cds-object-wal-pilot.md), adding this public field:

```yaml
ha:
  objectWALPilot:
    # All existing required object-WAL settings still apply.
    prefix: cds-metadata-pilot/RUN-ID
    metadataEndpoint: https://metadata.example:9443
```

The service namespace must equal the object prefix. Include `metadata_token` in
the operator-local provisioning JSON alongside `key` and `credentials`, and use
the same `c8s cds object-wal provision` command. The token is independent of the
WAL encryption key. The service certificate must chain to the CDS image's trust
roots. Never disable certificate verification. Status reports
`TransactionalMetadataPilot`.

Do not repoint an existing cluster or reuse an object-WAL prefix with a fresh
metadata database. There is no migration, garbage collection, automatic token
rotation, replicated metadata failover or production rollout in this pilot.

## Reproduce locally

The integration harness builds the same release CDS binary for all arms, runs
three CDS processes plus the metadata executable where selected, and uses TLS
and attested provisioning. Only hardware evidence, inventory and the conditional
object service are fixtures. Metadata transactions use a real persistent SQLite
database. No Docker, AWS credentials or cloud resource creation is required.

```sh
CDSHA_RELEASE=1 go test -tags=integration -count=1 -v \
  -run 'TestMetadataProcessCrashAndAmbiguousCommit|TestStorageBackendParity|TestWorkloadBackendParity' \
  ./test/integration/cdsha

CDSHA_RELEASE=1 CDSHA_TRANSACTIONAL_COMPARE=1 \
CDSHA_COMPARE_REQUESTS=64 CDSHA_COMPARE_REPEATS=3 \
CDSHA_COMPARE_CONCURRENCY=16 CDSHA_COMPARE_LATENCY_MS=0,25 \
CDSHA_COMPARE_METADATA_LATENCY_MS=0 \
CDSHA_COMPARE_OUTPUT=/tmp/metadata-comparison.json \
go test -tags=integration -count=1 -v -timeout 30m \
  -run '^TestTransactionalComparison$' ./test/integration/cdsha
```

Defaults compare `raft`, `object-batch-preferred`, `metadata-batch-preferred`.
`CDSHA_COMPARE_BACKENDS` also accepts `object-batch-direct` and
`metadata-batch-direct`. Metadata latency is independently configurable: repeat
with 25 ms on both services to separate faster metadata from other effects.
Injected latency is additional to actual TLS/network/SQLite costs. Zero means
no artificial delay, not zero real latency. The 25/0 setting models metadata
closer/faster than the object service; it is not an equal-latency comparison.

Each cell has unique signed tokens. Independent writes create distinct secret
paths; contended writes replace `/allowlist`. Both require token consumption and
a state mutation. The generator performs no write retries. It records every
HTTP outcome, successful p50/p95/p99, p95 across all outcomes, object/metadata
traffic, batches, conflicts and backpressure. Failed writes can be ambiguous.
This is closed-loop diagnostic load, not a capacity or cloud benchmark.
All comparison arms explicitly use a 10,000 requests/s and 10,000-request burst
front-door budget, plus a 20,000-secret ceiling, so those default HTTP/quota
limits do not mask backend admission costs. Production defaults are unchanged.

After timing, every successful token is replayed on another replica and must be
refused. A CDS writer is killed; acknowledged tokens and secret existence are
checked on survivors. The process is replaced, acknowledged secret values are
read with a workload certificate, and the workload grant is revoked. All these
checks retain the injected latency. The comparison requires immediate refusal
of requests started after revocation acknowledgement in **every arm**. A stale
release fails the cell, including for Raft; its implementation's existing
up-to-five-second read confirmation lease is not an exception to this test.
The separate legacy parity test still checks each backend's existing contract.
After a process loss, safe probes (already-spent token replay and create-if-absent
on an acknowledged path) have a 30-second retry budget for 503/transport errors;
an in-flight final probe can extend beyond that budget until its HTTP timeout.
Those errors and the slowest probe are recorded separately from timed load
errors; they are availability failures, not evidence that data disappeared.
Unexpected successful replays, missing values and revocation violations fail
immediately. Failed timed writes also fail the cell while allowing verification
of acknowledged requests to continue. No business-load retry or server deadline
extension is introduced.

Separate faults test metadata process SIGKILL/restart, full CDS restart,
committed-but-lost metadata responses, and object-only outage. Raw comparison
results and measured limitations are in
[the results document](cds-transactional-metadata-results.md).
