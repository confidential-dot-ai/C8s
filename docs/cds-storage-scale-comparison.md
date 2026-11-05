# Storage backend scale comparison

This branch measures the existing Raft, object WAL and transactional metadata
backends with the same release binary. It adds atomic high-water counters to
the existing bounded WAL actor; it adds no application mutex or commit protocol.
The counters record successful slot/byte reservations rather than sampling a
queue that may have drained by the next status read.

`TestTransactionalComparison` covers independent secret paths in one history
and contention on one policy. Its results now include checkpoint lag, admission
high-water marks and replacement-process startup time with identity checks.
`TestStorageScaleComparison` additionally runs four independent three-replica
clusters concurrently. Each has its own launch, signer, CA, encryption key,
history and actors. The metadata arm shares one service process containing
separate databases and budgets; it does not receive one process per cluster.

All measured writes use independently signed single-use operator tokens. There
is no load-generator retry. Failures and all-outcome p95 remain in the results.
Every acknowledged request must reject its original still-valid token after
writer loss, preserve its value, retain the same CA after process replacement,
and reject new secret reads immediately after revocation acknowledgement.
Identical paths contain different values in different clusters; foreign operator
credentials and foreign metadata tokens must be rejected. Twelve attested
workload certificate/secret-release flows run concurrently, then repeat with
the same worker keys. This is the current workload certificate renewal flow,
not the separate managed-Kubernetes node-token enrollment API.

The inventory endpoint is intentionally still a privileged port on a real local
IPv4 address. Concurrent operator load needs no inventory callbacks. Subsequent
issuance and security checks use separately pinned inventory servers one cluster
at a time. The harness does not relax production inventory validation or pool
the clusters' attestation trust.

## Run locally, in backend order

Run from this worktree with its `go.work` enabled. Linux local networking and the
privileged inventory port must be available. The suite builds its own release
processes and kills every owned process during cleanup. It creates no cloud
resource and starts no CI job.

```sh
unset CDSHA_COMPARE_S3_FILE
export CDSHA_RELEASE=1 CDSHA_TRANSACTIONAL_COMPARE=1 CDSHA_SCALE_COMPARE=1
export CDSHA_COMPARE_REQUESTS=64 CDSHA_COMPARE_REPEATS=2
export CDSHA_COMPARE_CONCURRENCY=16 CDSHA_COMPARE_LATENCY_MS=0,100
export CDSHA_COMPARE_METADATA_LATENCY_MS=2
export CDSHA_SCALE_CLUSTERS=4 CDSHA_SCALE_REQUESTS_PER_CLUSTER=16
export CDSHA_SCALE_CONCURRENCY=16 CDSHA_SCALE_CERTIFICATE_BURST=12
export TMPDIR=/workspace/cds-scale-tmp
mkdir -p "$TMPDIR" /workspace/cds-scale-results
for backend in raft object-batch-preferred metadata-batch-preferred; do
  CDSHA_COMPARE_BACKENDS="$backend" \
  CDSHA_COMPARE_OUTPUT="/workspace/cds-scale-results/$backend-transactions.json" \
  CDSHA_SCALE_OUTPUT="/workspace/cds-scale-results/$backend-clusters.json" \
  go test -tags integration -count=1 -timeout=30m -v \
    -run '^(TestTransactionalComparison|TestStorageScaleComparison)$' \
    ./test/integration/cdsha
done
```

Admission correctness also has targeted race tests. The Fleet test fills one
cluster's entire 64-request budget while the other fifteen clusters commit,
rejects cross-cluster credentials, and reopens every database to check durable
state. The WAL test keeps canceled queued entries charged until their actor
removes them and verifies the exact peak of three requests/six bytes.

```sh
GOWORK=off go test -race -count=1 ./internal/objectwal ./internal/metadatapilot
```

## Interpret the measurements

- Injected object GET/PUT delay models round-trip sensitivity, not a provider's
  measured latency or durability. The object fixture is in memory. Metadata is
  a real SQLite process using FULL synchronous commits on one local machine;
  its replicated HA, provider networking and billing remain unqualified.
  Select a disk-backed `TMPDIR`; `/tmp` can be tmpfs. The harness prints the
  release binary hashes so results from all arms can be compared exactly.
- Load rows report elapsed wall time and per-cluster successes divided by that
  shared interval. Sum the four cluster rates for fleet throughput. Certificate
  burst latency covers the complete issuance plus successful secret-release
  flow, including the test client's cryptographic checks.
- Admission peaks are per actor since process start, including bootstrap. They
  include active operations and reserved queue entries. The storage arms check
  both count and byte limits. No claim of formal lock-free progress during
  storage I/O is made; shared state remains actor-owned.
- WAL checkpoint lag is the maximum `applied - snapshot` across the three
  observations after load. Raft's log and checkpoint indices are different and
  are not compared numerically with WAL command indices.
- Cold-process time includes starting a new CDS process, provisioning the
  existing fixture key, and waiting for all three replicas to serve. The
  restarted actor's GET/replay/snapshot counters are retained. The storage
  service, remaining replicas and host page cache stay warm. This is neither a
  cold-provider benchmark nor a new native hardware-custody proof.
- Four clusters and short bursts characterize this pilot. p99 from a small
  sample is descriptive, not a production tail-latency SLO or a capacity limit.
  CI, shared production configuration and production release remain untouched.
