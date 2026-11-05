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

## Frozen baseline, 2026-11-05

The [complete measurements](../test/pilot/cds-sealed-recovery/results/2026-11-05-storage-scale-baseline.json)
were collected sequentially: Raft, object WAL, then transactional metadata.
All three used the same CDS binary, SHA-256
`a53e4f672a784db55cfcf4bf41350090e9f0ceb9035f95a496959f2ac2069943`,
from published source `660b8b0cb7b9c02423699dcf0e293c099bc80c07`.
Each single-history workload ran twice with 64 requests and concurrency 16.
The four-cluster workload used 16 requests per cluster and total concurrency 16.

| Backend | Object delay | Four-cluster writes/s | Independent paths, writes/s | One policy, writes/s | Acceptance |
| --- | ---: | ---: | ---: | ---: | --- |
| Raft | N/A | 154.19 | 96.80–104.57 | 55.87–65.14 | Passed |
| Object WAL | 0 ms | 126.33 | 49.74–73.64 | 21.52–37.61 | Passed |
| Metadata + object WAL | 0 ms | 57.78 | 34.30–37.34 | 28.74–30.38 | Passed |
| Object WAL | 100 ms | 3.66 | 1.17–1.76 | 1.57–1.58 | Failed: burst errors and cold recovery |
| Metadata + object WAL | 100 ms | 10.62 | 3.34–4.09 | 3.80–4.60 | Failed: cold recovery |

Metadata requests have an additional 2-ms delay in both rows. Ranges describe
two measured runs; they are not confidence intervals. Raft has local peer
networking and receives no injected object-storage delay. These results test
round-trip sensitivity, not comparative cloud-provider capacity.

All zero-delay cases completed replay, same-CA process replacement, revocation
and isolation checks. Each backend also completed 96 certificate/secret-release
flows across the four clusters, including a renewal round with the same worker
keys. At 100 ms, both storage backends acknowledged all 64 multi-cluster writes,
but the first cold replacement did not become ready within 60 seconds; later
clusters' security probes were not reached. A false completion field therefore
does not establish a replay or revocation violation.

In the 100-ms single-history cases, object WAL acknowledged 112/128 independent
path writes and 116/128 hot-policy writes. The remaining outcomes included HTTP
503 and a client timeout. Metadata acknowledged 128/128 in each workload, but
all four runs failed cold recovery. These failed runs remain in the report;
successful writes and zero observed stale reads cannot substitute for complete
acceptance checks.

The shared recovery defect is an interrupted backward WAL traversal: fetching
the chain exceeds the five-second actor deadline, and each retry discards and
re-downloads the same tail. A separate correction retains authenticated
immutable records inside the existing actor while continuing to fetch a fresh
head on every attempt. Its regressions and measurements must be reported
separately from this frozen baseline. Burst-serving failures also remain a
separate performance task.

This baseline does not justify replacing production Raft. The storage design
still offers independently replaceable CDS compute and durable identity
recovery, but production readiness requires completed recovery checks, a
qualified durable authority, native custody image upgrades, and testing across
real failure domains. The metadata fixture is one SQLite process and provides
no evidence of metadata-service HA.

## Related qualification gates

The ordered work also produced two hardware results and an upgrade regression:

- [Cross-host SNP recovery](https://github.com/confidential-dot-ai/C8s/blob/pilot/cds-cross-host-recovery/docs/cds-cross-host-recovery.md)
  recovered the same CA, spent-token state, secrets and revocation after losing
  every CDS process and excluding the original recovery host. A second enrolled
  chip and its encrypted recovery copy survived. The three CDS processes shared
  one guest; this was not a three-host availability test or a physical host
  power-off test.
- [Approved CDS image transitions](https://github.com/confidential-dot-ai/C8s/blob/pilot/cds-storage-image-transitions/docs/cds-storage-image-transitions.md)
  passed with real CDS processes and software attestation/custody fixtures,
  including interrupted upgrades and total process loss. Fresh grants to
  retired images were denied. Native custody-image upgrades remain unqualified.
- [Native TDX qualification](https://github.com/confidential-dot-ai/C8s/blob/pilot/cds-tdx-recovery-qualification/docs/cds-tdx-recovery-qualification.md)
  verified two nonce-bound hardware quotes against independently built image
  and launch measurements, and rejected an old quote. The deployed module's
  successful feature query did not advertise native sealing. This qualifies
  attestation on that host/module, not TDX durable key recovery; the probe
  requested and released no secret key.

Owned Kubernetes rehearsal resources were deleted with UID-scoped cleanup and
independent absence checks: 45 resource paths across the two SNP attempts,
seven TDX resource paths, and two empty TDX pod selectors. Shared production
configuration was unchanged. Raw native TDX evidence remains local; only its
sanitized result summary is published.

The useful engineering advance is recoverable CDS identity with replaceable
compute and encrypted durable state. Its production trust contract still
requires a fresh, linearizable storage authority and release-policy control
outside the infrastructure operator's control. Full rollback of all durable
history is outside that contract. The [bounded replay correction](https://github.com/confidential-dot-ai/C8s/blob/pilot/cds-wal-replay-progress/docs/cds-wal-replay-progress.md)
records the follow-up regressions separately; it does not change the original
baseline's results or remove the remaining hardware and HA qualification gates.
