# CDS object-WAL pilot

This opt-in backend makes CDS compute disposable while keeping its mesh CA,
allowlist and history, operator replay protection, secrets and sandbox bindings
in an encrypted object log. It reuses the existing CDS state machine and serving
handlers. CDS remains the cluster's attestation and secret-release authority.
Raft remains selected when `ha.objectWALPilot` is absent.

The implementation and local tests are a pilot, not a production migration.
No existing cluster can switch backend by editing its measured launch file.
Run two isolated clusters and compare them before choosing a production design.

See [the recorded actor/batching comparison](cds-object-wal-results.md) for the
local matrix and the unsuccessful live-S3 comparison attempt, including limits.
The separate [transactional metadata experiment](cds-transactional-metadata-pilot.md)
routes only the encrypted head to a SQL-backed service when `metadataEndpoint`
is explicitly selected; the protocol below describes the original object-head arm.
The [sealed recovery increment](cds-protected-recovery.md) replaces raw-key
provisioning with process-bound grants in an optional mode. Its trusted key
authority is currently a local software fixture, not production key custody.

## What commits a change

1. A replica reads the current `PREFIX/head` and applies missing committed state.
2. Its actor groups admitted commands into one AES-256-GCM encrypted immutable
   batch at `PREFIX/wal/RANDOM`.
3. It replaces the encrypted head using `If-Match: ETAG`, or `If-None-Match: *`
   for the first record. **That successful conditional write is the commit.**
4. It applies each command in order through `cdsha.FSM` and returns each result.

All replicas can propose writes. By default they forward batches to a preferred
writer whose identity, address and epoch are in the **same encrypted CAS head**
as the committed tail. No clock lease grants commit authority. After an
unreachable writer, a contender resolves any ambiguous commit, then claims a
new epoch through that head CAS. An old writer cannot commit with its old ETag
or rebase a forwarded batch across the new epoch. The object service supplies
linearizable ordering; this backend runs no Raft election or peer quorum.

Forwarding uses pinned armTLS with the committed CDS images and exact launch
bytes. A domain-separated HMAC from the attested WAL key authenticates the body.
Only measured replica addresses on the CDS client port are dialed. Redirects
and transparent POST retries are disabled. A receipt causes the origin to replay
its original results. Duplicate requests are checked against retained history,
including across checkpoints. Writer backpressure does not trigger takeover.
`directWriters: true` selects the competing-CAS baseline for comparison.

A request ID survives internal retries. After a lost commit response, the
replica searches committed history for that ID, even if other writers have
advanced the head or checkpointed. The SDK never retries PUT itself. An upload
without a committed head reference is an orphan and is never applied. If the
deadline expires with an unknown outcome, the write fails with an unavailable
result; callers must reconcile before retrying a business operation. This is
not an exactly-once guarantee across separate HTTP retries.

Every protected HTTP request confirms a fresh head before serving. A 500 ms
background poll catches up idle replicas; readiness expires after five seconds
without a successful observation. An object-store outage fails closed for
protected requests immediately upon their failed read. `/readyz` can reflect
the most recent background observation until that observation expires.

The head, commands, snapshots, CA private key and secret values are encrypted.
Associated data binds each object to its full name, cluster and measured launch
digest. Ciphertext hashes link records. Storage must preserve acknowledged
objects and linearizable head updates: encryption detects alteration but does
not independently detect an entire old history served to a cold cluster.

## Files and cloud integration

| Location | Change |
|---|---|
| `internal/objectwal` | Encrypted log, conditional publication, recovery, checkpoints and S3 adapter |
| `internal/cdsobject` | Adapter to the existing CDS state machine and stores |
| `internal/cdsconfig` | Measured public `ha.objectWALPilot` settings |
| `internal/cmds/cds` | Backend selection, fresh-read gate, attested provisioning and diagnostics |
| `test/integration/cdsha` | Same three-process policy, issuance and secret-release flows against Raft and object WAL; process loss, total restart and outage |
| `test/pilot/cds-load` | Pinned HTTP load generator usable against either cloud pilot arm |
| `cloud/internal/launchcontract` (companion branch) | Accept the public pilot block in the existing measured-file envelope; reject embedded keys and credentials |

The companion `cloud` branch is also `pilot/cds-object-wal`. Deploy its launch
validator before submitting a pilot launch file through the cloud API. Neither
branch changes placement, production manifests, the cluster catalog or traffic
routing. The workspace specification is unchanged by this experiment.

## Cloud fixture

Use the existing `c8s-cds/1` launch-file transport and TDX VM path in our cloud.
Build a CDS image from this branch with the normal release build settings and
publish its reference measurements through the existing image-build procedure.
The usual integration suite uses `c8s_dev` timing overrides; the local pilot
command below selects release processes. **Cloud comparisons must use normal
release timings for both arms**.

Create separate pilot projects/namespaces and cluster IDs, e.g.
`cds-raft-pilot` and `cds-object-pilot`, each with three identical CDS VMs and
synthetic workloads. The first cloud comparison can place all three VMs on one
host: it tests VM failure and total-compute-loss recovery. Record actual placement;
continued service during a host failure requires a later run with independent
hosts. Do not use the SNP `test/e2e/cds-ha-vms.sh` lane for these TDX guests.

Both arms use the same image, CPU/memory, workload policy and client location.
For the load matrix below, set `--secrets-max-paths 20000` on both arms so quota
does not masquerade as a backend limit. Local allowlist storage must be tmpfs
and `--allowlist-persistent` must remain false. The object arm needs outbound
HTTPS to its S3 service and replica forwarding on 8443. Both serve clients
on 8443; the Raft arm additionally needs its existing peer connectivity on 8444.

Start with a **dedicated AWS S3 Standard bucket in `us-east-2`**, with a unique
prefix for this exact cluster/launch file. Disable public access and lifecycle
deletion for the active prefix. Grant `s3:GetObject` and `s3:PutObject` on
`BUCKET/PREFIX/*`, plus `s3:ListBucket` on the dedicated bucket. S3 needs the
latter permission to return 404 for an absent initial head instead of 403;
the implementation issues no LIST calls. Do not grant deletion.
Never replace or restore `head` out of band while the pilot is running.
Bucket administration and disaster recovery remain separate operator duties.

No writes-per-second throttle or GCS-specific workaround is embedded in the
protocol. `endpoint` and `pathStyle` permit our own HTTPS S3-compatible service
as a separate trial, provided it passes the same conditional-write, consistency
and fault checks. A compatible API alone is insufficient. S3 Express is a
subsequent experiment: its directory-bucket credentials, availability model
and endpoint behavior have not been validated by this pilot.

## Configure and provision

Create the normal HA launch file using the existing `c8s cds config new`
workflow. Before measuring and pinning it, add this block under `ha`:

```yaml
ha:
  replicas: [cds-object-1.example.org, cds-object-2.example.org, cds-object-3.example.org]
  voters: 3
  objectWALPilot:
    bucket: YOUR-DEDICATED-PILOT-BUCKET
    region: us-east-2
    prefix: cds-object-pilot/RUN-ID
    keySHA256: LOWERCASE-SHA256-OF-THE-32-BYTE-KEY
    # directWriters: false   # preferred writer, fenced by head CAS
    # batchMaxEntries: 64
    # batchMaxBytes: 4194304
    # batchDelayMS: 2
    # queueMaxRequests: 256
    # queueMaxBytes: 16777216
    # endpoint: https://objects.example.org  # optional custom service
    # pathStyle: true                       # optional custom service
```

`voters` remains required by the shared launch schema but has no quorum meaning
for the object backend. Each `replicas` name should resolve to its intended
replica for the existing operator status commands. Keep every replica's launch
bytes identical. Build client pin documents against those exact final bytes.

Generate a random key on the **operator's machine**, outside repository and
host configuration. Retain it securely for total-compute-loss recovery:

```sh
umask 077
openssl rand 32 > wal.key
sha256sum wal.key
```

Put only that digest in `keySHA256`. Construct a provisioning document using
the key and scoped S3 credentials obtained through the operator's usual flow:

```sh
python3 - wal.key s3-credentials.json > wal-provision.json <<'PY'
import base64, json, pathlib, sys
key = pathlib.Path(sys.argv[1]).read_bytes()
assert len(key) == 32
credentials = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert credentials["access_key_id"] and credentials["secret_access_key"]
print(json.dumps({"key": base64.b64encode(key).decode(), "credentials": credentials}))
PY
```

The credentials JSON has `access_key_id`, `secret_access_key` and, for temporary
credentials, `session_token`. These files stay on the operator machine. Do not
put them in the launch file, VM cloud-init, Kubernetes Secret or host environment.

Boot the three VMs with the measured launch file. They expose the existing
attested bootstrap listener and remain unready until provisioned and joined.
Deliver the same WAL key and credentials to each:

```sh
for target in cds-object-1.example.org cds-object-2.example.org cds-object-3.example.org; do
  c8s cds object-wal provision --target "$target" \
    --cds-pin cds-object-pin.json --input wal-provision.json
done
```

This command verifies the endpoint locally through the existing pinned armTLS
client before sending secrets. The measured key commitment authorizes
provisioning. The CDS AWS client loads no host environment or instance-metadata
credentials. Re-running provisioning with the same key refreshes expiring
credentials without changing state. Automating that delivery is outside this
pilot; expired credentials stop service until refreshed.

For the first start only, post the existing signed Genesis decree:

```sh
c8s cds ha decree genesis \
  --config cds-object.yaml --operator-key operator.key \
  --target cds-object-1.example.org --cds-pin cds-object-pin.json \
  --platform tdx --vcpus 4 --image-manifest cds-manifest.json \
  --resume-version 0
c8s cds ha status --config cds-object.yaml --cds-pin cds-object-pin.json --json
```

Match `--vcpus` to the measured image/VM shape. Expect `ObjectWALPilot`, one CA
fingerprint, `joined=true`, `serving=true`, and no Raft leader. After any restart,
reprovision the original key and credentials; replay restores the original CA
and policy. **Do not post another Genesis for restart recovery.** Wait out the
normal operator-token floor after first Genesis before starting writes.

`GET /ha/object-wal/status` reports per-process applied index, head revision,
snapshot index, GET/PUT attempts, CAS conflicts, ambiguous responses, replayed
commands, batches, writer/epoch, forwards, takeovers, admitted requests/bytes,
admission limits, rejections and a stopped flag. Collect it through a verified
client. Batch/committed-command counters count positive local CAS replies; a
commit recovered after a lost reply appears in the applied index but can be
absent from those two counters.
Counters reset with the process and include background reads and checkpoints.
The regular `/ha/status`, `/ha/decrees`, `/readyz` and CDS metrics remain available.

## Compare against Raft

Build the same load tool once and run it from the same client location. It
verifies CDS pins, warms connections, round-robins requests across endpoints,
never retries writes, and emits JSON with status counts, throughput and p50,
p95 and p99 latency for successes plus p99 for all outcomes. Status 0 means
transport failure or timeout. Failed writes can have unknown outcomes. This
is a closed-loop concurrency test, not an open-loop arrival-rate benchmark.

```sh
go build -o /tmp/cds-load ./test/pilot/cds-load
/tmp/cds-load --targets https://cds-object-1.example.org:8443,https://cds-object-2.example.org:8443,https://cds-object-3.example.org:8443 \
  --cds-pin cds-object-pin.json --mode allowlist-read --n 1000 --concurrency 4
/tmp/cds-load --targets https://cds-object-1.example.org:8443,https://cds-object-2.example.org:8443,https://cds-object-3.example.org:8443 \
  --cds-pin cds-object-pin.json --operator-key operator.key \
  --mode secret-create --n 1000 --concurrency 4
```

Repeat against the Raft arm with its endpoints and pins, at concurrency 1, 4,
16 and 64, three runs per cell. Save JSON, binary/image digests, launch files,
client location, actual VM placement and timestamps. Secret creation uses
unique synthetic paths under `/pilot/RUN-ID/`; the pilot has no delete API.
Use a fresh isolated cluster or raise identical capacity limits when repeating
enough runs to exhaust the configured ceiling.

Compare each mode separately. Current Raft serves under a confirmed read
lease; this pilot confirms each protected request against storage. An operator
secret write commits token consumption and the secret as separate commands,
each eligible for grouping with other requests. Each batch requires a WAL object
and a head PUT. Background polling and checkpoint
writes add to request cost. Report those differences with latency and costs;
do not label an object PUT or a local fixture timing as end-to-end CDS latency.

These read contracts differ: the current CDS Raft implementation permits the
previous grant during its cached read-confirmation window (one second with
`c8s_dev`, five seconds with release timings). This is a CDS serving choice,
not a limitation of Raft itself. The object pilot requires a fresh head for
every protected request. Compare revocation latency alongside response latency;
an equal-freshness performance comparison would need equivalent serving gates.

| Scenario | Evidence to collect / required behavior |
|---|---|
| Steady reads and writes | Success/error counts, latency distribution, throughput, CPU/RSS, S3 requests/bytes and CAS conflicts |
| One CDS process/VM lost | Remaining endpoints continue; measure client-visible outage and replacement catch-up |
| Two CDS VMs lost | Object arm can continue from one compute replica with S3 available; compare actual Raft quorum behavior |
| All compute lost | After reprovisioning, object arm recovers the exact acknowledged CA, secrets, token history and policy; compare Raft's existing in-memory recovery requirements |
| Storage unavailable or credentials expired | Object arm stops protected reads/issuance/releases; credential refresh and restored connectivity recover service |
| Paused writer resumes after other writes | Its obsolete head CAS fails; no committed history overwritten |
| Lost PUT response | Original operation appears once in committed history; unresolved outcomes are reported as unknown |
| Concurrent create at one secret path | One successful creation; every replica agrees on its value and origin |
| Snapshot plus suffix replay | Cold recovery preserves CA, replay protection and acknowledged commands |
| Workload attestation and secret release | Local `TestWorkloadBackendParity` exercises the full CDS flow against each arm; repeat with real workloads and hardware evidence in the cloud. The load tool alone does not exercise these |

Zero acknowledged-write loss, CA divergence, accepted token replay, competing
create winners or stale service after a failed freshness read are hard correctness
requirements. Set workload latency and recovery-time budgets before the cloud
run, then compare measured results against those budgets. No cloud performance
or TDX end-to-end result is claimed by the local tests.

## Local verification and limits

```sh
go test -race -count=1 ./internal/objectwal ./internal/cdsobject ./internal/cdsconfig ./internal/cmds/cds
CDSHA_RELEASE=1 test/integration/cdsha/run.sh -race -run 'TestStorageBackendParity|TestWorkloadBackendParity|TestObjectWALWholeClusterRestartAndOutage'
# In the companion cloud checkout:
GOWORK=off go test -race -count=1 ./internal/launchcontract
```

Run from the C8s checkout on Linux with the Go version in `go.mod`. No AWS
credentials, Docker or TEE hardware are needed. The workload scenario needs a
local non-loopback IPv4 address and permission to bind TCP port 1019, such as
`CAP_NET_BIND_SERVICE` or an isolated test environment allowing that port. It
selects a local address and measures exactly its /32 into the node CIDR bound;
the production inventory address and port checks remain enabled. The CI job
permits the port on its disposable runner. `CDSHA_RELEASE=1` builds the child
CDS processes without `c8s_dev`; omitting it keeps the existing suite's fast
election and lease settings. CI runs this workload scenario with release
processes separately from the accelerated membership/fault scenarios.

`TestWorkloadBackendParity` launches three real CDS processes for each backend,
plus mock attestation services and the real inventory token/digests handlers.
The inventory uses a Unix socket for workload tokens and mutual armTLS for CDS
callbacks. The scenario verifies:

- A challenge from one replica produces a CA-verified workload certificate at
  another, including its sandbox and matched-workload identities.
- Every replica releases an operator-provided secret to that workload over
  mutual TLS; a reused operator token is rejected on another replica.
- Three simultaneous workload creates at one path produce one winner and two
  conflicts; all replicas read the winning value.
- Issuance and release continue after one process dies (the leader in the Raft
  arm), and the replacement catches up.
- After total object-arm process loss and reprovisioning, the same CA, secrets,
  sandbox binding and spent operator token recover. A pre-restart workload
  certificate remains usable, and new issuance succeeds.
- A storage outage refuses already-prepared valid issuance and release
  requests with 503; restoring storage restores both operations.
- Revoking the workload's secret grant blocks release at every replica even
  though its issued certificate remains valid. Object WAL must reject the
  first request after acknowledgment; the Raft arm reports any reads of the
  previous grant and must stop them within its configured lease (five seconds
  in the release run, one second in the development run).

The process harness uses simulated SNP evidence, a fixed sandbox inventory and
a local HTTPS conditional-object server with the real AWS SDK. The race flag
instruments the test harness; its child CDS binaries are not race-instrumented.
This checks CDS process wiring and failure behavior;
real TDX evidence, container-runtime discovery, independent object-service
semantics and AWS performance still require separate runs. Local latency
numbers are diagnostics, not an S3 or Raft performance comparison.

## Actors, admission and batching

One actor owns each CDS cluster's WAL state and FSM application. A separate
bounded control actor owns provisioning and credential refresh. Atomic immutable
snapshots expose readiness and diagnostics without waiting for storage IO.
There is no application mutex around WAL or provisioning IO. The local object
fixture uses 32 key shards and holds no lock during network IO or injected delay.
The reused CDS stores retain their existing short locks, also used by Raft.
Go channels use runtime synchronization; this is not a formal claim that the
whole application is lock-free.

| Bound | Default / behavior |
|---|---|
| Admitted work | 256 messages, 16 MiB payload; includes active work |
| Group commit | At most 64 commands / 4 MiB, up to 2 ms collection delay |
| Remote ingress | 16 concurrent bodies, 32 MiB total encoded bytes, 12 MiB per body |
| Actor IO | 5 seconds per operation; 2 seconds for a forwarding attempt |
| Replay | 64 MiB decoded record data and 4,096 records per catch-up |

Admission reserves capacity before copying payloads. Full queues reject promptly
instead of spawning work or waiting without a bound. Cancellation while queued
prevents execution; cancellation after execution starts reports an unknown write
outcome. One canceled caller cannot cancel other commands in its batch. Shutdown
closes admission and drains every admitted request before closing the FSM.
Coalesced reads share only an observation started after they arrived.

Batch records and writer metadata use head version 2. This implementation reads
old single-command records, but older binaries reject version 2. Use fresh pilot
prefixes; do not mix versions, measured configurations or writer modes.

## Reproduce the local and S3 comparisons

The opt-in process harness runs the same release binary and signed HTTP policy
workload against four variants: Raft, single-command direct object writers,
batched direct object writers, and batched preferred writer. Each HTTP write
commits a token consumption and policy update. It does not retry failed writes.
It reports successes, errors, latency, throughput and object-attempt counters,
then checks that replicas recover and converge. Errors remain in the report even
if convergence succeeds; a passing test is not a zero-error claim.

```sh
CDSHA_RELEASE=1 CDSHA_COMPARE=1 \
  CDSHA_COMPARE_REQUESTS=48 CDSHA_COMPARE_CONCURRENCY=1,16 \
  CDSHA_COMPARE_LATENCY_MS=0,25,100 CDSHA_COMPARE_OUTPUT=/tmp/local-comparison.json \
  test/integration/cdsha/run.sh -race -run TestPilotComparison
```

The delay is added to each object request outside fixture locks. No provider
request-rate cap is simulated. Raft runs only zero-delay cells because it does
not use this service. These short, single-run cells are diagnostic; repeat larger
runs before drawing capacity conclusions. Counters include background polls and
checkpoints within the sampling window. Latency percentiles cover successes;
failed or unknown outcomes are counted separately.

For actual S3, prepare an **operator-local mode-0600 file** containing `bucket`,
`region`, `prefix` and `credentials` using the credential fields above. Use a
dedicated bucket and temporary credentials with GetObject/PutObject on the test
prefix and ListBucket on that bucket.

```sh
CDSHA_RELEASE=1 CDSHA_COMPARE=1 \
  CDSHA_COMPARE_REQUESTS=48 CDSHA_COMPARE_CONCURRENCY=1,16 \
  CDSHA_COMPARE_S3_FILE=/private/pilot-s3.json \
  CDSHA_COMPARE_OUTPUT=/tmp/s3-comparison.json \
  test/integration/cdsha/run.sh -race -run TestPilotComparison
```

`CDSHA_COMPARE_BACKENDS` optionally selects comma-separated variants named
`raft`, `object-single-direct`, `object-batch-direct`, `object-batch-preferred`.
Every S3 cell creates a random DEK and unique subprefix. The comparison discards
these synthetic test keys afterward; its encrypted test objects are disposable.
The harness creates no buckets, changes no IAM policy and deletes no objects.
Clean up its dedicated resources separately. CDS still loads credentials only
through attested provisioning, never the host chain.

The three CDS processes and client run locally; only the object service is AWS.
This measures this machine's path to S3, not CDS running inside AWS or our TDX
cloud. Compare object variants directly; local Raft versus remote S3 is not a
matched cloud deployment comparison. Raft's cached read confirmation and the
object pilot's fresh-per-request gate also have different freshness contracts.

## Remaining lifecycle limits

The pilot checkpoints after 100 commands and retains all WAL, snapshots and
orphans. It has no garbage collection or compaction; a lagging live process
replays its missing history within the replay bound; a replica beyond that bound
must restart from a checkpoint. Commands are capped at 4 MiB and encrypted objects
at 64 MiB. Monitor the reported snapshot index for checkpoint progress. A full
restart needs the retained key, credentials and original measured launch bytes.

Genesis, SetNodeImages, signed UpdateMeasurements and RotateKey decrees are enabled. The
[storage lifecycle extension](cds-storage-lifecycle.md) also renews the CA
certificate through a conditional WAL commit while retaining its key.
[Image-policy transitions](cds-storage-image-transitions.md) are covered by real
process recovery tests; native custody-image upgrades remain unqualified.
DEK rotation, Raft membership/recovery decrees, automatic
credential issuance and storage disaster-recovery procedures need separate
lifecycle work before production. Use a short-lived pilot, unique bucket
prefixes, synthetic state and the unchanged Raft deployment as the comparison.
