# One committed operator write

The storage pilot previously committed token consumption, returned to the HTTP
handler, then committed the authorized mutation. A successful operator write
therefore needed two sequential log submissions. Losing the serving process
between them could leave a spent token without the requested mutation.

With `ha.objectWALPilot.atomicOperatorWrites: true`, the pilot submits the signed
PUT request once. The existing per-cluster WAL actor commits it, then the shared
state machine verifies its signature and exact method/path/body binding, spends
its token, and applies or refuses the mutation. A successful response still
requires a durable commit and successful application. There is no CDS Raft in
either storage arm; the storage provider supplies the ordering authority.

The combined command covers allowlist replacement, route-manifest replacement
and operator secret writes. Request authorization still checks time validity and
the token floor before admission. Historical replay verifies the signature and
binding without requiring an old token to remain unexpired. The current mesh CA
is checked when applying a route manifest. Only public response information is
returned; an occupied secret's existing value is never included.

## Failure contract

- A valid token is consumed even when its body is malformed, its version or
  digest precondition fails, or a secret write is refused. The next request
  using that token receives the existing replay refusal.
- Invalid authorization or an oversized body never reaches the log. As before,
  an impossible allowlist `If-Match` is refused before spending the token.
- Before commit-head publication, replacement processes recover neither effect.
  After publication, they replay the whole command, including its token spend
  and its mutation or deterministic refusal. Disposable local stores are rebuilt
  after an interrupted application; this is not a cross-store SQL transaction.
- A lost commit reply remains an unknown outcome. This does not add exactly-once
  response delivery, and clients must not interpret a transport error as proof
  that the mutation did not commit.

The bounded actor, group commit, preferred-writer forwarding, fresh-read gate,
CAS authority, checkpoint/replay limits and timeouts are unchanged. This adds no
production mutex, worker or service. Independent clusters retain separate
actors and admission budgets; one cluster still has one ordered history.

## Compatibility and scope

The measured option defaults to false. Raft and existing unmodified pilot
configurations retain the original path. Both modes share pure request parsers
to keep status codes and response bodies aligned.

`operator` is a new log-entry kind. All CDS and recovery readers must understand
it before a writer emits it. Old strict decoders fail closed on the new field;
they cannot continue serving by skipping it. The launch option itself is
measured, so enabling it changes launch identity. This pilot does not claim an
in-place migration of an existing immutable launch or compatibility with old
recovery readers. Image-transition tests use readers built from this source.

The new command reduces durable submissions, not the trust requirements. It
still assumes a fresh, linearizable commit authority and the existing recovery
custody design. It does not solve native custody-image upgrades, loss of every
enrolled hardware root, or TDX key recovery on hardware without native sealing.

## Local comparison

Use the [scale comparison procedure](cds-storage-scale-comparison.md), keeping
its workload and budgets fixed. Run Raft once, then object and metadata arms
with `CDSHA_ATOMIC_OPERATOR_WRITES=0` and `=1`. Use the same release binary for
all five runs. For this comparison, object operations have an injected 100-ms
delay and metadata operations 2 ms, with 64 writes at concurrency 16 and four
independent clusters of 16 writes each. Set `CDSHA_COMPARE_REPEATS=1`; this is a
short comparison, not a capacity or tail-latency qualification.

The counter assertion requires exactly one committed command for every
successful operator write when the option is enabled. Compare throughput,
all-outcome p95, batches, object operations and metadata operations as well as
the existing replay, failover, revocation, CA-identity and admission checks.

Additional acceptance tests:

```sh
go test -race -count=1 ./internal/cdsha ./internal/cdsobject \
  ./internal/cdsrecovery ./internal/cmds/cds ./internal/allowlist \
  ./internal/secrets ./internal/cdsconfig ./internal/objectwal
CDSHA_RELEASE=1 go test -tags integration -count=1 \
  -run '^TestAtomicOperatorHTTPCompatibility$' ./test/integration/cdsha
CDSHA_RELEASE=1 CDSHA_ATOMIC_OPERATOR_WRITES=1 \
  go test -tags integration -count=1 \
  -run '^TestStorageImageTransitionAndInterruptedRecovery$' \
  ./test/integration/cdsha
```

These run local CDS processes with software attestation and fixture recovery
keys. They create no cloud resources, change no production deployment and run
no CI job. Native hardware qualification remains separate.

## Results, 2026-11-05

The [complete measurements and failed attempts](../test/pilot/cds-sealed-recovery/results/2026-11-05-atomic-operator-write.json)
use published code `3c2d6429fe4ab65e02bdd693c1dcc9840628cccb`, tree
`dd5342c5ee272f161598bc4f75721ba5cd68ca8a`. All five timed arms used CDS binary
SHA-256 `99b65951257658f3b9769d944b43b2ea91a81e3dd2b2acd08938a925271f1266`.
Object operations retained the 100-ms injected delay and metadata operations
the 2-ms delay. No measured request was retried.

Transactional metadata passed all three workloads in both modes. The combined
path completed 192/192 measured writes, verified every acknowledged token's
replay refusal, and passed failover, CA identity, secret preservation, revocation
and cross-cluster isolation checks. Its four independent clusters completed 96
certificate/secret-release flows, including renewal with the same worker keys.
Admission count and byte peaks remained within their existing bounds.

| Metadata workload | Original writes/s | Combined writes/s | Original p95 | Combined p95 |
| --- | ---: | ---: | ---: | ---: |
| Independent paths, one history | 3.98 | 7.16 | 6.74 s | 4.68 s |
| One policy under contention | 3.27 | 6.49 | 9.72 s | 4.20 s |
| Four independent clusters, aggregate | 9.54 | 18.52 | Per-cluster values in JSON | Per-cluster values in JSON |

Each metadata single-history workload committed 64 commands for 64 writes,
versus 128 before. Cold-process recovery was not uniformly faster: independent
paths improved from 12.5 to 8.5 seconds, while the hot-policy case went from 8.1
to 11.7 seconds. The checkpoint trigger still counts commands, so halving
commands also changes when that unchanged trigger fires.

The pure object arm improved its hot-policy workload from 1.50 to 3.29 writes/s
and from 15.30 to 5.27 seconds p95, with 64/64 writes in both modes. Across four
clusters, combined writes completed 64/64 at 7.51 writes/s versus the original
62/64 at 3.31 writes/s. However, both modes failed subsequent worker-burst
availability checks. Independent paths also remained unreliable: the original
acknowledged 53/64 and the combined path 52/64. Acknowledged state in those
single-history cases survived replacement and passed replay and revocation
checks; HTTP 503s during load remain failures. The object arm is not qualified
by this result.

The Raft reference completed 19/64 independent-path writes and 64/64 hot-policy
writes; its four-cluster load completed 64/64 but a later worker burst failed.
These failures are retained. They are not evidence that the storage design has
stronger correctness or durability than production Raft.

HTTP parity and the combined path's interrupted-image/total-process-loss test
passed for both storage backends. Targeted race tests passed for signed-command
replay, expired historical authorization, concurrent duplicate requests,
encrypted snapshot recovery, and lost replies before/after publication in
both backends. Seven other affected packages passed their full race suites;
vet passed. The full `cdsha` race suite was not clean: it had leader/barrier
timing failures, with a nil-leader test-helper panic in an overlapping run.
The final two failing tests each passed five isolated repetitions on both the
unmodified baseline and this pilot. That does not turn the full suite green.

An initial overlapping image test timed out on object readiness; the sequential
rerun passed with unchanged deadlines. The result bundle records this and the
corrected test-fixture failures. All processes owned by this comparison exited;
an independent audit inspected 138 processes, with zero unreadable entries and
zero matching test processes. No cloud resources or CI jobs were created.

This supports keeping the combined command and favoring transactional metadata
for further qualification. It does not qualify a production Raft replacement:
the metadata service here is not replicated HA, and native custody upgrades,
TDX key recovery and sustained workloads remain open. A separate candidate
[readiness correction](https://github.com/confidential-dot-ai/C8s/tree/pilot/cds-refresh-before-serving)
addresses a cached-readiness precheck discovered during this comparison; its
source and follow-up results must be evaluated separately.
