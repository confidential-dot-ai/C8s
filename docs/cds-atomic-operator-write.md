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
