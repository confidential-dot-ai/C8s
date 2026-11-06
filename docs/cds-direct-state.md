# CDS direct-state pilot

This branch tests whether CDS can dispense with its application WAL, replay,
checkpoint and preferred-writer protocol. Raft and the existing object-WAL /
metadata-WAL pilots remain controls. The default configuration is unchanged.

The measured opt-in is `ha.objectWALPilot.directState: true`, together with
`atomicOperatorWrites: true` and a metadata endpoint. The existing block retains
the object-store and recovery enrollment settings; the selected backend is
`DirectStatePilot`, with no running Raft node or object-WAL actor.

## Commit and recovery

1. Read a consistent set of current record versions from metadata.
2. Evaluate CDS rules in private memory. The existing FSM evaluates control and
   policy changes; shared secret quota rules evaluate individual secret paths.
3. Encrypt proposed values. Values up to 32 KiB stay encrypted in metadata;
   larger values go into immutable, hash-addressed object storage first.
4. One strictly serializable metadata transaction checks every read version and
   publishes only changed records. An operator token spend and its mutation or
   deterministic refusal are published together.
5. Acknowledge only after successful commitment. A lost response is an unknown
   result, never an automatic retry. Only a definite conflict permits a fresh
   evaluation. Unreferenced uploads remain uncommitted orphans.

A replacement reads current identity and policy directly, and reads secrets on
demand. It does not walk a command history. AEAD binds ciphertext to cluster,
measured launch, namespace, record key and monotonically increasing per-record
version. Keyed hashes hide token identifiers and secret paths from metadata. They do not hide access
patterns, object sizes or transaction structure.

| Record | Coordination |
| --- | --- |
| CA identity and signed image policy | Changed only by validated control transitions |
| Allowlist, signed route manifest, policy history | One current encrypted policy image; policy writers contend |
| Spent operator token | Separate permanent record keyed on signed JWT claims, excluding its malleable signature |
| Secret path | Separate current record; first writer and overwrite retain existing semantics |
| Secret quota counters | Exact cluster and holder budgets; new paths still contend on the cluster count |
| Sandbox bindings | One bounded current record in this first candidate; exact existing expiry/reclamation rules |

The policy image is gzip-compressed before encryption, with an 8 MiB decoded
size bound checked before publication and while reading. Secret values and the
CA private-key record are not compressed. The policy image preserves the existing
audit history. That is an application feature, not a command log used to recover other records. It currently also
contains redundant spent records for policy writes; secret tokens are separate.

## Concurrency and freshness

Each cluster has 16 write admission shards, one active transition and eight
admitted requests per shard. Read admission has 16 active / 64 admitted requests.
The existing requestgate actor owns scheduling; a hot write shard cannot occupy
every worker. Shared authoritative state belongs to metadata. Private temporary
FSM/store locks do not protect cross-request network IO.

Every authorization path reads current metadata. A fixed 64-slot atomic cache
retains at most 16 MiB of hash-verified immutable ciphertext, never current record
versions or authorization decisions. Both issuance and secret-release caches
explicitly bypass process-local generations for this backend. Missing metadata
fails closed, even when ciphertext remains cached.

Reads and writes are bounded to 16 keys, 8 MiB per value, and 16 MiB aggregate.
Conflicts are reevaluated at most 16 times within the existing five-second
operation deadline. Existing HTTP body, ingress, token time and rate limits
remain in force. This is bounded concurrent code, not a claim that Go channels
or SQLite are formally lock-free.

## Trust and remaining qualification

Metadata supplies ordering, atomicity, freshness and durability. Encryption
protects confidentiality and integrity but does not make a fully rolled-back
metadata service fresh. The object store must retain successfully uploaded
immutable values. The operator cannot be allowed to impersonate either trusted
authority under the intended threat model. There is still consensus somewhere
inside a production HA metadata service; CDS is delegating that responsibility.

The local metadata executable uses one per-cluster actor and SQLite with WAL
journaling and FULL synchronous durability. Its SQLite journal is not a CDS
application replay protocol. It is **not** replicated metadata HA. Later work
qualified the bounded native
[SNP](cds-direct-native-recovery.md) and [TDX](cds-tdx-current-recovery.md)
recovery paths for this backend. The dedicated
[metadata service HA qualification](cds-ha-metadata.md) has since passed.
The [three-host CDS comparison](cds-three-host-qualification.md) now has completed
Raft and direct-state runs, with 60 and 56 required phases respectively, using
the same guest images, client, workload and deadlines. Both passed native TDX
startup on three workers, the issuance/release burst, isolated-guest refusal,
majority service and revocation, observed authority-quorum-loss refusal, and
recovery with the same CA and replay rejection. All three image replacements
and image retirement passed, and independent audits confirmed cleanup. The
direct-state run adds three etcd members and three adapters; etcd uses Raft
internally. Earlier unsuccessful attempts and network observations are retained.
This is bounded HA evidence with a synthetic operator-known state key. Combining
it with hardware-protected key custody and total CDS replica loss is the next
qualification; the separate native custody results do not establish that
combined guarantee, production scale or an in-place migration path.

Known prototype limits: binding updates serialize; path creation shares a quota
counter; the current policy image is reconstructed in private SQLite for each
policy access; token records and unreferenced objects are retained without GC;
`TopHolders` diagnostics are not yet implemented. No in-place migration from an
existing Raft/WAL namespace is provided. A new measured configuration does not
magically authorize recovery of an old launch. These limits preclude treating
this pilot as a production replacement.

## Frozen local result

The [complete comparison](../test/pilot/cds-sealed-recovery/results/2026-11-05-direct-state.json)
retains all five unsuccessful object-policy attempts as well as the successful
compact-state candidate. Both final comparison arms use source `e12457fa`, tree
`c8562291b70c73dfdb39e961805f9e9416ad2b2b`, and identical release-binary hashes.
There are 16 client workers, two connections per replica, 100 ms added object
latency and 2 ms added metadata latency. These are local software fixtures.

| Matched workload | Metadata-WAL control | Direct current state |
| --- | ---: | ---: |
| Independent paths, successful writes | 64/64 | 64/64 |
| Independent paths, writes/s; p95 | 7.43; 3.48 s | 27.81; 1.23 s |
| Hot policy, successful writes | 64/64 | 64/64 |
| Hot policy, writes/s; p95 | 7.11; 3.45 s | 13.69; 2.72 s |
| Four clusters, writes/s in aggregate | 13.53 | 17.17 |
| Four clusters, successful writes / worker flows | 64/64; 96/96 | 64/64; 96/96 |
| Cold replacement readiness across six cases | 4.97–11.86 s | 0.54–1.05 s |
| Revocation acknowledgement, independent / hot | 145 / 117 ms | 230 / 223 ms |

Both arms retained the CA, acknowledged secrets, explicit spent-token rejection,
cluster isolation and immediate-after-acknowledgement revocation. The direct
candidate then passed three additional hot-policy rounds (192/192 writes,
20.01–24.78 writes/s). This variation is one reason not to publish a production
speedup or SLO from these samples. Revocation acknowledgement did not improve.

The final hot-policy load required no object GETs or PUTs: its compressed policy
fit inside encrypted metadata. The result does not solve high contention on a
policy that exceeds that bound. Earlier attempts deliberately retain that
negative evidence. The final candidate removes the extra policy batcher added
in those experiments; the original bounded admission shards remain.

## Local acceptance so far

The transaction tests cover concurrent single-use tokens, metadata restart,
unknown commit outcomes before/after commit, revocation between preparation and
commit, independent keys sharing policy without conflicts, bounded hot-shard
admission, ciphertext substitution and cache freshness.

The real-process HTTP test compares legacy, atomic WAL and direct-state public
responses. The direct-state workload test covers cross-replica issuance/release,
worker renewal bursts, one-process failure, total CDS process loss, original
certificate/CA continuity, acknowledged secrets and spent tokens, storage
outages, immediate-after-acknowledgement revocation, and rolling restart. These
use software attestation and a test-held key; they do not prove operator key
exclusion or native hardware recovery.

The first unmeasured acceptance attempt retained an important failure: the
secret-release cache initially trusted a constant local generation and served
after revocation. Both policy cache paths now bypass local generations for
remote state, and a targeted regression plus the full HTTP run enforce this.
The same initial run hit HTTP 429 in all three compatibility modes because it
omitted the comparison harness's existing rate settings. Subsequent comparison
runs use those identical test-only settings for every backend.

The first frozen comparison (`3bf3e151`, tree
`588dc64c410c3525cdd20a85bef4cc2ae477076b`) passed 64/64 independent-path writes
and all four-cluster correctness checks, but acknowledged only 59/64 hot-policy
writes; five requests returned 503. It is not a replacement recommendation.
One fleet cluster performed 199 object GETs while the other three needed 2–3.
A deterministic cache-collision reproducer showed two hot objects alternating
between the same slot required 20 GETs instead of two.

The follow-up keeps the same cache bound with four-way immutable atomic sets,
and retains successfully uploaded ciphertext locally. Neither change caches
current metadata or authorizes an uncommitted value. The collision regression
and complete direct-state race suite pass. A test now waits for actor shutdown
before asserting its completion notifications have drained; operation deadlines
and admission limits are unchanged.

Further frozen comparison results and custody qualification will be appended
with source trees, settings and failures. No CI, production rollout or cloud
resource creation is involved in this local phase.

The second frozen comparison (`46372896`, tree
`2b9cae086cccbbb558d06aea1e46b2e36c9beb6f`) passed independent paths and the
four-cluster checks, but still returned six 503s in 64 hot-policy writes.
The follow-up batches queued policy writes to avoid speculative uploads per
individual update. Its admission and operation deadlines are unchanged.

Current-record versions now advance by exactly one, enforced by the metadata
API. A storage client cannot reinstall an old authenticated version/value pair;
relabeling old bytes with a new version fails AEAD authentication. This does not
protect against a dishonest metadata service or whole-database rollback, and a
storage writer can still cause denial of service. Fresh metadata remains a
trusted dependency. Old prototype namespaces with random versions cannot be
opened by this revision; the pilot requires a fresh namespace.

The third frozen run (`51522e9b`, tree `afd38643fc11013de9c1f0a6a1c7c5dbcd3de719`)
returned two 503s in 64 hot-policy writes. All recorded policy batches contained
one request: the standard armTLS client permits two connections per host and
freshness checks delayed the second arrival beyond the 1 ms collection window.
The next candidate uses a bounded 25 ms policy collection window. It does not
change client pooling, admission capacity, operation deadlines or assertions.

The fourth frozen run (`52134d7e`) combined up to two policy requests per batch
but still exhausted conflict retries for one request (63/64 acknowledged).
The next revision caches validated object reads only: speculative uploads no
longer occupy the cache or give the winning writer a one-GET advantage.
Conflicts use bounded randomized backoff (1–64 ms), retaining 16 attempts and
the five-second deadline. This trades a winner's extra GET for fairer contention;
it is not a claimed general throughput improvement or a fairness guarantee.

The fifth frozen run (`187098c6`, tree `d9a5217789f6c2c948c49df4fc2a976fd5f62577`)
returned two hot-policy 503s. Backoff/cache changes did not resolve the structural
cost of rewriting a sparse SQLite policy image through object storage.

The next candidate removes the policy batcher entirely. It compresses policy
images, preserves the same current policy, version, digest, signatures and
history, and inlines encrypted records up to 32 KiB within the metadata API's
existing 64 KiB value limit. Large values still upload before metadata commits.
Tests cross the inline/object boundary, recover cold, reject corrupted or
oversized decompression, and retain outage/revocation checks with large objects.
This changes data placement, not the metadata service's capacity or deadlines.
Small-policy performance must not be extrapolated to policies whose compressed
image exceeds the inline limit; the earlier object-path contention remains a
material limitation. The comparison client retains two connections per replica
with 16 client workers, as in the WAL control.
