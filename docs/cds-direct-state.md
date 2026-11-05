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
3. Encrypt proposed values. Values up to 1 KiB stay encrypted in metadata;
   larger values go into immutable, hash-addressed object storage first.
4. One strictly serializable metadata transaction checks every read version and
   publishes only changed records. An operator token spend and its mutation or
   deterministic refusal are published together.
5. Acknowledge only after successful commitment. A lost response is an unknown
   result, never an automatic retry. Only a definite conflict permits a fresh
   evaluation. Unreferenced uploads remain uncommitted orphans.

A replacement reads current identity and policy directly, and reads secrets on
demand. It does not walk a command history. AEAD binds ciphertext to cluster,
measured launch, namespace, record key and random version. Keyed hashes hide
token identifiers and secret paths from metadata. They do not hide access
patterns, object sizes or transaction structure.

| Record | Coordination |
| --- | --- |
| CA identity and signed image policy | Changed only by validated control transitions |
| Allowlist, signed route manifest, policy history | One current encrypted policy image; policy writers contend |
| Spent operator token | Separate permanent record keyed on signed JWT claims, excluding its malleable signature |
| Secret path | Separate current record; first writer and overwrite retain existing semantics |
| Secret quota counters | Exact cluster and holder budgets; new paths still contend on the cluster count |
| Sandbox bindings | One bounded current record in this first candidate; exact existing expiry/reclamation rules |

The policy image preserves the existing audit history. That is an application
feature, not a command log used to recover other records. It currently also
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
application replay protocol. It is **not** replicated metadata HA. Provider HA,
replica placement, durable independent custody and native SNP/TDX recovery remain
separate qualification steps.

Known prototype limits: binding updates serialize; path creation shares a quota
counter; the current policy image is reconstructed in private SQLite for each
policy access; token records and unreferenced objects are retained without GC;
`TopHolders` diagnostics are not yet implemented. No in-place migration from an
existing Raft/WAL namespace is provided. A new measured configuration does not
magically authorize recovery of an old launch. These limits preclude treating
this pilot as a production replacement.

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

Frozen comparison results and the next custody qualification will be appended
with source trees, settings and failures. No CI, production rollout or cloud
resource creation is involved in this local phase.
