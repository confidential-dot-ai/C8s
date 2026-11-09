# Current-value authority

`casregister` implements classic [CASPaxos](https://arxiv.org/abs/1802.07000) over
three fixed, distinct members. It stores the current value, accepted ballot and
promise. It does not retain a replicated command log and imports no Raft or etcd
implementation. SQLite uses a local recovery WAL.

This package supplies local peer calls for the CDS integration experiment. It
does not supply a network service, attestation, encryption or a key custodian.
The application must encrypt values and admit only approved state transitions.
A generic authority credential must not allow an infrastructure operator to
submit old state under a fresh ballot.

## Persistence and ownership

`Bootstrap(Config)` creates a previously absent authority directory and pins
its member identity, cluster enrollment and value-size limit. `Open(Config)`
requires that exact enrollment and every existing cluster database. Missing
state never implicitly creates a new register. Enrollment does not change while
the authority is running.

Each enrolled cluster has its own SQLite database, owner goroutine and bounded
mailbox. The owner persists promises before replying; acceptance persists the
promise, accepted ballot and value in one transaction before replying. SQLite
uses `synchronous=FULL`, including on replacement database connections.

Admission reserves a bounded slot before copying an accepted payload. Each
cluster holds at most `QueueSize` queued requests plus one active request. Calls
over that bound return `ErrBusy`; different clusters have independent admission
and database transactions. Limits multiply by the configured enrollment size.
Channels and database internals use synchronization; this is actor ownership,
not a formally lock-free implementation.

## Proposals and uncertainty

`NewProposer(peers, cluster, queueSize)` gives one bounded owner to a cluster's
proposals. A cryptographically random process incarnation and increasing round
form its ballots. The owner prepares a majority, selects the value with the
highest accepted ballot, evaluates the transform, then accepts on a majority.
Pure reads accept the identity transform; a prepare-only maximum read is unsafe.

`Update` retries bounded prepare contention with exponential jitter. It never
retries the transform after acceptance might have been dispatched:

- A majority of durable acceptance replies returns the chosen value.
- `ErrUnavailable` means this invocation dispatched no application acceptance.
- `ErrUnknown` means acceptance might have happened and can still happen later.

A successful result is a caller-owned copy. Pending peer calls keep their own
unchanging candidate bytes even if the caller clears or modifies that result.

An application must not turn an unknown result into a definite failure or blindly
retry a non-idempotent request. A new token-bearing request passes the application's
ordinary replay checks. This package does not introduce a historical response or
secret-bearing receipt API.

Transforms run only on the owner and must be bounded, without external effects.
They must not retain or mutate their input after returning. A transform error
aborts computation and is wrapped with `ErrUnavailable`; it is **not a confirmed
state-dependent business refusal**. Such a refusal must return the unchanged
current value with no error, then report the decision only after successful
identity acceptance. Otherwise a partially accepted value could justify a
refusal and then disappear from a later quorum.

Cancellation before acceptance atomically prevents dispatch. Queued cancellation
returns immediately; cancellation after a transform may have started waits for
owner completion so captured caller input can safely be released. Cancellation
after acceptance starts returns unknown; the transform has already finished and
the candidate has been copied. Calls have a five-second protocol deadline and
individual peer phases a one-second deadline. Callback runtime remains the
caller's bounded local-computation obligation.

Per-peer dispatch slots bound outstanding RPC goroutines. Peer implementations
must honor cancellation; response loss must not imply that the underlying storage
operation was canceled. `Close` joins the owner and its peer calls.

## Failure assumptions

The authority is operated outside the adversarial CDS infrastructure domain.
Members are trusted not to equivocate or roll back their storage. The protocol
tolerates one unavailable member while a reachable majority remains. SQLite
crash recovery does not prevent its administrator from restoring an old disk.
The filesystem/storage implementation beneath SQLite remains a deployment audit
obligation, including the strict no-Raft requirement.

The same three authority identities and their durable databases survive restart.
Lost-disk rejoin, membership replacement and configuration changes are unsupported.
Copying peers and reusing a member identity after losing its promises is unsafe.
Fresh proposer randomness assumes working cryptographic entropy and no cloning of
an already-running proposer incarnation. Attestation and clone-safe enrollment
remain deployment work. Continual competing proposals can prevent progress; no
unconditional wait-freedom or throughput advantage is claimed.

The tests cover retained-state reopening, abrupt termination of an owned process,
persistent promises, same-ballot refusal, lost acknowledgments and late accepts,
state-dependent refusal, single-use contention, cancellation, admission bounds,
cluster isolation and missing enrollment. They do not establish power-loss
durability, hostile rollback resistance or native SNP/TDX custody.
