# CDS current-state experiment

The `internal/cdscurrent` adapter runs existing CDS allowlist and secret handlers
over one encrypted current value per cluster. `internal/casregister` supplies a
three-member classic CASPaxos authority. This is a local integration experiment;
the deployed CDS command and its backend selection are unchanged.

```text
operator or workload request
            |
     replaceable CDS replica
     private in-memory stores
            |
     encrypted current value
            |
   three fixed authority members
   independent SQLite databases
```

## Commit and recovery

A replica decrypts the selected state, restores private copies of the actual
allowlist database, secret store and sandbox ledger, then invokes the existing
HTTP handler. The complete candidate includes the CA key and certificate,
allowlist history and spent-token journal, secrets, bindings and outstanding
secret challenges. A majority must durably accept the encrypted value before an
operator response is sent. Authorized refusals preserve their token consumption;
an invalid `If-Match` retains the handler's non-consuming behavior.

The authority retains its current accepted value and promises, not a command
history. SQLite uses a local recovery WAL. No Raft or etcd package is imported by
the adapter or its authority. This source-level property does not audit the
filesystem's physical storage service or a future deployment's dependencies.

Prepare-only contention can retry with bounded backoff. Once an acceptance may
have occurred, an inconclusive quorum returns `ErrUnknown` without reapplying the
handler. HTTP reports this as 503 with `X-CDS-Outcome: unknown`. A caller must not
treat that response as proof of cancellation. A new public request with a spent
operator token still gets replay rejection. There is no durable response-receipt
history and no status endpoint that releases a previously authorized secret.

An approved replacement needs the same provisioning key, configuration and
authority enrollment. It reads the current value and recovers the same real
ECDSA CA. `Bootstrap` is an explicit initial-enrollment operation; recovery never
calls it, and existing state cannot be overwritten by it. A missing or invalid
value causes refusal. The original allowlist journal survives, so replacement
does not reset token history or add a new process-start cutoff.

The encryption envelope uses XChaCha20-Poly1305 with fresh random nonces. Its
authenticated context binds the cluster, operator key set and application limits.
Only ciphertext crosses the authority interface. Authentication detects changed
bytes and configuration mismatches; it does not make an authority resistant to
administrative rollback.

## Secret release and isolation

A release challenge is durably consumed before the workload handler can return a
secret. Policy, secret values and sandbox bindings come from the exact snapshot
whose acceptance consumed it. The existing handler checks the verified client
certificate, challenge-bound sandbox token, approved inventory and current grant.
The local proof uses real CA-issued certificates and mutual TLS; its inventory
fixture is not hardware attestation.

This deliberately strengthens challenges from once per replica to once per
cluster across compute replacement. A failed or uncertain consumption releases
nothing. Malformed paths are rejected before consumption. A release concurrent
with revocation may linearize first; a release begun after completed revocation
must deny. Already disclosed plaintext cannot be revoked.

Each authority cluster has its own bounded actor mailbox and SQLite database.
Each proposer owns its ballot sequence; each replica bounds active requests with
channel admission. There is no application-global mutex held over network work.
Go channels, database internals and the reused private stores still use locks;
this is not a formally lock-free implementation.

The adapter limits a complete encrypted value to 8 MiB, operator bodies to the
existing 64 KiB default, secret challenges to 1,024 and bindings to 4,096. Full
state is copied for each mutation. The retained allowlist journal has no pruning
path in this adapter, so continued policy changes eventually exhaust the state
limit and refuse further mutations. These are experiment bounds, not evidence
of production throughput or bounded storage under an arbitrary workload.

## Local checks

Use the repository's Go toolchain and exact dependency versions:

```sh
GOWORK=off go test -count=1 ./internal/casregister ./internal/cdscurrent
GOWORK=off go test -race -count=1 ./internal/casregister ./internal/cdscurrent
GOWORK=off go vet ./internal/casregister ./internal/cdscurrent
GOWORK=off go list -deps ./internal/cdscurrent
```

Tests cover real CA recovery, live canonical and alternate-signature token
replay, authenticated refusal semantics, secret release and revocation, lost
accept responses, cluster isolation and two three-client register workloads.
Porcupine treats an unknown write as pending, allowing it to take effect after
the timeout. Histories include concurrent reads and writes, replica cancellation
and reads after one authority becomes unavailable.

The authority suite also kills an owned subprocess and checks that its committed
value and promise survive restart. The CDS handler recovery fixture replaces
all replica/proposer objects and reopens the durable authorities in one test
process. It does not kill three independent CDS VMs. Tests create disposable
databases and local listeners and clean them up.

## Remaining production gates

- Provisioning is a caller-supplied test key. Independent, recipient-bound SNP
  and TDX key custody and hardware-protected recovery remain unimplemented.
- Authority members and proposer code are trusted. The peer interface is local;
  authenticated network transport, attested typed admission and a pinned authority
  incarnation must be implemented before exposing it across a trust boundary.
- Fixed member identities and durable promises must survive crashes. Lost-disk
  replacement, membership changes and backup restore are unsupported. Rejoining
  a member with reset promises is unsafe even after copying its peers' values.
- The adapter exposes CA reads, allowlist reads/writes, operator secret writes
  and legacy workload secret reads. Production issuance, decrees, CA renewal,
  workload secret creation and the pod-secret/KMS broker are not integrated.
- CA and credential validity still depend on the existing clock assumptions.
  An expired CA refuses recovery; no indefinite-lifetime claim is made.
- Unauthenticated requests can currently reach bounded consensus work. Preflight
  authorization, sustained-work budgets and server-enforced request read deadlines
  are required before deployment; context cancellation alone does not interrupt
  an arbitrary request-body reader.
- Hot-policy throughput, large-state copying, recovery procedures and operational
  cost must be compared against Raft. A legal history is not a performance win.

No cloud fixture or production rollout is required to run these checks. The
experiment must not be selected as a production backend until these gates pass.
