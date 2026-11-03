# CDS storage lifecycle

This development branch builds on the integrated concurrency pilot at
`ead656ddda63a953e71dd08a7e59670b5834487b`. It retains encrypted durable
recovery and the existing storage authority. It does not implement the separate
peer-quorum proposal or change production backend selection.

## Certificate renewal and key rotation

| Operation | Authorization and ordering | Identity and recovery |
| --- | --- | --- |
| Automatic CA certificate renewal | After half the current certificate lifetime, a replica prepares a renewal and conditionally commits it through the WAL actor | Retains the private key, issuer subject and subject key identifier. Existing leaves remain valid. Recovery restores the committed renewed certificate. |
| CA private-key rotation | Existing operator-signed RotateKey decree with its base version, intent ID and expiry; the common FSM validates and orders it | Installs a new key and certificate in the encrypted log. Existing leaves must be reissued. Cold recovery restores that new key, not another fresh identity. |

Both object-head and transactional-metadata backends use these operations.
Rotation retains secrets, policy, sandbox bindings and spent operator tokens.
A repeated signed intent or competing decree based on an old version cannot
install another key. Certificate renewal does not advance the operator decree
version.

Renewal is proposed during the existing maintenance loop. A failed storage
operation cannot publish a local-only certificate. A conflict is reconsidered
against current state on a later tick. Continuous application-write contention
can delay this optimistic maintenance; sustained-load renewal progress and its
operational alert budget still need qualification.

The two commands already exist in the shared CDS state machine. Neither stored
entries nor the encrypted object/head format gains a new field. This alone
does not qualify mixed-version or measured-image upgrades.

## Conditional maintenance

`objectwal.Log.AppendIfCurrent` admits one command into the same bounded actor
mailbox as other work. It requires an exact applied application index. The actor
reads and applies the authoritative head before checking the index, uploads the
immutable command, and publishes with the head's conditional update.

If another application command wins the CAS, the stale maintenance command is
not rebased. In particular, an old-key renewal cannot follow a winning key
rotation and stop the FSM, and a delayed renewal cannot overwrite a newer one.
A checkpoint or preferred-writer change alone does not change application state
and does not invalidate this condition.

Maintenance commits directly by CAS, without forwarding or claiming the
preferred writer's epoch. The current owner fields remain unchanged. This is
an unbatched maintenance path; ordinary writes retain batching and forwarding.
It adds no application mutex. Request/byte admission, queued cancellation,
shutdown accounting and unknown-outcome reporting remain actor-owned.

A lost response is resolved by the original request ID before checking the
application-index precondition again. If the request committed, later writes
or checkpoints must not turn that success into a false precondition failure.
Separate HTTP retries still do not have an exactly-once guarantee.

## Existing TLS connections

Publishing new TLS client roots only changes subsequent handshakes. The local
rotation scenario exposed successful secret releases on connections opened
under the old CA in both storage arms.

The shared cluster request gate now checks a presented client certificate
against the current committed mesh CA after its freshness barrier and before
dispatching a protected request. The root pool is an immutable atomic snapshot.
Verification also checks certificate validity at request time. A same-key
certificate renewal keeps old leaves valid; a key rotation refuses them with
HTTP 403 on already-established connections. The TLS listener continues its
normal verification on new connections.

This serving correction applies to the Raft and both storage backends.
Certificate-free clients retain their existing route authorization, and
bootstrap/status/health routes remain reachable under their existing rules.
New-client handshakes can wait for the existing asynchronous root-publication
loop after rotation. Other mesh consumers' trust-refresh behavior is outside
this CDS gate; this is not instantaneous revocation throughout the mesh.

## Recovery and custody boundary

The operator still retains the pilot WAL encryption key. Possession of that
key plus the ciphertext permits recovery of the CA private key. These changes
do not provide operator-inaccessible key custody. They do not rotate the WAL
encryption key, erase older encrypted CA keys from retained history, or protect
cold recovery against a storage authority serving an entirely old history.

Durable recovery with stronger key custody needs a separately protected,
attestation-aware recovery-key release design. A rollback-resistant recovery
policy also needs a trusted current-state anchor. Neither is claimed here.
Certificate validity and signed-token/decree expiry still use wall-clock time;
the absence of a writer lease does not make all CDS authorization clock-free.

## Validation

The targeted unit/race coverage exercises:

- One winner among simultaneous conditional publishers; a competing write
  after upload but before publication; lost responses behind later checkpoints.
- Bounded active/queued maintenance, cancellation and preserved writer epochs.
- Automatic renewal and recovery through both head authorities, with an
  existing leaf verified under the renewed CA.
- A paused renewal losing to a key rotation or another renewal, without
  stopping the FSM or overwriting the winner.
- Concurrent/replayed rotations and recovery of their one committed key.
- Revalidation of existing TLS state after the freshness barrier, same-key
  renewal continuity, expired leaves and unavailable current CA.

The release-process `TestCARotationBackendParity` scenario runs Raft, object
WAL and transactional metadata sequentially. It exercises the actual CDS
HTTP/TLS path with attestation/inventory fixtures, keeps workload TLS sessions
open across rotation, and checks old-leaf refusal, new issuance, secret/token
preservation and revocation. Both storage arms also lose all CDS processes and
recover the rotated identity. This is a local process test, not a hardware or
independent-host failure result.

Local results on 2026-11-03:

| Check | Outcome |
| --- | --- |
| Full race suites: object WAL, storage-backed CDS, CDS command package | Passed |
| Targeted vet and diff/format checks | Passed |
| Rotation process scenario: Raft, object WAL, transactional metadata | 3/3 passed; old leaves refused on reused TLS connections |
| Existing workload process scenario, normal rate limits | 3/3 passed; 72 burst issuances/releases, failover, strict policy revocation and rolling restarts |
| All CDS processes lost after rotation, both storage arms | Rotated CA, existing leaf, secret, binding and spent token retained |

The first rotation run reproduced HTTP 200 secret releases on old TLS
connections in both storage arms. Its Raft case first encountered a temporary
503 while the new key invalidated its serving lease. The final scenario waits
for serving to recover while retaining the old TLS connections, then requires
403 from every replica. It therefore measures correct authorization after
recovery, not zero-interruption rotation. A separate unit test installs the new
CA inside the freshness barrier and checks refusal on that same request.
The final release-process run passed all six backend/scenario cases in 147 s.

```sh
go test -race -count=1 -timeout 5m ./internal/objectwal ./internal/cdsobject ./internal/cmds/cds
CDSHA_RELEASE=1 go test -tags=integration -count=1 -timeout 15m -v \
  -run '^(TestCARotationBackendParity|TestWorkloadBackendParity)$' ./test/integration/cdsha
```

## Remaining production work

The next architectural gaps remain a replicated metadata authority with
durable failover, stronger recovery-key custody, measured-image transitions
and mixed-version validation, encryption-key rotation and bounded history
retention, and managed-Kubernetes enrollment/renewal integration. A full cloud
rehearsal still needs to compare failure domains, availability and sustained
load with the corrected Raft baseline. This branch performs no deployment or
migration and makes no production-equivalence claim.
