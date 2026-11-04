# CDS sealed recovery pilot

This branch builds on `pilot/cds-storage-lifecycle` at `e369c226`. The goal is
disposable CDS compute, durable recovery of the same identity, and a smaller
protocol to operate. CDS still attests workers, issues certificates, enforces
policy and releases secrets. Its durable state is stored separately.

The commit rule remains **upload encrypted state, conditionally publish the
head, apply, acknowledge**. Protected requests still confirm that head before
serving. Recovery uses that same history. This increment adds no peer quorum,
second commit record, clock lease, or new metadata service.

## What changes

The baseline pilot provisions a raw WAL key whose hash is in the measured
launch file. Anyone holding that key can decrypt the logged CA and secrets.
The new optional mode provisions a signed, encrypted recovery grant instead.

1. A CDS process generates an ephemeral X-Wing recipient key and random nonce
   in memory. Its public recovery request binds the cluster, full launch-file
   digest and object prefix.
2. A trusted authority fetches that request directly through pinned armTLS.
   Its approved image pins must bind the exact expected launch file. An
   operator-forwarded request is never accepted as attestation evidence.
3. The authority seals the WAL key to that process, signs the grant, and
   returns only ciphertext to the provisioning relay. The channel reuses
   `pkg/overenc` with a separate recovery transcript domain.
4. The existing bounded control actor verifies and opens the grant, creates
   the existing WAL actor, and recovers the committed FSM. It never exposes
   the recovered key through an API or local key file.

The authority public key is the measured `ha.objectWALPilot.recoveryAuthority`
field (base64 Ed25519). It is mutually exclusive with legacy `keySHA256`.
Protected mode refuses raw keys. `GET /ha/object-wal/recovery-request` serves
only public material, including while unjoined or storage is unavailable.
`POST /ha/object-wal/provision` accepts `grant`, storage credentials and the
existing optional metadata token. The CLI can relay this JSON unchanged.

The control mailbox remains bounded at eight requests; the existing separate
HTTP control admission budget also covers recovery requests. The actor owns
grant opening and credential refresh. Public recipient data is immutable,
serving flags use atomics, and no new application mutex guards IO. This is an
actor design with bounded queues, not a claim of formal lock-free progress.

## Initialization and retries

A grant defaults to recovery only. Missing history leaves the replica
unjoined; even a valid operator-signed Genesis is refused. Creating a new
cluster requires the authority to explicitly grant `allow_genesis` to its
initial process, in addition to the existing signed Genesis decree. The
authority must durably distinguish initialization from recovery.

A grant can be redelivered to the same process to retry a lost provisioning
response. Another process, cluster, configuration or prefix cannot use it.
Credential refresh must recover the same WAL key; it cannot replace that key
or elevate the process's initial Genesis permission. This adds no exactly-once
claim for separate application requests. Ordinary WAL retry semantics apply.

## Trust and remaining work

`cdsrecovery.Release` is an attested release helper, **not a deployed key
custodian**. The integration authority is explicitly a software fixture. It
owns the WAL key, signing key, approved launch policy and initialization state
in test memory. We have not established operator-inaccessible custody merely
by adding encryption or a public key to an operator-written launch file.

A production authority must protect those keys and policies from the
infrastructure operator, survive losing all CDS replicas, and authorize image
upgrades without letting the operator approve code that exports keys. Its
availability affects new provisioning and recovery; it is outside the normal
write/read path. Credential refresh currently needs a usable grant too.
Authority rollback, HA, key rotation and revocation require a concrete provider
and failure tests. Existing replicas do not periodically recheck grant policy.

The existing storage contract also remains: acknowledged objects survive and
head reads/CAS are linearizable. Encryption and sealed grants do not detect a
complete old history presented to a cold cluster. The missing-head refusal
test proves refusal to create a replacement identity, not general protection
against storage rollback or a malicious storage service.

Use fresh isolated clusters. Moving an existing operator-known WAL key into
this protocol does not erase the operator's old copy. The measured config
change is not an in-place migration or a mixed-image upgrade mechanism. Cloud
launch validation must explicitly accept the new public field before any
cloud rehearsal. Production defaults and deployments are unchanged.

## Local validation

Run locally, without CI:

```sh
go test -race ./internal/cdsrecovery ./internal/cdsconfig ./internal/cdsobject ./internal/cmds/cds
CDSHA_RELEASE=1 go test -tags integration -count=1 -timeout 15m -v \
  ./test/integration/cdsha \
  -run 'TestProtectedRecoveryRefusesDowngradeReplayAndMissingHistory|TestCARotationBackendParity'
```

The rotation comparison runs Raft, object WAL, transactional metadata, then
both storage arms with sealed recovery, sequentially. It checks old-leaf
refusal on existing TLS connections, new issuance, secret and spent-token
preservation, total CDS process loss, recovered CA identity and revocation.
The adversarial recovery scenario checks raw-key downgrade, wrong authority,
key replacement, wrong recipient, tampering, stale grant replay after restart,
and missing-history refusal. Attestation and inventory remain fixtures; these
are process and protocol checks, not hardware-custody or cloud HA results.

Local results (2026-11-03, America/Vancouver):

| Check | Result |
| --- | --- |
| Race suites: recovery, measured config, storage CDS, CDS command package | Passed |
| Vet, formatting and diff whitespace checks | Passed |
| Release-process rotation comparison | All five variants passed |
| Total process loss in four storage variants | Same rotated CA, leaf, secret, binding, spent token and acknowledged revocation retained |
| Adversarial recovery scenario | Passed, including refusal to elevate Genesis permission during refresh |

These are correctness results, not throughput measurements. All local test
processes were cleaned up. No CI job, production rollout or cloud resource
change was used for this increment.
