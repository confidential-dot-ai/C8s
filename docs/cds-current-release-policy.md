# Current policy for CDS recovery

This increment adds `cdsrecovery.WALAuthority` on top of the
[sealed-custody experiment](cds-sealed-custody-experiment.md). It uses the
existing encrypted WAL, its existing commit head and the complete CDS FSM.
It adds no policy service, policy head, release ledger or write to storage.

The change gates **recovery-key release to CDS replicas**. Worker joins,
certificate issuance and secret requests still use CDS's existing handlers;
they do not call this authority for each operation.

## Release rule

1. Replay through a fresh committed head and read the FSM's current signed
   `PinsDecree`.
2. Fetch the recipient's ephemeral request over armTLS pinned to those images
   and the exact enrolled launch file.
3. Read the committed head again. Release only if the current image-policy
   intent still matches the one used for attestation.

Changing the image policy during attestation returns `ErrPolicyChanged`; the
caller must retry with a new attestation under current policy. Unrelated
commits, such as node-policy changes or workload writes, do not invalidate an
otherwise current CDS image policy. Storage failure, missing committed state,
known rollback, invalid replay or fenced cluster state refuses release. There
is no cached-policy fallback.

The original signed enrollment still fixes the cluster, configuration, object
prefix, destination origins, key commitment and first process's initialization
request. **Its image list is only a bootstrap policy.** After Genesis, even an
original capsule and original enrollment must obey current committed CDS pins.
An approved replacement receives the same WAL key, with Genesis permission
false; the existing encrypted history supplies the CA identity and state.

Before committed Genesis, only the exact process request recorded at enrollment
can receive a key. Thus bootstrap provisions that process first, commits the
signed Genesis, then provisions other replicas. A missing head on cold recovery
does not authorize a newly started process to reinitialize the cluster.

## Revocation ordering

Release linearizes at its final fresh head read. A revocation ordered before
that read prevents release. A revocation ordered after it overlaps an already
authorized release, whose encrypted reply may arrive later. The race tests
exercise both orders. This does not promise to recall a key or ciphertext
already released, or make acknowledgement and network delivery atomic.

## Implementation and isolation

`NewWALAuthority` requires a trusted storage binding, a fresh dedicated CDS FSM
and the exact launch file. `RestoreWALAuthority` additionally opens the original
capsule; it cannot skip current-policy checking. The runtime constructing the
FSM and store must derive their configuration from the independently approved
measured launch, including the policy-signing keys. The caller owns the FSM's
stores and closes them after the authority.

The authority's WAL actor is read-only, including a store wrapper that refuses
PUT. It uses the same signature, version, replay and snapshot validation as CDS,
so there is no second state-machine interpretation of what was accepted. It
replays the whole cluster state, not just policy: this is an explicit memory
and cold-start cost of reusing that implementation.

The existing per-cluster admission actor admits at most sixteen releases,
with four active at once. Each authority owns its replay actor and FSM. A
blocked cluster cannot spend another cluster's permits. Shutdown cancels IO,
drains active work and clears the authority's key buffers. No new application
mutex or process-wide work queue was added; existing per-FSM/store locks remain.

## Local validation

The deterministic tests exercise original-capsule replay after a signed image
update, approved image replacement with the same key, cold snapshot recovery,
both revocation race orders, failure of the final read, outage recovery,
missing heads, known rollback, forged/stale decrees, per-cluster saturation and
cancellation. A separate counterexample deliberately violates the storage
contract and confirms that whole-history rollback remains outside this proof.

Two new variants in the existing real-process suite use this authority:
`object-wal-current` and `transactional-metadata-current`. They use the same
TLS object adapter as CDS; the metadata variant reads its head from the separate
transactional metadata process. Both run the workload and CA-rotation scenarios,
including total CDS process loss, authority reconstruction, identity recovery,
spent-token rejection, acknowledged revocation and rolling restarts. Keys and
attestation remain software fixtures; hardware custody is unverified.

The local runner now requires fourteen backend/scenario combinations, retaining
Raft and all previous storage variants:

```sh
test/pilot/cds-recovery-acceptance/run-local.sh /tmp/cds-current-policy-001
```

It uses no CI or cloud resources. Choose a fresh output directory. The report
continues to keep `full_acceptance_passed` and `production_qualified` false.

## Remaining boundaries

- **Trusted freshness:** storage must supply durable, linearizable reads/CAS.
  A cold authority cannot detect a complete authentic old history served in
  violation of that contract. The counterexample remains executable.
- **Retired custody code:** this gate governs new releases through this code.
  It cannot force an older ungated authority image to obey it or erase a key
  already available to compromised code. Only the gated runtime may be enrolled
  when qualifying a hardware root. The legacy `Authority` remains available
  solely for baseline comparisons; this is not a migration of old sealed roots.
- **Policy control:** infrastructure administrators must not also control the
  policy-signing keys if the requirement is to exclude them from CA access.
- **Production wiring:** the new authority is a library exercised by the pilot
  fixture, not a deployed key service. Signed image transitions use the existing
  FSM/WAL command format in the focused tests. The object backend's public
  decree endpoint still needs its broader image-upgrade lifecycle implemented;
  this change does not claim that running retired CDS replicas lose keys.

## Hardware run status

The native SNP sentinel probe is still awaiting a measured image and an isolated
guest run. On 2026-11-04, Cloud PR #1149 remained open, unmerged and conflicted at
`0fdaa620`; its catalog entry pins an older TDX-only artifact. It cannot launch
the SNP probe. The existing CDS image has no shell, and its image profile does
not install the probe. Copying a binary into an ordinary guest would not qualify
the protected runtime.

The local Docker daemon is available, but the confos checkout has no compiled
builder, mkosi tools tree or kernel-builder output. The next hardware increment
needs a dedicated probe image built locally, its measured artifact pinned in an
isolated launch path, then same-chip restart and different-chip refusal checks.
No CI, shared production release, host installation or production resource
mutation was performed for this increment.
