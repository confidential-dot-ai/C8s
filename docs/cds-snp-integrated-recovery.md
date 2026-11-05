# Integrated CDS recovery on SNP

The pilot joins the qualified SNP derivation primitive to the real CDS
process suite and `cdsrecovery.WALAuthority`. It runs three release-build CDS
processes and the authority inside one measured, disposable SNP VM. Destroying
that VM removes all CDS, authority, workload-client and attestation-service
memory. The replacement uses the same measured image and physical chip.

This is an isolated correctness experiment. It does not qualify a production
rollout, three independent failure domains, image retirement, firmware changes,
or recovery after losing every enrolled physical chip. The original Raft and
storage pilots are unchanged.

## Custody and enrollment

The first guest derives an Ed25519 authority from SNP and publishes only its
public key in an attested reply. Its derivation binds all normalized CDS
settings except that public-key field. The host checks that the resulting
launch document changes only that field, then recreates the VM with the exact
complete launch document bound in SNP `HOST_DATA`.

The complete launch bytes bind the capsule wrapping key. The firmware request
selects all six supported guest fields and the saved committed TCB/guest SVN.
SNP does not derive a key from `HOST_DATA`: the measured program checks that
binding before using the hardware key. A different measured launch must not
open the original capsule.

The WAL key is generated inside the guest. The signed registration and
`SealAuthority` capsule are persisted before releasing any grant. Every grant
uses the existing `WALAuthority`, including its current-policy replay and final
fresh-head read. Missing registration on recovery is an error, not permission
to initialize another CA. There is no software root-key option.

The pilot's local attestation API obtains actual SNP reports and uses the
existing attestation-go verifier, embedded AMD roots and CRL checks. Public
collateral travels through the host; the guest verifies it independently and
has no general network egress. The host independently verifies each phase's
nonce, full request/result binding, image, exact launch, signature and CRL.

## External persistence

The real S3 adapter talks to a local TLS endpoint that relays conditional
object operations over the owned VM tunnel. One host worker owns a SQLite
fixture with `synchronous=FULL`; it commits before replying. The external data
contains encrypted WAL objects, a signed public registration, the encrypted
authority capsule and an encrypted test-client capsule. The CA and WAL keys
never appear in the relay API.

The relay has bounded admission and message queues. This fixture exercises
conditional-write and durability semantics; its latency is not an AWS result.
It retains the pilot's trusted, linearizable object-store freshness assumption.
It does not establish resistance to an operator presenting a complete old
history to a cold recovery authority.

## Acceptance assertions

1. Three real CDS processes serve one CA and release a synthetic secret to an
   attested workload. A signed policy update revokes that access; all three
   processes refuse a fresh request after the update is acknowledged.
2. Persist the original workload leaf/key and spent operator request only in
   the encrypted test-client capsule. Remove the VM and verify its VMI is gone.
3. Recreate it with a new hardware guest identity. Restore the authority from
   SNP and the original capsule, then restore all three CDS processes from the
   external encrypted history.
4. All replicas must expose the original CA, reject the spent request with the
   explicit token-reuse error while it remains unexpired, and refuse the
   revoked workload's fresh secret requests.
5. A new signed authorization must let the original leaf read the original
   secret. This positive control rules out generic unavailability or a broken
   client being mistaken for successful revocation.

`integrated_cds_recovery_passed` is separate from the broader production and
operator-exclusion qualification flags. A successful run must also demonstrate
new VMI/report IDs, the same chip, and UID-scoped cleanup.

## Local build and owned cloud runner

`images/cds-snp-acceptance/build` stages release binaries and source receipts in
an explicitly selected `ACCEPTANCE_BUILD_DIR`. Build the profile with the pinned
ConfOS builder, the existing reviewed kernel fragment, two vCPUs and 4 GiB.
Inspect the resulting verity image, service masks, public file permissions,
binary hashes and measured boot inputs before launch.

`test/pilot/cds-sealed-recovery/hardware/integrated.py` accepts the same owned
native renderer and access-tool paths as the primitive runner. It creates only
its own claims, public launch Secret, population Pod, narrow NetworkPolicy and
Manual VM. It reuses public immutable disk artifacts across guest recreation,
does not mount a writable CDS state disk, records resource UIDs before dependent
actions, and cleans in `finally`. `cleanup` resumes from the durable journal.

All builds and tests run locally. No CI or shared-production rollout is needed.
