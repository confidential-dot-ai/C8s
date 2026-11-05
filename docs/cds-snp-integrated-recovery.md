# Integrated CDS recovery on SNP

The pilot joins the qualified SNP derivation primitive to the real CDS
process suite and `cdsrecovery.WALAuthority`. It uses two disposable SNP VMs:
one custodian with an unchanged launch template, and one running three release
CDS processes, the policy-checking authority and the synthetic workload client.
Destroying both VMs removes all of their memory. Replacements use the same
measured image and physical chip.

This is an isolated correctness experiment. It does not qualify a production
rollout, three independent failure domains, image retirement, firmware changes,
or recovery after losing every enrolled physical chip. Raft remains the default;
the changes stay on the pilot branch.

## Verified hardware result

Native run 08 passed on 2026-11-05 using source commit
`12612850144529503f2f3621a981a8dbd9d4c34a`. Both original VMIs were absent before
either replacement started. All three recovered CDS processes:

- Served the original CA fingerprint
  `74c50b388dc49ba7291243edf2e1bd25b5eb95746fb6f71f1ac2e1223cab5c24`.
- Rejected the original spent request with the explicit token-reuse error while
  its token remained valid.
- Rejected fresh secret requests from the previously revoked workload.
- Let the original workload leaf read the original secret only after a new
  signed authorization, ruling out generic unavailability as a false pass.

The original custody authority was reconstructed from SNP and delegated over a
new attested encrypted channel. Five distinct guest report IDs and VMI UIDs,
unchanged per-role launch hashes, the same chip, verified AMD signatures and
issuer CRLs establish the tested sequence. The CA and WAL keys were not exported
as plaintext. The [sanitized result](../test/pilot/cds-sealed-recovery/results/2026-11-05-snp-integrated.json)
records the image, binary and source hashes, phase checks and cleanup audit.

Cleanup was independently checked across all eight attempts: 124 unique owned
resource paths were absent, and the worker remained Ready and CloudQualified
without memory, disk or PID pressure. Six unrelated owner VM deletions were
recorded during the successful run; this is not a claim that the entire fleet
was unchanged or that customer application latency was measured.

Local release-process lifecycle checks also passed for Raft, current-policy object
WAL and transactional metadata. The storage backends retained the rotated CA,
existing leaf, secret, binding, spent token and revocation after total process loss.
The 300 ms storage-latency cold-recovery regression and the affected package race
suites passed. These local comparisons use software attestation; the hardware
result above qualifies the object-WAL integration on one physical chip.

## Custody and enrollment

The first guest derives an Ed25519 authority from SNP and publishes only its
public key in an attested reply. Its derivation binds the custodian's full
launch through SNP and a normalized CDS context through HKDF. The host checks
that the completed CDS document changes only the authority field. A separate
CDS VM boots that completed document; the custodian always boots its original
template, byte for byte.

SNP **always mixes `HOST_DATA` into derived keys**, independently of the six
optional guest-field selectors. [AMD's implementation](https://github.com/amd/AMD-ASPFW/blob/3ca6650dd35d878b3fcbe5c7f58b145eed042bbf/fw/psp_bl_uapps/sev_uapp/src/sev_mcmd.c#L5502)
shows this unconditional binding. Native run 02 exposed the earlier fixture's
incorrect assumption: writing the derived public key back into the custodian's
own launch changed its hardware root. Normalizing a software HKDF context
cannot undo that binding. No launch check or hardware selector is relaxed.

The custodian computes the approved CDS launch itself and verifies an actual
SNP report binding that exact launch, image and a fresh X-Wing recipient key.
Only then does it send the authority signing seed and capsule wrapping key in
a signed encrypted grant. The raw hardware root stays in the custodian. The
receiving measured fixture verifies the authority pinned in its CDS launch and
consumes the grant once. The untrusted host only transports public evidence
and ciphertext. This fixed-image delegation is an acceptance fixture, not a
production custodian API or a qualification of authority-image retirement.

The capsule wrapping key binds the unchanged custodian launch. The capsule's
authenticated identity also binds the complete CDS launch. The firmware request
selects all six supported guest fields and the saved committed TCB/guest SVN.

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
object operations over the owned VM tunnel. Four workers own persistent tunnel
connections and exchange bounded messages with one SQLite actor. Only that
actor owns the database, conditional-write order, counters and timing trace.
Its `synchronous=FULL` commit finishes before a worker may reply. The external data
contains encrypted WAL objects, a signed public registration, the encrypted
authority capsule and an encrypted test-client capsule. A distinct bounded
relay operation carries the encrypted custody grant. The CA and WAL keys never
appear as plaintext in the relay API.

The relay has bounded admission and message queues. This fixture exercises
conditional-write and durability semantics; its latency is not an AWS result.
It retains the pilot's trusted, linearizable object-store freshness assumption.
It does not establish resistance to an operator presenting a complete old
history to a cold recovery authority.

The runner's concurrency correction passes 27 local checks, including four
simultaneous create-if-absent writes with exactly one durable winner. A local
diagnostic adding 300 ms to every storage operation exposed replacement startup
timeouts in both preferred-writer and direct-writer modes. The preferred-writer
regression now passes with the corrections below and the original five-second
operation deadline. This is a correctness regression, not a production latency
or capacity qualification; direct-writer latency was not requalified.

Native run 05 completed all three CDS startups with the concurrent relay, then
stopped at the workload fixture's interface enumeration: the image's address-family
sandbox excluded route netlink. The acceptance image now allows `AF_NETLINK` for
that local query. It adds no guest egress rule, executable-input route, or shared
host setting. The corrected image was rebuilt and re-enrolled for native run 06.

Native run 06 passed the full seed phase and destroyed both VMs. Replacement
custody also passed, and all three CDS processes replayed the original CA.
One process then exited when its freshness window expired between the joining
readiness observation and startup's CA lookup. Startup now waits for a usable
current CA, stopping on process cancellation or backend exit. It never creates
a replacement identity or bypasses the freshness gate. The operation deadlines
and replay/revocation assertions remain unchanged. Focused race tests exercise
the transient gap, reuse of the recovered key, cancellation and backend exit.

Native run 07 again passed seed, custody reconstruction and replay of the original
CA, but one replacement timed out committing bootstrap workloads. The joining
listener now stays available through bootstrap and TLS preparation, so other
replicas can still reach its attested forwarding endpoint. A replacement never
forwards to its own address while its actor is executing the originating request.
Writer takeover publishes its new generation and first command in the same head
CAS, removing a separate ownership-only update and preventing claim-only churn.
Tests retain fencing and reconcile a lost takeover receipt without a duplicate.

An unchanged bootstrap seed or journal now completes after a fresh WAL read
barrier and a read-only check of the local policy store. Missing entries, generated
entry retirement and journal publication still use the normal committed path.
Journal integrity is still verified; no arbitrary mutation or token consumption
uses this shortcut. The check shares the existing seed-retirement rules and the
existing per-store lock; the WAL actor retains ownership of ordering and bounded
admission. There is no new shared lock, retry protocol or storage format.

## Acceptance assertions

1. Three real CDS processes serve one CA and release a synthetic secret to an
   attested workload. A signed policy update revokes that access; all three
   processes refuse a fresh request after the update is acknowledged.
2. Persist the original workload leaf/key and spent operator request only in
   the encrypted test-client capsule. Remove both VMs and verify both VMIs are
   gone before starting either replacement.
3. Recreate both with new hardware guest identities. Restore custody from SNP,
   delegate over the new attested encrypted channel, and restore the authority
   and all three CDS processes from the original capsules and encrypted history.
4. All replicas must expose the original CA, reject the spent request with the
   explicit token-reuse error while it remains unexpired, and refuse the
   revoked workload's fresh secret requests.
5. A new signed authorization must let the original leaf read the original
   secret. This positive control rules out generic unavailability or a broken
   client being mistaken for successful revocation.

`integrated_cds_recovery_passed` is separate from the broader production and
operator-exclusion qualification flags. A successful run must also demonstrate
five distinct VMI/report IDs (enrollment plus two pairs), unchanged per-role
launch hashes, the same chip, and UID-scoped cleanup.

## Local build and owned cloud runner

`images/cds-snp-acceptance/build` stages release binaries and source receipts in
an explicitly selected `ACCEPTANCE_BUILD_DIR`. Build the profile with the pinned
ConfOS builder, the existing reviewed kernel fragment, two vCPUs and 4 GiB.
Inspect the resulting verity image, service masks, public file permissions,
binary hashes and measured boot inputs before launch.

`test/pilot/cds-sealed-recovery/hardware/integrated.py` accepts the same owned
native renderer and access-tool paths as the primitive runner. It creates only
its own claims, public launch Secrets, population Pods, narrow NetworkPolicies
and Manual VMs. It reuses public immutable disk artifacts across guest recreation,
does not mount a writable CDS state disk, records resource UIDs before dependent
actions, and cleans in `finally`. `cleanup` resumes from the durable journal.

All builds and tests run locally. No CI or shared-production rollout is needed.
