# Current-state recovery authority

This follow-up to [direct state](cds-direct-state.md) replaces the recovery
authority's WAL replay with reads of the same encrypted current identity record
that CDS serves. It adds no policy database, election, checkpoint, release log,
or mutable enrollment flag. Raft and WAL deployments keep their existing paths.

An enrolled authority opens its original encrypted capsule. Before releasing
the state-encryption key, it reads current metadata, authenticates/decrypts the
identity record, validates it using CDS's shared `CurrentCore.Open`, and takes
the approved CDS images from its signed current decree. It fetches a fresh,
launch-bound recipient over attested TLS, then reads current metadata again.
The release is refused if the image-policy decree changed or freshness failed.
Only the exact enrolled initial process may initialize an absent cluster.

`CurrentAuthority` and `WALAuthority` share the same private release procedure.
Neither public API accepts a replacement policy or an optional freshness
callback. The current-state authority has read-only object/metadata adapters;
its only outputs are the existing signed, recipient-encrypted grants.

The final current-policy read is the release's linearization point. A
revocation before that read prevents release. A revocation ordered after it
cannot recall a key already authorized for release, even if the grant arrives
later. A new process cannot use an earlier incarnation's encrypted grant.

The metadata service remains the trusted ordering/freshness authority. An API
client cannot reuse an old record version; a dishonest service or a complete
database rollback is outside that contract. Encryption does not establish
freshness. The local SQLite metadata process is not replicated HA.

This adapter does not create hardware custody by itself. The capsule wrapping
and signing keys must remain inside independently controlled, approved TEEs.
Software tests use a test-held wrapping key. The earlier native SNP custody
proof and TDX attestation qualification do not automatically qualify this new
backend or a cross-platform release path. The subsequent
[native SNP rehearsal](cds-direct-native-recovery.md) and
[TDX rehearsal](cds-tdx-current-recovery.md) now cover this backend after total
source guest loss with the original worker(s) excluded. They use fixed custody
images and an unreplicated metadata fixture. Custody upgrades and an HA metadata
provider remain separate qualification work. No production backend switch is
enabled here.

## Local result

The [local acceptance](../test/pilot/cds-sealed-recovery/results/2026-11-05-current-state-custody.json)
passed at source `f6ef602c`: all nine affected package race suites, vet, the
legacy/atomic/direct HTTP contract, direct-state workload parity with and
without protected recovery, and the interrupted image-transition scenario.

After stopping all three real CDS processes and reconstructing the authority
from its original capsule, approved replacements retained the same CA, rejected
still-valid spent tokens, preserved acknowledged revocation, and could use the
original workload certificate and secret after a new authorization. The cold
authority refused a retired image; a replacement refused an earlier process's
grant. Worker bursts and rolling restarts also passed. Unit tests explicitly
order revocation on either side of the final metadata read and fail closed when
that read is unavailable.

The wrapping key is retained by this software test harness. These results prove
the integration and ordering contract, not independent hardware custody or loss
of an entire authority host. No cloud resource was created for these tests.
