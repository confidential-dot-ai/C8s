# TDX CDS with hardware-protected recovery

This rehearsal runs real CDS on TDX and keeps durable recovery custody on two
independently enrolled SNP chips. The current-state backend and its recovery
authority are unchanged: encrypted current records, immutable large objects,
and a fresh transactional metadata read before a release. CDS does not start a
Raft node or replay an application WAL.

The existing TDX hardware qualification did not advertise the sealing feature.
This path therefore gives TDX no persistent hardware-sealing responsibility.
An SNP custodian verifies a fresh TDX quote and encrypts its grant to the
recipient's ephemeral X-Wing key. The TDX image manifest is baked into the
immutable custodian image; the caller cannot supply or replace its image pins.
The signed quote must match that manifest's MRTD, RTMR1 and RTMR2, the exact
launch binding in RTMR3, the nonce, and the recipient key. Intel signatures,
collateral, revocation and the verifier's normal TCB policy are checked. No
host-supplied clock, alternate root or relaxed TCB option is accepted.

The local TDX attestation API uses real ConfigFS quotes and the same full image
and launch checks. One bounded provider actor owns quote generation; overload
is refused, and cancellation does not spawn an unbounded replacement operation.
SNP custody explicitly rejects a TDX request on its SNP verification path.
The grant remains encrypted through the runner and is consumed by only its
intended guest incarnation.

The runner requires four distinct qualified workers: two SNP custody workers
and two TDX CDS workers. At most two test VMs run together, each with two vCPUs
and 4 GiB of memory. It enrolls custody, makes a protected copy on the second
chip, creates CDS state, destroys every source guest, and excludes both source
workers from recovery. Replacement guests must retain the same CA, reject a
still-valid spent token, preserve revocation, and use the original certificate
and secret after a new authorization. Both CDS phases need independently
verified TDX receipts; SNP-only success cannot satisfy this test.

This is still a correctness rehearsal. Three CDS processes share one TDX
guest. The metadata fixture is a single-host SQLite service, not replicated
HA. The object fixture measures protocol correctness, not provider latency.
One enrolled SNP chip and its sealed copy must survive. Recovery after losing
every enrolled chip, custody image retirement, production membership, migration
and a real HA metadata deployment remain separate work. An operator-controlled
rollback of the entire metadata database is outside the freshness contract.
Full acceptance and production readiness remain false.

Only owned expiring resources are created. Removal checks recorded UIDs, and
an independent read-only audit checks that VMs, Pods, claims, backing volumes,
Secrets and network policies are absent. No worker or shared cloud rollout is
changed. Raw quotes, collateral, launch bytes and private runner data are kept
outside the repository; the published result is an explicit summary.

Native TDX CDS execution is pending for frozen image source `87c4aff8`. Local native-harness
compilation, the direct-state HTTP/workload regression, custody race tests,
and all 36 runner checks passed. The first image build stopped because the
builder's symlink target was absent inside its dedicated container; the retry
mounts the verified same-source builder explicitly. The failed log is retained.

The [first native attempt](../test/pilot/cds-sealed-recovery/results/2026-11-05-tdx-current-recovery-attempt-01.json)
passed custody enrollment but stopped before booting CDS on TDX: a read of an
owned backing volume returned HTTP 500. Cleanup and an independent absence
audit passed for all 14 recorded paths. The runner now includes HTTP 500 in its
existing three-attempt retry for unchanged GET requests. Mutation, authorization
and validation failures retain their previous behavior. All 36 runner checks
pass, including bounded retries and no mutation retry. The failure is retained;
it is not counted as native TDX recovery evidence.
