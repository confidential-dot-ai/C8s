# CDS with encrypted object state

This backend runs replaceable CDS processes against one encrypted current-state
object per cluster. It uses the existing CDS request handlers and S3 conditional
writes. It runs no CDS election, peer quorum, application WAL or consensus
protocol. The existing singleton and Raft modes remain available in the same
binary; selecting `objectState` does not start them.

This implementation is a candidate for production qualification. Local tests
exercise the request and custody protocols. Opt-in tests also exercise live S3
semantics and session permissions. These do not qualify a custody deployment,
native SNP/TDX recovery, or a migration of an existing cluster.

## State and requests

The object contains the CA certificate and private key, allowlist, routes,
canonical spent operator tokens, secret values, sandbox bindings, and outstanding
issuance and secret challenges. XChaCha20-Poly1305 encrypts the complete state and binds
it to the cluster and exact storage authority. A fresh encryption nonce on every
replacement prevents identical state from reusing a previous ciphertext ETag.
Its 192-bit random nonces let independent writers share a durable key without
coordinating a nonce counter; failed conditional writes also use fresh nonces.

Each admitted request performs:

1. A current, strongly consistent object read and authenticated decryption.
2. Construction of private, in-memory stores and handler caches.
3. Execution of the actual CDS handler with buffered output and success logs.
4. If state changed, a conditional replacement against the exact read ETag.
5. Publication of the response and success logs only after confirmed commitment.

Read-only requests linearize at the object read. Mutating requests linearize at
the successful conditional replacement. Rejections that consume a token or
challenge also commit that consumption. A secret response or issued certificate
stays inside the process until its challenge consumption commits.

Every request with a client certificate verifies it against the current CA,
including requests on an established TLS connection. Maintenance refreshes the
TLS root immediately and every 15 minutes even when a replica is idle. The CA
certificate renews under the same private key; its renewal is an ordinary state
replacement.

Conflicts return HTTP 409 with `X-C8s-Commit-Outcome: not-committed`. The caller
must reread and revalidate its operation. CDS does not automatically execute a
handler again: pod secret release can contact an external KMS. A lost storage
acknowledgment returns HTTP 503 with `X-C8s-Commit-Outcome: unknown` and releases
no buffered secret. The authorization may have been consumed. There is no durable
response receipt or exactly-once response-delivery promise.

S3 mutations have no SDK retries. A retry after a lost successful response could
return 412 and incorrectly make a committed operation appear uncommitted.
The transport treats a single-attempt 412 or S3's explicit
`409 ConditionalRequestConflict` as a rejected write. Unclassified or undecodable
409 responses, timeouts and lost acknowledgments retain an unknown outcome.
Missing or unreadable current state fails closed; serving replicas never create
a replacement CA because an object disappeared.

## Admission and limits

Each CDS process serves one measured cluster. A dispatcher owns a bounded queue;
workers own their private request state. Different clusters use separate
processes and objects. There is no process-wide mutable CDS state protected by a
global request lock. Existing store-local locks operate only within a private
view; Go channels and the underlying libraries are not claimed to be formally
lock-free.

The measured defaults are four workers, 64 queued requests and a 16 MiB encrypted
state limit. Excess requests return 503 with `Retry-After: 1`. Each request has a
30-second overall deadline, including queueing; S3 calls have a 10-second limit.
Shutdown cancels admitted work and waits for workers before releasing their data.

Each challenge purpose retains at most 8,192 outstanding random nonces. Once
consumption or pruning durably removes a nonce, moving a clock backwards cannot
resurrect it. Expiry checks still depend on the guest clock; this backend does
not establish trusted elapsed time for an outstanding nonce. Spent operator
tokens use the existing canonical signed-token
identity and signed-time pruning floor. Policy history retains at least 32
entries and every older entry still needed for delayed activation. State that
cannot fit is refused; live authorization records are never evicted for space.

The current codec reconstructs SQLite in memory and serializes the complete
state on a mutation. A single hot cluster still serializes writes on one object.
This version does not claim higher throughput or lower latency than Raft.
Measure independent clusters, join/renewal bursts, and contended policy updates
before choosing instance sizes or adding batching.

`/healthz` and `/metrics` remain independent of storage. `/readyz` requires a
fresh readable state, healthy attestation API and sufficient CA validity.
Metrics include `c8s_cds_object_requests_total`, `commits_total`,
`conflicts_total`, `unknown_total`, `busy_total`, `queued` and `inflight`, each
with the `c8s_cds_object_` prefix. The committed-state log and final HTTP request
status describe durable outcomes; success logs are deferred until commitment.

## Measured configuration

Prepare a standalone object settings file, for example:

```yaml
bucket: YOUR_DEDICATED_BUCKET
key: clusters/YOUR_CLUSTER/current
region: us-east-2
expectedBucketOwner: "YOUR_12_DIGIT_PROJECT_ID"
recoveryAuthority: YOUR_BASE64_ED25519_PUBLIC_KEY
snpMinTCB:
  bootloader: 12
  tee: 0
  snp: 28
  microcode: 28
maxBytes: 16777216
workers: 4
queueCapacity: 64
```

Pass it to the existing generator with `c8s cds config new
--object-state-file object-state.yaml` and the other required cluster, node-pin
and image-manifest arguments. The generator embeds an `objectState` block and
generates a launch pin covering it. An optional `endpoint` must be an HTTPS
origin. `ha` and `objectState` are mutually exclusive. Credentials and encryption
keys are forbidden in this public launch document.

The `snpMinTCB` values above illustrate a firmware floor; choose values approved
for the actual SNP hardware before generating the measured launch. All four
components are required, including an explicit zero where appropriate, and the
combined floor must be nonzero. This peer-verification floor is independent of
the custodian's fixed hardware-key derivation TCB. Raising one must not silently
change the other.

Running the generated configuration selects this backend before opening legacy
stores or creating a local CA. Object mode requires no `--allowlist-db` and
refuses `--allowlist-persistent`. Runtime storage credentials arrive through
signed, encrypted grants to the approved guest. There is no ambient credential
provider or host identity fallback. Region, bucket, object, endpoint and expected
owner come exclusively from measured configuration.

## Recovery and custody

Before serving cluster routes, CDS exposes its self-attested armTLS listener
with three recovery endpoints:

- `GET /object-state/recovery/request`: public ephemeral recipient and exact
  cluster, storage and measured-launch bindings.
- `POST /object-state/recovery/grant`: a bounded, signed encrypted state-key
  grant sealed to that recipient; no plaintext key is accepted.
- `POST /object-state/recovery/credentials`: a separately signed and encrypted
  temporary storage session, bound to that same recipient.

A replica only recovers an existing authenticated state object. Missing,
corrupt or unreadable state fails closed. Replica startup, key grants and
credential renewal cannot initialize state or generate a replacement CA.

The `c8s cds custody serve` service owns one cluster's recovery authority inside
an independently approved SNP guest. Its measured `c8s-cds-custody/v1` document
contains a CDS configuration template, fixed SNP and/or TDX CDS image pins, an
independent owner's public client CA, and fixed SNP derivation parameters. TDX
image pins contain MRTD and RTMR1/2; the completed launch supplies the RTMR3
binding, so it must not be pinned in the original custody document. The CDS template contains the recovery-authority placeholder
`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=` exactly once. The custodian
replaces it with its derived public authority in a separate CDS launch document;
it always boots the original custody document.

The custodian derives the state encryption key and authority signing seed from
SNP hardware with separate HKDF domains. The root is bound to the chip, guest
policy, image identity, measurement, fixed guest SVN and fixed firmware TCB;
the original custody document also binds the derived keys. Derivation requires
a non-debug, non-migratable VMPL0 report matching that original document.
The approved boot chain must measure the actual executable and prevent
host-selected code. Generic firmware measurement plus HOST_DATA is insufficient.
See the [custody image build instructions](../images/cds-guest/README.md).

This root supports restart on the same chip with the same image, original
configuration and derivation parameters. It does not yet provide recovery after
losing that chip, transfer to a new custody image, or TDX-based root derivation.
SNP custody can release to approved SNP and TDX CDS replicas. Fixed parameters
must not silently follow a firmware upgrade. Changing the owner CA, image
approval, original configuration or selected derivation parameters changes the
root and needs a protected transition that is not implemented. Owner CA expiry
therefore bounds this fixed configuration's usable lifetime.

Object-mode startup, recovery, issuance and inventory verification use the same
local native verifier. The attestation API supplies evidence and health; its
remote verification response does not authorize an object-mode peer. Native SNP
requires the measured floor for reported, current and launch firmware TCBs,
plus fresh signed revocation data. Native
TDX requires fresh authenticated collateral and `UpToDate` platform, module and
quoting-enclave status. Missing, future-dated or expired collateral fails closed.
These validity windows use the verifier's wall clock; they do not establish a
hardware-trusted clock or prove that the collateral is the latest publication.

Guests must also forbid debug and migration. Image pins alone do not establish
these properties: SNP `MIGRATE_MA` and TDX `TD_ATTRIBUTES.MIGRATABLE` are checked
separately, including after a pin refresh. Missing or malformed policy claims
fail closed. The current verifier supports VCEK SNP on the qualified processor
generations; VLEK and Turin/FMC evidence remain rejected pending verifier
qualification. TDX collateral profiles that the pinned SDK cannot fully
validate are rejected. These restrictions apply to the object backend; they do
not silently change legacy attestation behavior.

The owner uses mutual TLS and freshly verifies the custodian's native SNP
measurement, launch document, minimum TCB and revocation collateral. Its identity
is independent of the CDS CA being recovered. The following owner commands use
`--url`, `--config`, `--custody-pins`, `--client-cert` and `--client-key`:

1. `c8s cds custody launch --output CDS_CONFIG` obtains the public completed
   launch. Pin these exact bytes for subsequent operations and CDS boots.
2. `c8s cds custody initialize --cds-config CDS_CONFIG --aws-profile OWNER_PROFILE
   --role-arn DEDICATED_ROLE` is an explicit **new-cluster** operation. It uses a
   create-only session and confirms the current object's CA after conditional
   creation, including after a lost acknowledgment. It returns no key. It is
   never part of restart or credential renewal.
3. `c8s cds custody provision --cds-config CDS_CONFIG --aws-profile OWNER_PROFILE
   --role-arn DEDICATED_ROLE --replica HTTPS_ORIGIN --renew` provisions approved
   replicas and renews their sessions. Repeat `--replica` for up to 16 origins.
   The owner verifies the pinned completed launch before issuing credentials.

The owner CLI issues 15-minute AWS sessions, renews after five minutes with
jitter, and retries renewal failures with bounded backoff. Initialization is a
single attempt; an unknown result requires inspection before explicitly
repeating that new-cluster operation. Credential values are sent only inside
attested TLS and are not printed or persisted by the CLI. This owner process,
its client identity and its AWS authority must be controlled independently from
the infrastructure operator.

The custodian freshly reads, decrypts and validates the same current object CDS
serves before ordinary provisioning. For each grant it reads authenticated
policy, fetches the recipient over freshly verified armTLS, checks its exact
launch and image, and rereads policy before sealing. An incarnation-specific
X-Wing recipient and pinned Ed25519 signature bind the grant. A bounded control
actor owns each provisioning job and its results, with admission before body
reading. At most 16 bounded replica attempts run concurrently, so an unavailable
replica cannot consume a healthy replica's renewal budget. Partial failures
report each requested replica's readiness. No enrollment object, peer election or recovery log is involved.

Credential renewal retains the original recipient and uses distinct signature
and encryption domains. It carries no state key. The replica's bounded control
actor admits two grant requests and installs immutable credential snapshots.
Different credentials must advance the expiration floor, which survives expiry.
An identical still-valid session may be resealed and redelivered. An exact retry
of the latest encrypted grant can acknowledge its previous installation without
extending validity; HTTP 204 alone does not prove a fresh session.

Credentials may arrive before or after the one-shot state-key grant. A refresh
can retry an unfinished read of existing state. Every S3 request consults the
current provider, so an outer SDK cache cannot hide a replacement session.
Expired credentials fail closed; AWS checks expiry independently of the guest
clock. Grants accept at most one hour of remaining validity.

The AWS owner issuer gives all three session types `s3:GetObject` on the exact
object and `s3:ListBucket` with `s3:prefix` equal to its key. The latter permits
S3's missing-object 404 instead of an ambiguous 403. Reader sessions cannot
write; initializer sessions require `s3:if-none-match`, and replica writer
sessions require `s3:if-match`. Both writes target only the exact object. Session
policies also constrain the project and selected Region. They grant no delete,
version-read or bucket/role administration permissions. The prefix condition
can reveal names starting with the key string; it is not exact-name filtering.

Storage ordering is a trust boundary. The infrastructure operator must not
write or delete the current object, obtain guest writer credentials, alter
storage policy, or restore older state. Even a conditional write can replace
current state with older authentic ciphertext. Encryption cannot detect that
after total replica loss. Current state must not be expired by lifecycle rules;
explicit initialization is not recovery from its deletion. S3 strong consistency
and conditional writes are provider contracts, not proof that provider internals
contain no consensus protocol. Existing pod KMS is not this bootstrap authority:
its broker depends on the CA that recovery must restore.

## Upgrade and release boundaries

Recovery checks the exact measured launch configuration and state format.
Replacing a CDS binary while keeping that configuration and format is supported
when the custodian and client bootstrap pins already approve the replacement.
Changing node pins, operator keys, admission settings or storage configuration
requires a separately designed authenticated transition. Legacy Raft pin,
membership, CA-rotation and recovery decrees do not apply to this mode. An
unknown state format fails closed; there is no automatic downgrade or migration.

The existing secret-release authorization rules remain in effect. `/secrets`
checks the current CDS allowlist; `/pod-secrets` delegates its release policy to
the external KMS. The latter's final CAS fences concurrent state changes but
does not replace the KMS's revocation checks. Independent owner-signed
secret-release policy is a separate feature; storage HA does not
prevent an operator authorized by those existing rules from authorizing a
workload. Already released secrets and already provisioned CA keys cannot be
recalled by changing a release policy.

Before enabling this mode for an existing production cluster, qualification must
cover live storage conditional-operation semantics and permissions, independent
durable custody, native SNP and TDX total-replica-loss recovery, rolling binary
upgrades, and a fenced migration preserving the existing CA and replay state.
No migration or production rollout is performed by this change.

## Live S3 acceptance

`TestObjectS3Acceptance` runs three separate CDS test processes against a fresh
object in an existing dedicated test bucket. It uses the actual request handlers,
encrypted state codec and S3 transport. Inventory and attestation are synthetic;
the processes communicate over ordinary TLS. Native attested bootstrap and
protected custody require their own qualification.

Use an authenticated AWS profile with permission to inspect the bucket, assume a
dedicated writer role, and remove versions of the newly created test object. The
writer role needs `s3:GetObject` and `s3:PutObject` on the test prefix, and
`s3:ListBucket` so the runner can grant an exact-key prefix condition. The
runner restricts each temporary writer session to its object and that prefix and
delivers credentials to child processes over an anonymous pipe. Cleanup uses the
parent identity. The bucket must have no Object Lock configuration, and MFA
Delete must be disabled so automated cleanup can remove test versions.

Set the following values for your dedicated test resources:

```sh
export AWS_PROFILE=YOUR_TEST_PROFILE
export AWS_REGION=us-east-2
export C8S_OBJECT_S3_RUN=1
export C8S_OBJECT_S3_BUCKET=YOUR_DEDICATED_TEST_BUCKET
export C8S_OBJECT_S3_PREFIX=runs/YOUR_UNIQUE_TEST_RUN/
export C8S_OBJECT_S3_OWNER=YOUR_12_DIGIT_PROJECT_ID
export C8S_OBJECT_S3_WRITER_ROLE=YOUR_TEST_WRITER_ROLE_ARN
go test -race -count=1 -timeout=10m -run '^TestObjectS3Acceptance$' -v ./internal/cmds/cds
```

The test checks concurrent policy reads and writes with Porcupine, response
suppression after a committed write loses its acknowledgment, and revocation
while a secret release is paused before commitment. It kills and waits for all
three processes before starting replacements, then checks the original CA,
replay rejection and retained revocation. Ambiguous writes are tested separately
from the strict concurrent register history. Child race reports and unexpected
exits fail the parent test, including failures detected during process cleanup.

The runner logs its random object key and removes only that object's versions
and delete markers. It verifies absence after cleanup. The existing bucket,
writer role and other objects are retained. A failed cleanup fails the test;
use the recorded key for a subsequent cleanup attempt.

`TestObjectS3CustodyCapabilities` uses the same opt-in environment to check the
actual reader, initializer and writer session policies against disposable
objects. It checks conditional-create/replace separation, unconditional-write
rejection, and denied deletion, version reads and unscoped listing. It cleans
its exact object versions and leaves the existing bucket and role unchanged.

`TestObjectAcceptanceProcessHarness` checks subprocess startup, ordinary TLS and
termination locally without AWS. The live test requires explicit opt-in and is
skipped during an ordinary local test run. Run it directly from a trusted
execution environment; fixture keys and writer credentials must stay out of
command arguments, test output and committed artifacts.

## Native recovery acceptance

`TestObjectNativeWorkloadGuest` is a gated entrypoint in a separately measured
test binary, built with the `native-workload` image variant. It is excluded
from the production CDS command. Its fixed inventory qualifies the CDS
issuance and secret-release paths, not production NRI or Kubernetes isolation.
The [image instructions](../images/cds-guest/README.md) describe the build inputs.

The guest accepts one owner-authenticated configuration binding three original
and three replacement origins, the exact completed CDS launch, native image
pins, and its inventory address within that launch's node range. It obtains an
actual CDS-signed leaf using native evidence, keeps its private key and random
target/control secret values in guest memory, and returns only public checks.
Its bounded prepare, arm and verify phases retain their receipts; retrying a
phase cannot regenerate proof material.

The owner runner must independently verify distinct VM and recipient identities,
replacement unreadiness before grants, and termination of every original before
recovery. Remove only the target path's read grant while retaining the control
grant. After recovery, the fixture checks the original leaf's control value and
revoked-target refusal before any successful new issuance can recreate sandbox
bindings. It then tests both replay pools using older unused challenges as
positive controls. Exceeding the unchanged challenge lifetime makes the run
inconclusive, not successful replay rejection. Operator-token replay and its
unused valid control are separate owner-run assertions; a successful policy
write must follow these guest checks so it cannot repair missing revocation.

Ordinary local tests skip this hardware entrypoint. Native evidence, exact
artifact/source hashes, VM identities, timing and owned-resource cleanup must
be recorded for a qualifying live run. Same-chip custodian restart and loss of
all CDS replicas do not establish recovery after losing the custody chip.

## Architectural references

The [Turbopuffer object-storage queue](https://turbopuffer.com/blog/object-storage-queue)
motivates replaceable processes and conditional replacement of durable object
state. Its indexing notifications have at-least-once delivery; CDS additionally
commits security state before releasing responses. This implementation does not
adopt the separate search database's application WAL.

The S3 transport follows [conditional write semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
the [PutObject conditional-conflict contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html),
and the AWS SDK's [explicit no-retry option](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-retries-timeouts.html).
