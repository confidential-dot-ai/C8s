# Highly available CDS: operator notes

"Workload policy" below is what the API and CLI call the allowlist.

These notes cover running CDS as several replicas that share one mesh CA
(`launch-config new --cds-node`). Earlier workflows were run on TDX hardware. The format-3/authenticated-backup
changes below have local tests only; they are not a validated TDX rollout.

## Starting an HA cluster

HA CDS starts with a **fresh launch**. A cluster that runs a single CDS
(no `cdsHA` in its launch documents) does not convert in place. Create a new
bundle with `c8s node launch-config new --cds-node <name>` (repeat the flag:
an odd number, 3 to 9), launch every node, and apply the Genesis decree. Then move
workloads and re-apply the workload policy (`c8s allowlist apply`) and secrets.

## Compatibility boundary: format 3 and peer binding v2

This release reads and writes state format **3** (SQLite snapshot images).
Format 2 previously named incompatible JSON-row and SQLite encodings. Neither
format-2 variant is supported here. Old backups are refused, not migrated.
Peer binding v2 also differs from the earlier v1 certificate binding; changing
measurement pins does not make those protocols interoperable.

**Do not roll an existing format-2/v1 deployment (including v25 test clusters)
into this release.** Retain its exact old image and recovery tools with its old
backups. This boundary requires a clean deployment: a new CA and replicated
state, followed by deliberate workload, policy and secret migration. Clean
redeploy is not state preservation. A state-preserving bridge release and
old-backup compatibility have not been implemented or tested.

## Rolling CDS to a new image

The procedure below applies ONLY when both releases explicitly support the
same peer binding and overlapping state formats. It does not cross the above
boundary.

1. Sign and apply an `UpdateMeasurements` decree that pins both images
   (`c8s cds ha decree --image <old> --image <new>`). Nodes and pods follow
   it. No node is relaunched for this.
2. Replace the cds nodes one at a time, the leader last. Each replacement
   gets a **new name** (`c8s node launch-config add-cds-node --image-manifest
   <new manifest.json>`). Wait until the new replica serves before you remove
   the old node.
3. Sign and apply a decree that pins only the new image.
4. Remove the old image's workload policy entries. They stay until you do.

When the new release reads a newer state format, the cluster changes format
by itself. That happens when every seat is filled by a replica that reads the
new format, so during the rollout the old format stays in force.

The router, `get-cert`, the injected sidecars and `allowlist-proxy` follow the
decrees through the node's enforcer.

## Application policy and read freshness

Genesis records application policy version 1 in the replicated Core: the exact
sandbox binding TTL and capacity, and the secret path, per-holder and value
limits. These values are immutable for that cluster. Every joining replica
must use identical effective values. Missing, unknown or different policy is
refused before membership or snapshot state changes. Recovery uses the same
policy as live application, including refused logged commands. Policy version
is separate from snapshot format. The format-3 release requires a clean
redeploy; it does not infer policy for old clusters or support format-2 restore
or rolling conversion.

Local authorization reads are **bounded stale, not linearizable**. Each replica
periodically asks the leader for a Raft barrier, then waits until its own FSM
has applied the returned watermark. The read certificate expires one Lease
(default five seconds) after the request **started**. Heartbeats alone never
renew it. A changed Raft instance, leader, term or decree epoch invalidates it.
HTTP admission, CA access and readiness check this evidence locally. Ordinary
GET requests do not append log entries. Explicit CatchUp calls force a barrier.
At a Lease/3 refresh interval the default cost is at most about 0.6 barrier
entries per replica per second, plus explicit CatchUp calls; test settings with
a one-second Lease use about three per replica per second. If application or
quorum confirmation stalls, replicas stop admitting reads when evidence expires.
This is an admission-time guarantee, not an atomic transaction around an entire
HTTP handler that was already admitted.

Genesis fallback fails closed on discovery errors and unreachable discovered
peers, and never replaces locally known cluster state. A successful **empty**
discovery result still permits the explicitly signed initial Genesis. Stateless
reboots cannot distinguish a true first launch from replay of a still-valid
Genesis when discovery hides all existing members. Complete prevention needs a
trusted one-time boot generation or new operator authorization; this change
does not claim to provide that marker.

## Checking the replicas

    c8s cds ha status --image-policy-file server.json https://<node-1>:30808 https://<node-2>:30808 ...

`status` reads `GET /ha/status` from each replica over armTLS, with the same
connection flags as the other `c8s cds` commands. It prints each replica's
role, epoch, mesh CA and applied index, and fails when a replica cannot be
reached, is not serving, or disagrees on the epoch or mesh CA. A status is the
replica's own report; `c8s cds ha decrees` gives the agreed decree record.

## The mesh CA certificate

The replicas share one mesh CA key for the life of the cluster. Past half the
certificate's lifetime (`--ca-cert-validity`, one year by default), the leader
renews the certificate under the same key through the log, so every replica
serves the same new certificate and running workloads keep their trust anchor.
Replacing the key itself is the `RotateKey` decree, a break-glass step.

## Rebooting nodes

* A rebooted cds or agent node rejoins under its own name. A rebooted voter
  loses its state and comes back as a new member. The cluster gives its seat
  to another replica.
* **A server-node reboot starts a new, empty cluster.** The server keeps
  all cluster state on the per-boot encrypted scratch disk (see
  operator.md, "Revocation is a launch-time decision"). That includes the CDS
  backups, because they are ConfigMaps in the same etcd. Surviving the loss
  of the control plane is the job of server HA, which is tracked separately.
  Until then, a backup you exported earlier (below) is the way back.

## Backups

The leader seals the state to the recovery key and stores it at most once a
minute. Writes made after the last backup are lost
in a total loss, so the window is up to one interval.

**Export the backup off the cluster on a schedule.** The backup is sealed to
the recovery key, so you can store the export anywhere:

    kubectl get configmaps -n c8s-cds-decrees \
      -l c8s.confidential.ai/cds-backup=<cluster-id> -o json > cds-backup-$(date +%s).json

Retain the CA fingerprint and epoch/index independently from attested live
status, as described below. A manifest alone is not a trusted recovery record.
Recovery refuses a backup older than the `--min-epoch`/`--min-index` you give it.
The backup index and `--min-index` are application state watermarks, as reported
by attested status `applied_index`. They include applied commands and membership
configurations, not read-only Raft barriers. Raft's internal last-log and snapshot
positions are separate and must not be used as recovery floors. A floor above
the authenticated state index is refused even if a later barrier exists; the
CLI never lowers or translates the supplied floor.

## Splitting the recovery key

    c8s cds ha recovery-key split --recovery-key recovery.key --out shares --shares 5 --threshold 3

Give each `share-N.json` to a different custodian, then destroy
`recovery.key`.

## Recovering from a total loss

Use this when every replica lost its state:

    c8s cds ha recover --url <cds url> --image-policy-file server.json --operator-key server.key \
      --backup-file cds-backup.json --cluster-id <id> --bootstrap-node <a fresh cds node> \
      --decree-key decree.key --trusted-ca-sha256 <recorded-CA-fingerprint> --min-epoch <E> --min-index <I> \
      --recovery-key-share share-1.json --recovery-key-share share-3.json --recovery-key-share share-4.json

Fewer shares than the threshold are refused. The restored cluster keeps its
mesh CA, secrets, workload policy and decree record, and the other replicas join it.
If an attempt's answer times out while the replica restores, `recover` checks
the decree record and reports success when its own Restore is there.

### Restore and peer resource limits

Pre-join `/ha/restore` accepts one restore request at a time per process
(concurrent requests get HTTP 429). Upload reads have a 30-second deadline.
Legacy JSON requests without `X-CDS-Restore-Decree` are limited to 1 MiB of
wire data. For larger restores, use the updated `c8s cds ha recover` client:
it sends the signed decree as JSON in this header before the unchanged JSON
body. The server authenticates the decree and checks local restore eligibility
before reading a large body. The header is limited to 16 KiB; pre-join total
HTTP headers are limited to 20 KiB (plus net/http's fixed parsing allowance).
Authenticated JSON bodies are limited to 256 MiB including base64 encoding.
The body decree must match the header and the decoded snapshot must match its
signed SHA-256. These bounds apply even to replayed valid decrees. Old clients
must upgrade or send the header to restore backups above the legacy cap.
Snapshot decoded-size and compressed-size limits apply separately.

The peer mux admits at most 64 inbound sockets, including TLS handshakes,
control requests and Raft streams. Excess sockets close immediately. TLS and
Raft target framing share a 10-second deadline; control I/O has a 30-second
deadline. Mux shutdown closes all accepted sockets, including incomplete
handshakes and stalled target reads. These are availability bounds, not a
substitute for peer attestation or network policy.

## Backup provenance and recovery limits

HPKE Base encryption protects confidentiality, not sender identity. Anyone with
its public key can encrypt replacement state. New backups therefore carry an
ECDSA source signature from the snapshot's mesh CA. It covers a versioned,
domain-separated typed JSON message containing all backup metadata and SHA-256
of the exact ciphertext (including its HPKE encapsulated key). The CLI verifies
that signature against an **independently retained CA certificate fingerprint**
before decrypting, checking inner metadata/floors, or signing a Restore decree.
There is no unsigned-backup fallback.

Before loss:
1. Use `c8s cds ha status --image-policy-file server.json https://<node>:30808`
   over the attested channel. Retain the full 64-hex-character `ca=` value, cluster identity,
   epoch and applied index in an access-controlled offline recovery record.
   Do not use `--insecure` in this workflow.
2. Retain the CA pin for each backup generation you keep. CA certificate renewal
   changes its certificate fingerprint even if the key stays the same. Record
   the new fingerprint through the attested channel after renewal. Keep old pins
   with old backups. A key rotation likewise requires a new trusted record.
3. Export backup ConfigMaps as before. Export contents and displayed metadata
   are not trusted records. Never copy the expected pin from that export.

On total loss add `--trusted-ca-sha256 <recorded-full-64-hex-CA-fingerprint>`
to `c8s cds ha recover --backup-file backup.json ... --min-epoch <recorded-epoch>
--min-index <recorded-index>`. Select the independently recorded pin for that
backup. If no trusted pin was retained, stop: this CLI cannot authenticate the
backup and provides no trust-on-first-use bypass. Historical certificate expiry
alone does not reject recovery: a retained pin and valid signature authenticate
historical state; deciding to restore it remains an operator action. This is
not live TLS certificate validation.

Supported snapshot limits are 128 MiB compressed, 16 MiB JSON header (including
its newline), and 256 MiB SQLite image. Both snapshot creation and decoding
reject larger state. The limits are operational budgets, not guarantees that
all machines have enough memory: restoring SQLite and stores holds several
copies, and concurrent operations add memory. Size the instance accordingly
and prune retained history before reaching these limits. Size limits do not
make arbitrary SQLite images trusted. Source certificates are limited to 16 KiB
and signatures to 1 KiB before signature verification.

PeerBinding v2 checks certificate expiry at the handshake. Renewal and expiry do
not terminate established streams. Current-image pin removals cut tracked peer
streams on epoch recheck; final admission is serialized against the sweep. This
release does not add hard stream lifetime timers. Shared challenge redemption
also checks the current key and signed TTL at the issuer; a missing key fails
closed. Single-use tracking remains per replica. Use distinct operator keys
per cluster (see `docs/operator.md`).

## Route backend anchors after rotation

CDS checks address-backend anchors against its current mesh CA on each signed
route write, including after HA RotateKey without a process restart. Missing
current CA fails closed. Singleton CDS uses the same live CA provider interface.
A retired CA that CDS no longer trusts is not permanently banned as a backend
anchor; this matches behavior after restart. Routers independently reject every
mesh CA in their current trusted bundle, which can still include an older
generation. Do not reuse retired mesh keys for backend services as an operational
practice; CDS does not retain an unbounded historical exclusion list.
