# Highly available CDS: operator notes

"Workload policy" below is what the API and CLI call the allowlist.

These notes cover running CDS as several replicas that share one mesh CA
(`launch-config new --cds-node`).

This file explains how HA CDS behaves. The operational procedures are in
`cds-ha-runbooks.md`, the alarms in `cds-ha-alerts.md`, and the known limits
in [Known limitations](#known-limitations).

## Starting an HA cluster

HA CDS starts with a **fresh launch**. A cluster that runs a single CDS
(no `cdsHA` in its launch documents) does not convert in place.

1. Create a new bundle with `c8s node launch-config new --cds-node <name>`
   (repeat the flag: an odd number, 3 to 9) and launch every node.
2. Start the cluster with a Genesis decree: runbook 1 in
   `cds-ha-runbooks.md`.

What Genesis relies on:

- The decree names one replica process. `c8s cds ha status` shows its member
  ID as `id=` (`<node>/<ms>-<random>`). The replica mints it from `crypto/rand`
  inside the TD at every start and never stores it.
- `c8s cds ha decree --target-url` reads the member ID over armTLS (the
  `--target-*` flags are the usual connection flags) and signs it into the
  decree (`target_member`). It refuses a replica that already holds a cluster
  or runs on another node than `--bootstrap-node` (default: the target's
  node). It never takes a member ID from anything but the verified replica.
- The replica starts the cluster only when peer discovery shows at least one
  other replica and every replica it finds answers that it holds no cluster.
  The other replicas join. A one-replica cluster needs `--alone` on the
  decree; do not use it when there are more replicas.
- If the bootstrap replica restarts before it applies the decree, the decree
  is dead (its member ID is gone): read the ID again and sign a new one.

Then move workloads and re-apply the workload policy (`c8s allowlist apply`)
and secrets.

## Compatibility boundary: format 4 and peer binding v2

This release reads and writes state format **4** (SQLite snapshot images; the
replicated state records, per epoch, the index it was made from, and the
one-shot decrees carry `target_member`). Formats 2 and 3 are not supported
here. Old backups (sealed as `c8s-cds-ha-backup-v2`) are refused, not
migrated. Genesis, Recover and Restore decrees signed without `target_member`
are refused with an error that names the missing field: re-sign them.
Peer binding v2 also differs from the earlier v1 certificate binding; changing
measurement pins does not make those protocols interoperable.

**Do not roll an existing format-2/v1 deployment into this release.** Retain
its exact old image and recovery tools with its old backups. This boundary
requires a clean deployment: a new CA and replicated state, followed by
deliberate workload, policy and secret migration. Clean redeploy is not state
preservation. A state-preserving bridge release and
old-backup compatibility have not been implemented or tested.

## Rolling CDS to a new image

The procedure applies ONLY when both releases explicitly support the
same peer binding and overlapping state formats. It does not cross the above
boundary. The step-by-step version, with the readiness gate, is runbook 3 in
`cds-ha-runbooks.md`. In short:

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
peers, and never replaces locally known cluster state. An **empty** discovery
result also blocks it, unless the decree says `alone`. Genesis, Recover and
Restore decrees name the member ID of one replica process (`target_member`),
and only that process acts on them. A restarted replica has a new member ID,
so a recorded decree cannot be replayed to it, whatever the decree objects in
Kubernetes or the guest clock say. `expires_at` only bounds how long a
decree waits; it is not the replay protection.

## Reaching the replicas

Two NodePort Services lead to the replicas:

* `c8s-cds` (`cds.service.nodePort`, 30808) is for clients. It carries only
  Ready replicas, and a replica is Ready only while it serves. Any node's
  address may answer from any serving replica.
* `c8s-cds-replicas` (`cds.ha.replicaNodePort`, 30809) is for the operator.
  `https://<node>:30809` answers from the replica on that node only, whether
  it serves or not. Use it for replicas that do not serve: a fresh replica
  awaiting a Restore, or a Recover survivor without a majority.

A replica that has not joined is never Ready. One that has heard of no
cluster for a while shows `awaiting_restore: true` in `/ha/status`. A
replica that is only cut off from the others shows the same, so this is a
hint, not proof of a total loss.

## Checking the replicas

    c8s cds ha status --image-policy-file server.json https://<node-1>:30809 https://<node-2>:30809 ...

`status` reads `GET /ha/status` from each replica over armTLS, with the same
connection flags as the other `c8s cds` commands. It prints each replica's
member ID (`id=`), role, epoch, mesh CA and applied index, and fails when a replica cannot be
reached, is not serving, or disagrees on the epoch or mesh CA. A status is the
replica's own report; `c8s cds ha decrees` gives the agreed decree record.

## Replica divergence

Every replica keeps two digests of what it applied. They are reported in
`/ha/status`:

- `chain`: a rolling SHA-256 over every command it applied.
- `checkpoint`: its state digest at the latest checkpoint. A checkpoint is an
  empty log entry that the leader proposes every 10 s while the state changes.

The state digest covers Core, the mesh CA key, the decree record, and a
multiset hash of every allowlist row, secret and sandbox binding. Each store
keeps that hash up to date as it writes. Replicas that agree report the same
`checkpoint` at the same index. A backup's metadata carries the same value as
`state_digest`, so you can compare a backup with the live cluster.

The leader compares the replicas at each checkpoint.

- **A replica that differs from a majority of the voters is stopped.** This
  covers a follower that applied an entry the cluster never committed
  (hashicorp/raft #695), and a replica whose stored state changed under it. The
  stopped replica stops serving, exits, and on restart takes the leader's state.
  The leader's own `status` shows `divergence: stopped diverged replicas: …`.
- **A leader that differs from a majority of the other voters stops itself.**
  It hands off leadership, snapshots nothing, and exits. A single follower can
  never cause this; with 3 voters it takes both followers.
- **Local check at every snapshot.** Each replica recomputes the digests from
  the snapshot it is about to ship (to a joining replica or into a backup). If
  the state no longer matches what it applied, it refuses the snapshot and
  stops. Every restore (InstallSnapshot, `Restore`, and the CLI's backup check)
  refuses a snapshot whose content does not match its digests.

Each event logs one ERROR line per episode, starting
`cds-ha: replica divergence:`. The line names the checkpoint index, each member
ID with its `chain/state`, and how many voters agree.

**`divergence: no majority: …`.** No majority holds one state. For
example, one voter is down and the other two differ, or there is a three-way
split. Nothing is stopped automatically, because no side can be proven right.
**Backups pause** until the alarm clears. What to do: runbook 7 in
`cds-ha-runbooks.md`.

Snapshots and backups written before format 4 carry no digests. This release
refuses them.

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

**Watch backups.** The leader's `/ha/status` reports `last_backup`
(`index`, `epoch`, `at_ms`, `age_ms`) and, while backups fail for any reason,
`backup_error` (stage, cause, attempts, since when). The leader logs an error
once 3 attempts in a row failed or failures lasted 3 backup intervals. Alert on
`backup_error`, or on `age_ms` well past the interval while writes happen.
There is one backup slot, in the cluster's own Kubernetes; the export below is
the only second copy.

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

### Which backup the slot keeps

There is one backup slot per cluster (`cds-backup-<cluster-id>`). A new
backup replaces the stored one only if it continues the stored backup's
history: it holds the same decrees first, and it is at a later index of that
epoch, or in a later epoch made from the stored state or a later one. So a
second cluster (another Genesis), a restore of an older backup, or a Recover
side that lacks writes the stored backup holds cannot overwrite the live
cluster's backup. Its backups are refused, and the leader's `/ha/status`
shows `backup refused: ...` in `backup_error` until a backup is stored again.

## A replica that cannot apply a log entry

A replica whose own store fails (disk full, I/O error) stops serving and exits;
its restart rejoins with the cluster's state. Any other entry it cannot apply
(an unknown or malformed entry, a newer format, a panic while applying) would
fail the same way on every replica of the image. Such a replica does **not**
exit, because the log lives only in memory: it serves nothing, refuses writes,
keeps its log, logs `ALARM` every minute, and `/ha/status` shows `stuck` with
`stuck_local` false. If every replica halts, the cluster keeps a leader and its
membership but serves nothing. There are two ways out: roll an image that
applies the entry (no loss), or restart every replica and restore the last
backup (loses the tail). The steps are runbook 6 in `cds-ha-runbooks.md`.

If the cluster's serving leader is past the entry (only this replica fails,
for example an older image), the replica exits so its restart rejoins, as long
as the voters that follow the log keep a majority without it.

## Splitting the recovery key

    c8s cds ha recovery-key split --recovery-key recovery.key --out shares --shares 5 --threshold 3

Give each `share-N.json` to a different custodian, then destroy
`recovery.key`.

## Recovering from a total loss

Use this when every replica lost its state. The steps are runbook 5 in
`cds-ha-runbooks.md`. No replica is Ready then, so the restore goes to the
bootstrap node's own address on `c8s-cds-replicas` (:30809).

`recover` checks the backup, then on each attempt opens an armTLS
connection, reads that replica's `/ha/status`, and goes on only if it runs on
`--bootstrap-node` and holds no cluster. It signs the Restore decree for that
process's member ID (`target_member`) and sends it with the snapshot on the
same connection (every request of one connection goes to the one attested
replica it verified). Another replica, or the same one after a restart,
refuses the decree (HTTP 421) and `recover` tries again with a fresh ID.
The other replicas then join the restored one. Policy, revocations and secrets
written after the backup are not in it.

Fewer shares than the threshold are refused. The restored cluster keeps its
mesh CA, secrets, workload policy and decree record, and the other replicas join it.
If an attempt's answer times out while the replica restores, `recover` checks
the decree record and reports success when its own Restore is there.

### Restoring an older backup on purpose (rollback)

Restoring a backup older than the one in the slot is a rollback: the restored
cluster does not continue the stored backup's history, so its backups are
refused (`backup refused` in `backup_error`). To accept the rollback, export
the slot, restore, then delete the slot: runbook 5 in `cds-ha-runbooks.md`,
"Restoring an older backup on purpose".

## Recovering from the loss of a majority (Recover)

Recover is break-glass: one surviving replica becomes the only voter with the
state it holds; writes it did not receive are lost.

The steps, and when NOT to issue Recover, are runbook 4 in
`cds-ha-runbooks.md`. Above all: make sure the lost replicas are destroyed,
not only cut off, by means outside the cluster's hosts (cloud console, node
power state). From inside the cluster, a live majority that is cut off looks
the same as a lost one.

As for Genesis, the CLI reads the survivor's member ID over armTLS
(`--target-url https://<survivor>:30809`) and signs it in. If the survivor
restarts, it has no state left and the decree is dead.

The survivor acts only after the decree has stayed pending for the hold,
`2·dead_after + apply + lease + 2·tick` (57 s with the default timing),
while it still sees no leader and no member of its old configuration
answers with one. A live majority rejects the decree in that time
(`rejected_reason`), or, if it cannot read the decree objects, has stopped
serving (see "Fenced" below). If the slot holds a backup with writes the
survivor lacks, the recovered cluster's backups are refused: keep that
backup, then delete the slot as in the rollback steps.

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

### Fenced: the cluster serves nothing while it cannot see decrees

A Recover decree for a replica that is only cut off would start a second
cluster. Only the majority can refuse it, so its leader must see the decree
objects. The leader **fences** the cluster (no reads, no writes; every
replica's reads stop within `lease`) when:

- it has not listed the decree objects for `2·dead_after` (40 s by default)
  **and** a member is cut off (`cut_off_voters`); or
- it has not listed them yet in its term (it lists at once on taking
  leadership) **and** a member is cut off or has not yet reported it as its
  leader over an attested status probe; or
- a Recover decree it did not reject in time names one of its members: it
  saw the decree only after such a gap (status `refused late: ...`), or another
  replica applied it (`applied_epoch`, a fork).

`c8s cds ha status` on the leader shows `fenced` with `reason`, `since_ms`,
`stale_for_ms`, `cut_off_voters`, and for a Recover decree `decree` and
`member`; the leader logs `FENCED` at ERROR once a minute. A plain API outage
with every member healthy fences nothing, also across an election.

What to do:

- **API outage plus a cut-off member** (no decree named): restore the leader's
  API access (or the cut-off member). The fence ends at the next decree list.
  Do NOT issue Recover: the majority is alive.
- **Refused late**: the leader removed the named member from its
  configuration so Raft never merges it back. If that member did not recover,
  it sees the rejection and rejoins by itself once it can reach the cluster;
  the fence ends when it is a healthy member again (or a later process on its
  node is). If you know it is gone, `kubectl delete` the decree object.
- **Fork** (the decree shows `applied_epoch` and the named member leads its own
  cluster): your Recover won. Writes the old majority took after the cut are
  not in it. Restart all the old majority's replicas at once (they join the
  recovered cluster), or, to keep the old majority instead, stop the recovered
  replica and delete the decree object.

Before you sign a Recover, confirm outside the cluster's hosts that the other
replicas are gone (runbook 4).

## Backup provenance and recovery limits

Backups are sealed to the recovery key, and each carries an ECDSA source
signature from the snapshot's mesh CA. It covers a versioned,
domain-separated typed JSON message containing all backup metadata and SHA-256
of the exact ciphertext (including its HPKE encapsulated key). The CLI verifies
that signature against an **independently retained CA certificate fingerprint**
before decrypting, checking inner metadata/floors, or signing a Restore decree.
There is no unsigned-backup fallback.

Before loss:
1. Use `c8s cds ha status --image-policy-file server.json https://<node>:30809`
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

Restore only from backups you trust. Keep the recovery key shares and the
decree key as safe as the cluster's state. Use distinct operator keys per
cluster (see `docs/operator.md`).

## Route backend anchors after rotation

CDS checks address-backend anchors against its current mesh CA on each signed
route write, including after HA RotateKey without a process restart. Missing
current CA fails closed. Singleton CDS uses the same live CA provider interface.
Do not reuse retired mesh keys for backend services.

## Known limitations

- **Clean deployment only.** HA CDS starts from a fresh launch. A single-CDS
  cluster does not convert in place, and state formats and backups older than
  this release are refused, not migrated.
- **Bounded-stale reads.** A replica serves reads up to one Lease (5 s by
  default) after its last confirmed barrier. Reads are not linearizable.
- **Majority loss needs an operator.** A restarted voter comes back empty.
  When a majority is lost, restore from a backup or recover a survivor
  (runbooks 4 and 5).
- **Losing the leader right after a promotion.** A promotion into a free voter
  seat (at Genesis, or after `SetVoters` raises the seats) can commit before
  every voter holds it. Until all of them do, the promoted replica is not
  Ready, `seats_filled` stays false and nothing else is promoted, so a
  readiness-gated rollout never takes the leader then. If the leader is lost
  without a plan in that short window, about one replication round, the
  other voters cannot elect a leader: a voter that missed the promotion
  refuses the new voter's vote requests. The cluster stops serving until the
  old leader's replica is back with its log. If that replica is gone, recover
  a survivor (runbook 4).
- **Backups lag up to one interval.** The leader stores a backup at most once
  a minute, in one slot. Writes after the last backup are lost on restore;
  apply them again. Export backups off the cluster on a schedule.
- **Server-node reboot.** A server-node reboot starts a new, empty cluster
  until server HA is available. Keep an exported backup.
- **Size limits.** Snapshots are limited to 128 MiB compressed and 256 MiB
  SQLite. Size cds nodes for the chart's memory limit (`cds.ha.resources`,
  about 8 GiB nodes for the default 4Gi limit), and keep allowlist documents
  small.
- **Replica count.** 3 to 9 cds nodes, an odd number.
- **Every component change is a new image.** It needs new launch documents;
  a rolling upgrade replaces every cds node.
- **No metrics endpoint for HA state.** `/ha/status` and the log lines in
  `cds-ha-alerts.md` are the signals.
- **Attestation policy.** CDS-HA consumes the attestation library's verdict.
  TCB and attestation policy live in attestation-rs.

## Runbooks and alerts

This file is the reference. Step-by-step procedures (Genesis, adding and
replacing nodes, rolling upgrades, Recover, Restore and rollback, a halted
cluster, divergence, failing backups) are in `cds-ha-runbooks.md`. The meaning
of each `/ha/status` field and alarm log line is in `cds-ha-alerts.md`.
