# CDS HA: backups and restoring a lost cluster

A highly available CDS keeps its state in the replicas' encrypted memory and
nowhere else. The log that state comes from lives there too, so a cluster that
loses every replica at once is gone with them: the mesh CA it issued under, its
allowlist, its secrets and its sandbox bindings.

A sealed backup is the way back. The leader seals the whole replicated state to
the cluster's recovery key and appends it to the cluster's board. The private
half of that key never enters a CDS VM: the operator keeps it offline, and only
they can open a backup.

This page covers watching the backups, choosing one, and starting a lost
cluster again from it. [cds-ha.md](cds-ha.md) explains the behaviour it rests
on, and [cds-ha-runbooks.md](cds-ha-runbooks.md) covers every other procedure,
Recover of a surviving voter included.

## What a backup holds

| Part | Where it comes from |
|---|---|
| The mesh CA certificate and key | the lost cluster's log |
| The allowlist, with its history | the lost cluster's log |
| The secrets and the sandbox bindings | the lost cluster's log |
| The applied decrees and the cluster version | the lost cluster's log |
| The CDS images, the node images, the launch file digest | the Restore decree, not the backup |

The state is sealed with HPKE to the recovery key, and the metadata beside it
(cluster id, version, log index, state digest, applied decrees) is bound into
that seal: metadata changed on the board opens nothing. The mesh CA of the
sealed state also signs the metadata and the exact ciphertext, so a backup is
authenticated as that cluster's before it is opened.

The leader seals a backup at most once an interval, and only from a checkpoint
a majority of the voters confirmed, so a replica that diverged seeds no backup.
Every backup is one new object. No replica deletes one; a bucket lifecycle rule
prunes old objects.

## Keep these three things off the cluster

A backup without them restores nothing:

1. **The recovery key.** `ha.recoveryKey` in the measured configuration is its
   public half. Keep the private half offline. Whoever holds it can read every
   secret the cluster ever held, and start a cluster of their own under its
   mesh CA.
2. **The mesh CA fingerprint.** `ca` in `c8s cds ha status`, taken while the
   cluster was alive. A restore authenticates the backup against it, and never
   against a fingerprint read off the board.
3. **The newest version and log index you saw.** `version` from
   `c8s cds ha status` and `index` from the leader's `last_backup`. They are
   the floor a restore holds to: a backup below it takes back decrees,
   allowlist writes and secrets.

Record the first two once, at install. Record the third whenever you change the
cluster: after every decree, and after an allowlist or secret write that must
survive a total loss.

## Watching the backups

The leader reports its backups in `c8s cds ha status`:

```
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json --json
```

- `last_backup` is the version, log index and sealing time of the newest backup
  the leader appended. Only the leader answers for the backups; the other
  replicas report none.
- `backup_error` is why its backups are failing, with how long and how many
  attempts. The leader waits twice as long after each failure, up to 16
  intervals.

Three failed attempts in a row raise an alarm in the replica's log:

```
ALARM: this cluster's board holds no backup of the state it has now;
a total loss would restore older state
```

Treat it as a data-loss alarm, not a liveness one: the cluster serves normally
while it is raised. Check that the board endpoint answers, that the bucket
exists, and that the replicas' network scope still reaches it.

A leadership change moves the duty to the new leader, which appends its own
first backup once the voters confirm a checkpoint above the one on the board.

`c8s cds ha backups` lists what the board holds:

```
c8s cds ha backups --config cds-config.yaml
"backups/<ca>-12-4096-<mark>.sealed" version=12 index=4096 ca="<ca>"
```

Oldest state first. Every field comes from the object key, which is whoever can
write to that board's word. It says which backups to consider and nothing more.

## Runbook: restoring a lost cluster

### 1. Establish that the cluster is gone

A restore starts a second cluster under the same cluster id if the first is
still serving. Neither the CLI nor the replica can tell a total loss from a
host that hides the cluster, so this step is the operator's.

- Confirm with the infrastructure owner that every CDS VM of the cluster is
  destroyed, not stopped and not partitioned.
- Run `c8s cds ha status` against the configuration's replica entries. Every
  replica must answer `unreachable`, or answer `joined=false`.

A replica that holds no cluster and reached no replica holding one raises this
alarm, which is advice and not a verdict:

```
<address> ALARM: this replica holds no cluster and reached no replica that
holds one: the cluster may be lost
```

### 2. Choose a backup

```
c8s cds ha backups --config cds-config.yaml
```

Take the newest backup at or above the version and index you recorded. An older
one is a rollback: decrees, allowlist writes and secrets the cluster took after
it are gone, and workloads that hold a secret the restored cluster no longer
has will be refused.

### 3. Launch the replicas

Boot the cluster's CDS VMs again on the measured configuration. Use the same
configuration document unless you are changing a cluster-lifetime field; see
[Changing a cluster-lifetime field](#changing-a-cluster-lifetime-field).

Every replica comes up holding no cluster, and the one you restore on needs no
treatment of its own: a Restore decree names one process, and the others join
it afterwards.

### 4. Find the target replica

```
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json --json
```

Pick a replica that reports `joined=false` and an `awaiting_restore` line, and
note its address. `awaiting_restore` means it resolved every replica entry of
its cluster and none of the replicas that answered holds a cluster.

A replica that reports none of that still refuses a restore unless what it is
missing is the answer of another replica: `--alone` covers that one case. A
replica that holds a cluster, that has not looked for its cluster within
`dead_after`, or that reached a replica holding one refuses whatever the
decree says.

### 5. Restore

```
c8s cds ha recover \
  --config cds-config.yaml \
  --operator-key operator.pem \
  --target cds-1.example.org \
  --cds-pin cds-pin.json \
  --backup "backups/<ca>-12-4096-<mark>.sealed" \
  --recovery-key recovery.pem \
  --trusted-ca-sha256 <the fingerprint you kept> \
  --min-version 12 --min-index 4096 \
  --resume-version 14 \
  --platform sev-snp --vcpus 4 --image-manifest cds-image/manifest.json \
  --i-understand-restore-loses-writes
```

| Flag | What it decides |
|---|---|
| `--backup` | the board key `ha backups` listed |
| `--recovery-key` | the key file the backups are sealed to; refused unless the configuration names its public half |
| `--trusted-ca-sha256` | the mesh CA the backup must be signed by |
| `--min-version`, `--min-index` | the oldest state you accept |
| `--resume-version` | the highest version you know the cluster reached; the restored cluster resumes above it |
| `--platform`, `--vcpus`, `--image-manifest` | the CDS images the restored cluster accepts, as for a Genesis |
| `--nodes` | the node images it certifies; the configuration's `nodes` by default |
| `--alone` | restore even where the target replica finds no other replica |

Name the image the replicas are actually running. The replicas admit each other
by the image set this decree carries, so a set naming another image leaves a
cluster whose replicas cannot reach each other.

The command opens the backup locally, checks it, signs a Restore decree naming
the state, and posts the decree and the state to the target replica over
armTLS. The replica starts the one-voter group its cluster begins as, and the
restore is the first entry of its log. It answers with the version the restored
cluster is at.

A restore reads a whole state and starts a group, so it can take minutes. If
the connection breaks, read the decree record for the intent id the command
printed:

```
c8s cds ha decrees --config cds-config.yaml --cds-pin cds-pin.json
```

A record holding that intent is a restore that happened; rerunning the command
with the same flags signs a new decree, which a replica that already holds the
cluster refuses.

### 6. Let the other replicas join

They ask the restored leader to take them in, take the state from it, and fill
the voter seats. Wait for it:

```
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json
```

Every replica must report `joined=true serving=true`, the same `version`, and
the mesh CA fingerprint you kept.

### 7. Write the pins again

The restored cluster's pin decree is the Restore decree, so the document that
pins its CDS is new. Write it out and hand it to the clients and nodes:

```
c8s cds ha pin-policy --config cds-config.yaml --cds-pin cds-pin.json \
  --out cds-pin.json --decree-out pin-decree.json
```

Then write the node documents from `pin-decree.json` and update the clients'
pins, as runbook 6 of [cds-ha-runbooks.md](cds-ha-runbooks.md) does after a
CDS image roll.

### 8. Check what the restore cost

- Operator tokens issued before the restore are refused: the record of spent
  tokens went with the lost cluster.
- The allowlist version is raised to the restore time, so node enforcers take
  the restored document over anything they hold.
- Writes the lost cluster took after the backup are gone. Write them again.
- A workload holding a secret the restored cluster does not have gets a
  refusal, not a stale value.

## After a Recover

A backup may carry a doubt: a Recover decree the lost cluster could not account
for. Every replica of the restored cluster fences on it and serves nothing
until the doubt is lifted. `ha status` reports it as `fenced`. Sign a
`dismiss-recover` decree for the intent it names and post it to a replica:

```
c8s cds ha decree dismiss-recover --config cds-config.yaml \
  --operator-key operator.pem --to cds-1.example.org --cds-pin cds-pin.json \
  --base-version <the version ha status reports> --recover-intent <intent>
```

## Changing a cluster-lifetime field

`clusterID`, `operatorPublicKeys`, `ha.board`, `ha.recoveryKey`,
`ha.replicas`, `nodeCIDRs`, `leafDNSNames` and `leafDNSPatterns` are fixed for
a cluster's life: every replica boots the configuration as its launch file, and
every client pins it. A restore is the one way to change one and keep the mesh
CA, the allowlist and the secrets.

1. Take a backup's version and index from `ha backups`, and the mesh CA
   fingerprint from `ha status`, while the cluster is still alive.
2. Write the configuration again, under the same `clusterID`.
3. Destroy the cluster's VMs, and boot the replicas on the new configuration.
4. Restore as above. The Restore decree carries CDS pins bound to the new
   launch file, and the restored cluster records that launch file as its own.
5. Write the client and node pins again from `ha pin-policy`.

`clusterID` itself never changes: it is the cluster.

## Why a restore adds no power

A Restore decree crosses configurations, and it starts a cluster holding a mesh
CA and secrets its replicas never saw. It still grants nothing new: whoever
holds the recovery key can already decrypt every secret and the mesh CA key of
every backup. The decree is bound to one member id, carries the operator's
signature over the state digest, and a replica takes it only while it holds no
cluster and found none, so a host that keeps a copy of the board cannot replay
one.

## Refusals and what they mean

| What the replica answers | What it means |
|---|---|
| `the Restore decree names another replica process than this one` | the decree was signed for another member id; a restart mints a new one, so sign again |
| `this replica holds a cluster already` | the restore ran, or the replica joined one since; read `ha decrees` |
| `a replica of this cluster holds it` | a replica answered that it holds the cluster: it is not lost |
| `discovery did not resolve every replica of this cluster` | the resolver answered for fewer than the configuration's replica entries |
| `no other replica of this cluster answered` | the target reached no other replica; boot them, or restore `--alone` |
| `the state is <digest>, and the decree names <digest>` | the state was changed between opening the backup and posting it |
| `the decree pins CDS images of launch file <digest>, and this replica boots <digest>` | `--config` is not the document the replicas booted |
| `the cluster's policy is not this replica's` | the restored state comes from a cluster whose store limits this CDS image does not hold |
| `the backup was signed by another mesh CA than the one kept from the cluster` | `--trusted-ca-sha256` does not match the backup's signer |
| `the backup does not open with this recovery key` | another key, or the backup or its metadata was changed on the board |
| `the backup holds version <v> at log index <i>, below the floor` | the backup is older than the state you recorded |
