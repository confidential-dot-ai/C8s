# HA CDS: operator runbooks

Short procedures for HA CDS. Background is in `cds-ha.md`, limits in its
[Known limitations](cds-ha.md#known-limitations) section. Alarms and what
they mean are in `cds-ha-alerts.md`.

## Setup used by every runbook

    B=<bundle dir>                 # from `c8s node launch-config new`
    ID=<cluster-id>
    CDS=https://<any cds node IP>:30808            # clients: serving replicas only
    R() { echo "https://$1:30809"; }                # one node's replica, Ready or not
    CDS_NODES="<ip-1> <ip-2> <ip-3> ..."            # every cds node IP
    POL="--image-policy-file $B/server.json"
    NS=c8s-cds-decrees             # decree and backup namespace

> **Two addresses.**
> - `$CDS` is the `c8s-cds` Service, a NodePort with `externalTrafficPolicy: Cluster`. It answers from any **serving** replica, because a replica is Ready only while it serves. When no replica serves (before Genesis, after a total loss, or when the majority is lost), `$CDS` has no endpoints.
> - `$(R <ip>)` is the `c8s-cds-replicas` Service (NodePort 30809, `externalTrafficPolicy: Local`, `publishNotReadyAddresses`). It answers from the replica on that node only, whether it serves or not.
> - The operator credential cannot port-forward. Use `$(R ...)` for every step below that targets a replica that may not serve.

**Sample every replica.** This is an unauthenticated read. Use it to watch
the cluster. Never use it for the recovery record.

    ha_sample() { for ip in $CDS_NODES; do curl -sk -m 3 "$(R $ip)/ha/status"; echo; done |
      jq -s -c '.[] | {node_name, state, serving, joined, awaiting_restore, epoch,
        applied_index, voters: (.voters|length), seats_filled, retiring_voters, stuck,
        stuck_local, backup_error, last_backup, fenced, divergence}'; }

**Attested status.** Use this for anything you record or sign. It reads every
replica, serving or not:

    c8s cds ha status $POL $(for ip in $CDS_NODES; do R $ip; done)

**Decree outcome:**

    kubectl -n $NS get configmap -l c8s.confidential.ai/cds-decree=$ID \
      -o custom-columns=NAME:.metadata.name,STATUS:.data.status

**The recovery record.** Keep it offline. After Genesis, Recover, Restore,
RotateKey and every CA renewal, read attested status (above) and write
down `cluster`, the full 64-hex `ca=`, `epoch=` and `applied=`, with the date.
`recover` needs this record (`--trusted-ca-sha256`, `--min-epoch`,
`--min-index`). Never copy these values from a backup export.

**Export the backup on a schedule.** Do this at least every few minutes, and
store the file off the host:

    kubectl get configmaps -n $NS -l c8s.confidential.ai/cds-backup=$ID -o json > cds-backup-$(date +%s).json

---

## 1. Genesis (start a new cluster)

1. Launch the server. Wait until `:9345` answers. Then launch every cds node
   (an odd number, 3 to 9) and the agents.
2. Wait until every cds replica runs:

       kubectl -n c8s-system get pods -l c8s.confidential.ai/cds-ha=true -o wide

3. Read one replica over armTLS. It must show `joined=false`. Any replica can
   start the cluster. Before Genesis no replica is Ready, so `$CDS` has no
   endpoints: use the node's own address.

       c8s cds ha status $POL $(R <node IP>)

4. Sign the decree for that replica process, then apply it within 10 minutes:

       c8s cds ha decree --kind Genesis --cluster-id $ID --operator-key $B/decree.key \
         --target-url $(R <node IP>) --target-image-policy-file $B/server.json > genesis.json
       kubectl apply -f genesis.json

   The CLI prints `decree for member <id> on node <node>` on stderr.
   `--bootstrap-node` defaults to the target's node.
5. Check the result. The decree status must show `applied_epoch: 1`, and
   `ha_sample` must show every replica `serving: true` with one leader. Then
   write the recovery record.
6. If the decree is not applied, the target replica probably restarted. Its
   member ID is gone, so the decree can never act. Run steps 3 and 4 again with
   a new decree. Do not edit or re-apply the old one.
7. Wait `--jwt-clock-skew` (Helm `cds.jwtClockSkew`, 30 s by default) after
   Genesis before the first signed operator write. CDS refuses an operator
   token issued before Genesis plus that skew (401, "operator token issued too
   early"), so a token minted earlier never becomes valid: mint a fresh one
   after the wait.

Never pass `--alone` when the cluster has more than one replica. It lets the
replica start a cluster even when it finds no peers, so a replica that
cannot reach the others starts a second cluster.

## 2. Add a cds node, or replace one

A new replica joins as a non-voter. It takes a voter seat when a seat is free.

1. Find the pin floor. On a cluster that never applied `UpdateMeasurements`,
   `/ha/pins` answers 404: leave the flag out.

       FLOOR=$(curl -sk $CDS/ha/pins | jq .decree.base_epoch)

2. Write the node's launch document under a **new** name:

       c8s node launch-config add-cds-node --bundle $B --name <new-node> --pin-floor $FLOOR

3. Launch the VM with `$B/<new-node>` as its opkeydata disk. Give it a stable
   IP (see limitations, "Stable node IPs").
4. Wait for the readiness gate (below).
5. Replacing a node: delete the old VM only after the gate passes. Then wait
   for the gate again. The dead voter retires after about 20 s
   (`dead_after`), and the leader promotes a replacement.

**Readiness gate.** Go on only when all three hold:

- the new pod is `Ready` (`kubectl -n c8s-system get pods -l c8s.confidential.ai/cds-ha=true -o wide`).
  A replica is Ready only when it serves and the leader reports every voter
  seat held by a healthy voter.
- `ha_sample` shows the new node with `serving: true`;
- on the leader line, `seats_filled: true` and no `retiring_voters`.

Never remove a second node while the gate fails. With 3 voters, two missing
voters lose the majority. That needs runbook 4 or 5.

The old Node object stays `NotReady`. The operator credential cannot delete
it (see limitations).

## 3. Rolling upgrade to a new image (readiness-gated)

This works only when both images use the same peer binding and overlapping
state formats. It does not cross a format boundary (format 3 to format 4 needs
a clean redeploy: `cds-ha.md`, "Compatibility boundary").

1. Pin both images:

       OLD=$(jq -r '.tdx | "\(.mrtd):\(.rtmr1):\(.rtmr2)"' old-manifest.json)
       NEW=$(jq -r '.tdx | "\(.mrtd):\(.rtmr1):\(.rtmr2)"' new-manifest.json)
       c8s cds ha status $POL $CDS          # note epoch=
       c8s cds ha decree --kind UpdateMeasurements --cluster-id $ID --operator-key $B/decree.key \
         --base-epoch <epoch> --image $OLD --image $NEW | kubectl apply -f -

   Wait until the decree status shows `applied_epoch`. If it shows a
   `base_epoch` conflict, sign it again with the current epoch.
2. Replace the cds nodes one at a time, as in runbook 2, but add
   `--image-manifest new-manifest.json` to `add-cds-node`. Replace the
   non-voters first and the leader (`state: Leader` in `ha_sample`) last.
   Pass the readiness gate after each new node and after each removal.
3. If new replicas exit or crash-loop, stop the rollout. The old replicas
   keep the cluster. Read the new pods' logs (`kubectl -n c8s-system logs <pod>`)
   and the alerts table.
4. When every node runs the new image, pin only the new one:

       c8s cds ha decree --kind UpdateMeasurements --cluster-id $ID --operator-key $B/decree.key \
         --base-epoch <epoch> --image $NEW | kubectl apply -f -

5. Remove the old image's entries from the workload policy. They stay until
   you remove them.

## 4. Recover after losing a majority (break-glass)

Recover makes one surviving replica the only voter. It keeps the survivor's
state. Writes the survivor did not get are lost.

**Do NOT issue Recover when:**

- any replica of the old majority may still run. Check this outside the
  cluster's host: cloud console, VM power state, the host's own tools. The
  host can make a live majority look dead, by blocking its status or by cutting
  the survivor off.
- a replica answers `state: Leader` with `serving: true`, or any leader shows
  `fenced`. A fenced leader means the majority is alive but cannot read the
  decree objects. Fix its API access instead (alerts table, `fenced`).
- a Recover was refused with `the cluster has a leader with a majority`.
- the survivor has restarted (`joined=false`). It holds no state. This is a
  total loss: use runbook 5.
- the replicas show `stuck` (a halted cluster). The majority is not lost: use
  runbook 6.

Prefer Restore (runbook 5) unless the writes since the last
backup matter more than the risk above.

Steps:

1. Confirm outside the host that the lost voters are destroyed.
2. Read the survivor. It must show `joined=true`. Note its `epoch=`. A
   survivor without a majority does not serve, so `$CDS` does not reach it:
   use its node's own address.

       c8s cds ha status $POL $(R <survivor IP>)

3. Sign and apply the decree for that process:

       c8s cds ha decree --kind Recover --cluster-id $ID --operator-key $B/decree.key \
         --base-epoch <epoch> \
         --target-url $(R <survivor IP>) --target-image-policy-file $B/server.json \
         --i-understand-recover-is-break-glass > recover.json
       kubectl apply -f recover.json

   If the CLI says `the target replica holds no cluster`, you picked the
   wrong node: that replica holds no state.
4. Wait. The survivor acts only after the decree stays pending for about 57 s,
   with no leader and no answer from its old members.
   It logs `RECOVER: forcing a one-voter configuration`. If it refuses, read the
   alerts table. Do not sign it again with a new intent.
5. Rotate the key, so a lost replica that comes back holds a retired key:

       c8s cds ha decree --kind RotateKey --cluster-id $ID --operator-key $B/decree.key \
         --base-epoch <new epoch> --image $CUR \
         --i-understand-rotation-forks-the-cluster | kubectl apply -f -

   `$CUR` is the running image (`mrtd:rtmr1:rtmr2`). Every workload gets new
   certificates under the new key.
6. Add cds nodes (runbook 2) until every seat is filled.
7. Write a new recovery record. If the leader's `backup_error` says `backup
   refused`, the slot holds a backup with writes the survivor lacks. Do the
   slot steps in runbook 5, "Restoring an older backup on purpose".

## 5. Total loss: Restore from a backup

Use this when no replica holds state. Every line of `ha_sample` shows
`joined: false`, and no line shows a leader. This also covers a server reboot
and a host loss. After a server reboot the in-cluster backup slot is gone too,
so use your latest export.

1. Do not use this for a halted cluster (`stuck` on the replicas). A halted
   cluster still holds its log, and a Restore loses that log. Use runbook 6.
   Wait until `ha_sample` shows `awaiting_restore: true` on the replicas. A
   replica sets it once peers answer that they hold no cluster either, or at
   most 5 minutes after it starts when it reaches no peer. The cds pods stay
   **not Ready**: a replica is Ready only once it serves. `awaiting_restore`
   is a hint. A replica that is only cut off shows it too. Before you restore,
   confirm the total loss as described above.
2. Get the backup. Take the slot if it still exists, otherwise your newest
   export:

       kubectl get configmaps -n $NS -l c8s.confidential.ai/cds-backup=$ID -o json > cds-backup.json

3. From the recovery record for that backup generation, take the CA pin and
   the epoch/index floor.
4. Restore. Send it to the bootstrap node's own replica:

       c8s cds ha recover --url $(R <bootstrap node IP>) $POL --operator-key $B/server.key \
         --backup-file cds-backup.json --cluster-id $ID --bootstrap-node <that node> \
         --decree-key $B/decree.key --trusted-ca-sha256 <recorded ca> \
         --min-epoch <E> --min-index <I> \
         --recovery-key-share share-1.json --recovery-key-share share-3.json --recovery-key-share share-4.json

   Each attempt reads the replica's status and signs the decree for that
   process. The default 30 attempts cover retries. `recover` sends the
   decrypted state only to a replica that `--image-policy-file` pins in full
   (`$POL`); it refuses `--measurements` alone and plaintext `http://`.

   The replica restores only when peer discovery works and every replica it
   finds answers that it holds no cluster. A replica that does not answer
   blocks the Restore: find out why (delete a wedged pod) and retry. If
   discovery finds no other replica at all, the Restore is refused unless you
   add `--alone`. Add it only when you have confirmed outside the host that
   no other replica of this cluster runs, for example after a host loss that
   left one cds node. The host answers discovery, so it can hide a live
   cluster; `--alone` is your statement that there is none.
5. Check: `ha_sample` shows every replica serving one CA, and
   `c8s cds ha decrees $POL --url $CDS` lists the Restore. Write a new recovery
   record.
6. Wait `--jwt-clock-skew` (30 s by default) after the Restore, then apply
   again every policy change, revocation and secret written after the backup,
   each with a freshly minted token. The restored cluster refuses every token
   issued before the Restore plus that skew (401, runbook 1, step 7): it cannot
   know which of them were spent after the backup. The backup holds at most
   the state of one minute before the loss. The allowlist version restarts
   above the one served before the loss, so nodes take these writes.

**Restoring an older backup on purpose.** The restored
cluster's backups are then refused (`backup refused` in `backup_error`). This
keeps a fork from overwriting the live backup. To accept the rollback:

    kubectl get configmaps -n $NS -l c8s.confidential.ai/cds-backup=$ID -o json > slot-before-rollback.json
    # run step 4 with the older backup and a floor that admits it
    kubectl delete configmap -n $NS -l c8s.confidential.ai/cds-backup=$ID

Then check that `backup_error` clears on the leader within about 2 minutes.

## 6. Halted cluster after a deterministic stop

**Symptoms:** the logs show `cds-ha: ALARM: this replica cannot apply a
committed log entry`, then `cds-ha: ALARM: halted at a log entry no replica
could apply` once a minute. Replicas show `stuck` with `stuck_local: false`, nothing
serves, and writes are refused. The leader still applies decrees and keeps its
membership.

**Do not restart or reboot the replicas.** The Raft log lives only in memory.
It is the only copy of the writes since the last backup.

Option A, no loss: roll a fixed image.

1. Get an image that applies the entry. The `reason` in the ALARM names the
   index and the error.
2. Pin the running and the fixed image (runbook 3, step 1). The halted leader
   applies the decree.
3. Add one node with the fixed image (runbook 2, with `--image-manifest
   fixed-manifest.json`). It joins, replays the entry and serves, gets a seat,
   and takes over leadership. Then the halted replicas see a serving leader
   past their stop index. Each one exits and rejoins, but only while the voters
   that follow the log keep a majority.
4. Gate on `serving: true` for the new node before you add the next one. Then
   replace the remaining old nodes as in runbook 3.

Option B, lose the tail: reboot every cds VM, then do runbook 5 with the last
backup. Check the leader's `last_backup.age_ms` first. The halted leader
cannot take a snapshot, so the backup is from before the stop.

Only one replica halted, and the others serve? It exits by itself once the
serving leader is past the entry. If it runs an older image, replace it with
the current image.

## 7. Divergence alarm

Every replica reports `chain` and `checkpoint`. The leader compares them at
each checkpoint, about every 10 s. Read the leader's `divergence` field.

- `stopped diverged replicas: ...`: no action. The replicas that differ from
  the majority are stopped. They restart and copy the leader's state. If the
  same node diverges again, replace it (runbook 2).
- `this leader differs from the majority`: no action. The leader stops,
  hands off, and rejoins.
- `no majority: ...`: no side can be proven right, so nothing is stopped.
  **Backups pause** until the alarm clears.
  1. Bring back missing voters, or wait for them. The next checkpoint usually
     decides.
  2. If the alarm stays, read `checkpoint` on every replica (`ha_sample`, or
     `curl -sk $CDS/ha/status | jq .checkpoint`). Read the allowlist from
     each replica (`GET /allowlist`). Decide which state is right.
  3. Restart the replicas with the wrong state one at a time, by rebooting
     their VMs. Restart the leader first if it is wrong. Never restart a
     majority at once.
  4. If no live replica holds the right state, do runbook 5 with the last
     backup taken before the alarm. Match it by the `state_digest` in its
     metadata.

## 8. Backup failing, or backup too old

`backup_error` reads `backup failing since <time> (<n> attempts): <stage>: <error>`.
Each failed attempt also logs a `Warn` line `backup: <stage>`.

Alert when the leader shows `backup_error`, or when `last_backup.age_ms` is
over 3 minutes while writes happen. A new leader shows no `last_backup`
until its first backup, about 1 minute after it takes over.

By the stage in `backup_error`:

| `backup_error` says | Cause | Action |
|---|---|---|
| `store: ...` (deadline, refused, forbidden) | API server or etcd problem, or RBAC/quota in `$NS` | Fix API access. Each call times out after 10 s, and membership is not blocked. |
| `snapshot: ...` on a `stuck` leader | halted cluster | Runbook 6. |
| `the replicated state exceeds the snapshot size limit` | state too large | Delete allowlist entries, or lower `--allowlist-history-bytes` / `--allowlist-history-versions`. Writes that grow the state already get 507. |
| `backup refused: ...` | the slot holds another history: another Genesis, a fork, or a rollback | Compare `ca=` and `epoch=` from attested status with your record. If this cluster is the one you want, export the slot, then delete it (runbook 5, rollback steps). If the slot belongs to the live cluster, find and stop the other one. |
| none, but backups stopped while `divergence: no majority` | backups pause during the alarm | Runbook 7. |

Also check that your export job runs. The slot is the only in-cluster copy,
and it lives in the same etcd as the cluster.
