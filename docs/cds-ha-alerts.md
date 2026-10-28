# HA CDS: alerts

What each signal means and what to do. The signals are `/ha/status` fields
and log lines (`kubectl -n c8s-system logs <c8s-cds-ha pod>`). "Runbook N"
refers to `cds-ha-runbooks.md`.

`/ha/status` is the replica's own report. Fields marked "leader" are set only
on the leader. Read it over armTLS with attested status (`c8s cds ha status`,
see the runbooks' setup): its lines carry the fields below as `key=value`, and
its alarm lines carry the text. For a script, use `c8s cds ha status --json`
and read `.[].status`; there, fields that are false or empty are left out, so
`jq` shows `null`. `ha_sample` reads the same fields without authentication:
use it only to notice a signal, and confirm with attested status before you
act.

## Cluster state

| Signal | Meaning | Action |
|---|---|---|
| `serving=false` on one replica, for less than 1 min | It lost contact with the leader, or the clock jumped | None. Look at it if it lasts. |
| No `state=Leader` line for more than 60 s | An election is running, or the majority is lost | Count the live replicas. If a majority of voters is gone: runbook 5, or runbook 4. |
| `seats_filled=false`, or `retiring_voters=` above 0, for more than 1 min (leader) | A voter seat has no healthy voter. One more loss costs the majority. | Remove nothing. Add a cds node (runbook 2). |
| `term=` climbs fast | Elections keep happening | Check the host network and CPU. |
| `apply_lag` keeps growing, or `log_bytes` grows (`--json`) | A replica falls behind | Check the node's CPU and memory. Replace the node if it lasts. |
| `epoch=` or `ca=` differ between replicas in attested status for more than 5 s | A decree or rotation is in progress, or a replica is behind | Wait one lease. If it lasts, read `c8s cds ha decrees`. |
| `ca=` changed in attested status, but you signed no RotateKey | Normal CA renewal at half the lifetime changes the fingerprint | Write the new `ca=` into the recovery record (from attested status). |
| `awaiting_restore=true` on one replica while another replica serves | That replica is partitioned (for example a node that came back with a stale IP) | Fix the network. Do not restore. |
| `clock jump: not serving until the leader is heard again` | The VM was paused, or the host stepped the clock | None if it is rare. If it repeats, the host is at fault. |
| `slow leader: transferring leadership` / `slow leader: no caught-up follower; keeping leadership` | The leader is slow (disk or CPU) | Watch. If it repeats, check the host. |

## Stopped replicas

| Signal | Meaning | Action |
|---|---|---|
| `cds-ha: this replica can no longer follow the log (local fault); it stops serving and exits to rejoin`; `stuck=local` | Its own store failed (disk full, I/O, file descriptors) | None: it restarts and rejoins. If one node repeats it, replace that node (runbook 2). |
| `cds-ha replica stuck and its loop did not end it; exiting` | The watchdog ended a stuck replica | Same as the line above. |
| `cds-ha: ALARM: stopped following the log, ...` on every replica, `reason` with `database or disk is full`; `stuck=local` | The store is full on every replica at the same entry | Runbook 6, "A full store on every replica". Do not restart the replicas. |
| `cds-ha: the cluster's leader excluded this member; exiting` | The leader cut this member out while it was cut off (see "Refused late" in `cds-ha.md`) | None: it restarts and rejoins as a new member. If a Recover decree names it, check that decree first. |
| `cds-ha: ALARM: halted at a log entry no replica could apply`; `stuck=deterministic` | A committed entry that no replica applies. The replicas keep the log. | Runbook 6. Do not restart the replicas. |
| `leader wedged: raft refuses every barrier although a quorum answers heartbeats` | raft #696 stall. The leader exits, and another one takes over. | None. If it repeats, report it with the log line. |
| Pod `OOMKilled` | Not enough memory | Size the cds nodes at about 8 GiB (limitations). Several at once lose the majority. |
| `join refused` repeats on a new node | It cannot join. The line gives the reason. | Act on the reason. With a new IP after a reboot, suspect the Cilium stale-IP race: the node restarts its Cilium agent by itself within about a minute or two. Do not reboot the VM for it. |
| `cds-ha: pre-join server` (Error) | The replica could not open its operator port before it joined. It does not try again. Before Genesis or after a total loss, that replica cannot be read or restored. | Reboot that node's VM. |
| `renew mesh CA certificate` (Error or Warn, leader) | The CA certificate renewal failed. The leader tries again every backup interval. | If it repeats, read the error. Every replica's `/readyz` fails once the certificate has less than `cds.ca.minValidity` (1 h) left. |
| `prune allowlist history` (Warn, leader) | The history prune failed. | If it repeats, read the error. The state grows until writes get 507. |
| `node list did not sync within 1m30s`, then a restart | Cluster networking was not up yet | None if it happens once. |
| A node VM is up, but no ports answer and there are no pods | First quote after the host boot failed | Restart the VM. |

## Backups

| Signal | Meaning | Action |
|---|---|---|
| `backup failed: the replicated state exceeds the snapshot size limit ...`; `backup_error=true` (leader) | State over the snapshot bound. No backup is stored. | Delete allowlist entries, or lower the history bounds. Runbook 8. |
| `backups failing: no new backup is stored, so a total loss would restore older state`; `backup_error=true` (leader) | 3 failures in a row, or failures for 3 intervals | Runbook 8, by the stage. |
| `backup: store`, `backup: open snapshot`, `backup: read snapshot` (Warn) | A single failed attempt. `backup_error=true` shows it too. | Alert if they repeat for 3 minutes. Runbook 8. |
| The `backup_error:` line says `backup refused: ...` (leader) | The slot holds a backup from another history | Runbook 8, `backup refused` row. |
| The age in `last_backup=` over 3 min while writes happen (leader) | Backups stopped | Runbook 8. |
| `backups resumed` | Backups are stored again | None. |
| The age of your newest export file | Your off-host copy is old | Fix the export job. |

## Decrees, Recover and Restore

| Signal | Meaning | Action |
|---|---|---|
| Decree status `rejected_reason: base_epoch ...`, or the leader logs `decree rejected` with `why` | Signed for an old epoch | Read `epoch=` again, and sign a new decree with a new intent. |
| Decree status `rejected_reason` says `target_member` | Signed without a target, or for a process that restarted | Sign again with `--target-url` (runbook 1 or 4). |
| `decree object name "...": ...` from `c8s cds ha decree` | An `--intent-id` that is not a lowercase RFC 1123 name | Use lowercase letters, digits and `-`, or leave `--intent-id` out (the default is valid). Never reuse an intent: the object keeps the old `status`, and the leader skips the new decree. |
| `Recover decree refused: the cluster has a leader with a majority` | The majority is alive | Delete the decree object. Do not sign it again. |
| `Recover decree refused: this replica is not a voter` | The decree names a non-voter | Delete the decree object. Name a surviving voter (runbook 4). |
| `Recover decree names this replica: acting after the hold unless the cluster rejects it or answers` | A Recover is pending on this replica | Expected only during runbook 4. Otherwise delete the decree object now: the hold is about 57 s. |
| `Recover refused: a member of the cluster answers and has a leader` | The old cluster is alive | Delete the decree object. Find out why the survivor looked cut off. |
| `RECOVER: forcing a one-voter configuration with this replica's state` | A Recover was applied | Finish runbook 4: RotateKey, add nodes, write a new record. |
| `RESTORE: starting the cluster from an operator backup` | A Restore was applied | Expected only during runbook 5. Otherwise check `c8s cds ha decrees`. |
| `cds-ha: FENCED: this cluster serves no reads or writes`; `fenced=true` (leader) | The leader cannot rule out a Recover elsewhere | Act on the reason at the end of the `FENCED` line. See the next three rows. |
| `FENCED` reason: `has not seen the decree objects ... while members are cut off`, or `not yet seen the decree objects in its term` | Kube API outage during a cut-off (or right after an election) | Restore the leader's API access, or the cut-off member. The fence ends at the next decree list. **Do not issue Recover**: the majority is alive. |
| `FENCED` reason: `Recover decree may have been applied by <member>` (decree status `refused late: ...`) | A Recover arrived while the leader was blind | If that member is gone, delete the decree object. Otherwise wait: once it reaches the cluster it exits, its restart rejoins as a new member, and the fence ends. |
| `FENCED` reason: `Recover decree was applied by <member>: this cluster is a fork` | The Recover side runs its own cluster | Keep the recovered cluster: reboot all of the old majority's VMs at once, so they join it. Or keep the old majority: stop the recovered replica and delete the decree object. Writes on the side you drop are lost. |

## Divergence

| Signal | Meaning | Action |
|---|---|---|
| `cds-ha: replica divergence: replicas that differ from the majority are stopped and re-seeded from this leader`; `divergence: stopped diverged replicas: ...` line (leader) | A minority replica held other state. It is stopped, and it rejoins. | None. If the same node repeats it, replace that node. |
| `cds-ha: replica divergence: this leader differs from the majority; it stops and hands off leadership` | The leader held other state | None. It rejoins under a new leader. |
| `cds-ha: replica divergence: no majority holds one state ...`; `divergence: no majority: ...` line | No side can be proven right. Backups pause. | Runbook 7. |
| `cds-ha: replica divergence resolved` | A later checkpoint agreed | None. Check that backups resume. |

## Writes

| Signal | Meaning | Action |
|---|---|---|
| HTTP 507, or the text names `snapshot capacity` (secrets: `state_capacity`) | A write would take the state past 75% of the snapshot bounds | Make the allowlist document smaller, or wait for the history prune (about one second). |
| HTTP 503 from every replica | No serving leader: an election, a halted cluster, or a fence | Read attested status: `stuck=`, `fenced=`, or no `state=Leader`. |
