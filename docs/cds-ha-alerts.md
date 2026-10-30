# CDS HA alarms

What to watch on a CDS that runs as several VMs, and which runbook answers it.
[cds-ha.md](cds-ha.md) explains the behaviour.

Two sources say the same things. Every replica reports itself over the
attested channel, which `c8s cds ha status` reads and prints as one line per
replica plus one line per alarm; and every replica logs what is wrong with it
to its own journal at ERROR, prefixed `cds-ha:`, once for as long as the cause
holds. The lines an operator must act on carry `ALARM:`. Alert on either
source, and read the other to tell which replica is at fault.

A status is one replica's own word. `ha status` exits non-zero when the
replicas do not agree, which is the one check that needs no threshold:

```sh
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json || alert
```

## The line of one replica

| Field | Normal | Alert on |
|---|---|---|
| `cluster` | the cluster id its launch file names | any other value: the replica serves another cluster |
| `member` | the id this process minted at its start | a value that changes often: the VM is restarting |
| `state` | `"Leader"` on one replica, `"Follower"` on the rest | no leader, or two leaders in one term |
| `joined` | `true` | `false` for longer than a replica needs to join |
| `serving` | `true` | `false`: the alarm line says what it waits for |
| `version` | the same on every replica | two replicas on different versions for longer than a write takes |
| `node_images_version` | the version of the last node-image decree | a value you did not decree |
| `ca` | the same on every replica | any difference: runbook 7, and no client trusts both |
| `voters` | the seat count the cluster holds | fewer than the seats for longer than a replacement takes |
| `non_voters` | the replicas without a seat | a count that grows while `voters` stays short |
| `applied` | rising on every replica | one replica that stops rising while the others move |
| `roll_safe` | `true` on the leader between rolls | `false` while a roll is to go on: runbook 2 |
| `checkpoint` | `<index>:<digest>`, equal across replicas at one index | different digests at the same index: runbook 9 |
| `last_backup` | `<version>:<index>` of the newest backup on the board, rising on the leader | a value that stops rising while `applied` moves: the alarm line says what failed |

A replica that does not lead reports `voters`, `non_voters`, `roll_safe`,
`last_backup` and the divergence as `-`: only the leader knows them.

## Alarm lines

| Alarm | What it means | What to do |
|---|---|---|
| `this replica does not serve its cluster: ...` | it holds no cluster, lost contact with its leader, is fenced, or stopped following the log | the reason names which; follow the matching row |
| `this replica stopped following the log: ...` | applying an entry failed here | one replica: it exits and rejoins. Every replica: runbook 8 |
| `this replica is fenced: ...` | the cluster holds the doubt of a Recover | runbook 7 |
| `a Recover decree names a member this cluster cannot account for` | an operator handed the cluster to a member that does not answer here | runbook 7: bring it back or dismiss the Recover |
| `a member of this cluster may be carrying a recovered cluster of its own` | that member is out of the cluster and rejoins only as a new member | destroy its VM, or let it rejoin |
| `this replica holds no cluster and reached no replica that holds one` | every replica of the cluster may be gone, and this one is new | confirm the loss outside the host, then runbook 11 |
| `the replicas of this cluster hold different state: ...` | the leader compared the checkpoints | runbook 9 |
| `this cluster's board holds no backup of the state it has now: ...` | the leader could not seal its state or could not append it to the board | the reason names the attempt that failed; the board or the replicated state is at fault |
| `no replica of this cluster may be replaced now: ...` | the seats are not settled | wait; do not replace a VM |
| `the replicas of this cluster take turns answering at one address` | a replica entry resolves to a load-balanced address, or two VMs share one | give every replica its own address: runbook 3 |
| `this leader's Raft refuses every barrier of its term` | the leader cannot confirm reads | it exits, and another replica takes the cluster over; alert if it repeats |
| `this replica admits no peer: the cluster's CDS images are none of this launch file's` | this VM runs an image the cluster does not accept | the roll skipped it, or its Admit expired: runbook 6 |

## Thresholds worth setting

- **A replica that does not serve for more than a minute.** Below that, an
  election, a seat change and a restart all look the same.
- **Two replicas on different mesh CAs, ever.** This is a split cluster.
- **A cluster without a leader for more than a minute.**
- **Fewer voters than seats for more than five minutes.** A dead voter is
  replaced on its own; one that is not means no replica can fill the seat.
- **An alarm line that repeats for more than an hour.** Nothing above clears
  by waiting that long.
- **A `last_backup` that has not moved for more than an hour while the cluster
  takes writes.** A total loss would restore state older than the cluster
  holds.
