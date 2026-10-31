# CDS HA runbooks

Procedures for a CDS that runs as several VMs. [cds-ha.md](cds-ha.md)
explains the behaviour each one relies on, and
[cds-ha-alerts.md](cds-ha-alerts.md) what to watch.

Every runbook assumes:

- `cds-config.yaml`: the launch file every replica of the cluster boots;
- `cds-pin.json`: the pin document for the CDS images the cluster accepts,
  which `c8s cds ha pin-policy --out` writes;
- `operator.key`: a private key whose public half the launch file pins.

Every decree is posted to a replica over the attested channel: `--to` names
any replica of the cluster, and `--target` the one replica a `genesis`,
`recover` or `admit` is for. The answer says what the cluster made of it.

Read the cluster before and after every step:

```sh
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json
```

`version=` in that line is what the next decree's `--base-version` names. A
decree that names another version does nothing, which is the point: two
operators cannot apply conflicting commands.

## 1. Start a cluster (Genesis)

The replicas are booted and none of them holds a cluster.

1. Check that every replica answers and reports no cluster:

   ```sh
   c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json
   ```

   Every line reads `joined=false serving=false`. A replica that answers
   nothing has no route, no launch file, or a launch binding its own attester
   refuses: read its VM's console before going on.

2. Sign the Genesis decree for one of them. The command reads that replica's
   member id and mesh CA over the attested channel and signs them in:

   ```sh
   c8s cds ha decree genesis \
       --config cds-config.yaml --operator-key operator.key \
       --target cds-1.example.org --cds-pin cds-pin.json \
       --platform sev-snp --vcpus 4 --image-manifest cds-manifest.json \
       --resume-version 0
   ```

   `--resume-version 0` is the first cluster under this cluster id. Every
   later Genesis names the highest version the old cluster reached.
   `--nodes` overrides the node images the cluster starts out certifying; the
   launch file's `nodes` is the default.

3. Wait for the cluster. Within a few seconds of the decree being posted, the
   decreed replica leads and the others join:

   ```sh
   c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json
   ```

   Every line reads `joined=true serving=true` with one `state="Leader"`, one
   `version=1`, and one `ca=` for all of them.

4. Apply the policy and the secrets the cluster is to hold. A cluster whose
   allowlist does not persist refuses an operator token issued before it
   started for as long as `--jwt-clock-skew` (30 seconds by default): wait
   that long after Genesis, then write.

A one-replica cluster is the only case that needs `--alone`: without another
replica to ask, a Genesis is refused. Do not pass it with more replicas
booted, because a host that hides the others would get a cluster beside them.

## 2. Replace a replica VM

A VM is gone, or is to be replaced for any reason other than a new CDS image
(runbook 6).

1. Wait until the cluster says one replica may be replaced:

   ```sh
   c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json | grep roll_safe=true
   ```

   The one line that can say it is the leader's; every other replica reports
   `roll_safe=-`, because only the leader knows the seats.

2. Destroy the old VM and boot its replacement with the same launch file, at
   an address the launch file's replica entries resolve to.

3. The new VM is a new member. It joins, catches up, and takes the seat of the
   member it replaced once that one has counted as dead. Wait for
   `joined=true serving=true` on its line and `roll_safe=true` again before
   replacing another.

A process that only restarts needs none of this: its unit restarts it, and it
rejoins the same way.

## 3. Add replicas behind a name

The launch file is measured, so the replica entries cannot change. Adding a
replica behind a name they already carry needs no new launch file.

1. Boot the VM with the same launch file.
2. Add its address to the DNS name a replica entry names, so the name resolves
   to it as well as to the replicas already running.
3. Wait for its line to read `joined=true serving=true`. It serves reads
   without a vote: the voter seats are a count, and the seats are full.

Give the seats to the new replicas with runbook 4 where the cluster is to
tolerate more loss. A replica entry that resolves to a load-balanced address
is refused, so the name must resolve to the replicas themselves.

## 4. Change the voter count

More seats tolerate more loss and cost a wider majority per write. The count
is odd, at most 9, and no larger than the number of replicas that can fill it.

```sh
c8s cds ha decree voters \
    --config cds-config.yaml --operator-key operator.key \
    --base-version 12 --voters 5 \
    --to cds-1.example.org --cds-pin cds-pin.json
```

The replicas fill or give up one seat at a time, so the cluster keeps a
majority throughout and keeps taking writes. Watch `voters=` in `ha status`
until it reads the new count. A count the replicas cannot fill leaves the
cluster without a majority for its own seat changes: name no more seats than
there are replicas.

## 5. Upgrade the node images the cluster certifies

Two decrees, with the node relaunches between them. No CDS VM, launch file or
client pin changes.

1. Write the node pin document naming the image being replaced and the one
   replacing it, and decree it:

   ```sh
   c8s cds ha decree node-images \
       --config cds-config.yaml --operator-key operator.key \
       --base-version 12 --nodes nodes-old-and-new.json \
       --to cds-1.example.org --cds-pin cds-pin.json
   ```

   Wait until `node_images_version=` in `ha status` names the version this
   decree produced.

2. Relaunch the nodes on the new image, as any node upgrade does
   ([upgrade.md](upgrade.md)). Each node's certificate is issued because the
   cluster certifies its image, which both images now are.

3. Decree the new image alone:

   ```sh
   c8s cds ha decree node-images \
       --config cds-config.yaml --operator-key operator.key \
       --base-version 13 --nodes nodes-new.json \
       --to cds-1.example.org --cds-pin cds-pin.json
   ```

4. Keep the node document of the decree in force: it is what
   `c8s verify --kind cds --served-policy-file` expects the cluster to serve.

## 6. Roll the CDS image

Every replica VM is replaced with one running the new CDS image. During the
roll the cluster accepts both images, so a new replica reaches a leader still
running the old one.

1. Check `roll_safe=true`.

2. Decree both images:

   ```sh
   c8s cds ha decree pins \
       --config cds-config.yaml --operator-key operator.key \
       --base-version 12 --platform sev-snp --vcpus 4 \
       --image-manifest cds-manifest-old.json \
       --image-manifest cds-manifest-new.json \
       --to cds-1.example.org --cds-pin cds-pin.json
   ```

   Wait until `c8s cds ha decrees` lists it, then write the pin document it
   makes. That document is the `--cds-pin` for the rest of the roll: it
   verifies a replica of either image.

   ```sh
   c8s cds ha pin-policy --config cds-config.yaml --cds-pin cds-pin.json \
       --out cds-pin-both.json --decree-out pins-applied.json
   ```

3. Replace one VM with one running the new image, then let it admit the
   cluster's images:

   ```sh
   c8s cds ha decree admit \
       --config cds-config.yaml --operator-key operator.key \
       --target cds-1.example.org --cds-pin cds-pin-both.json \
       --cluster cds-2.example.org
   ```

   An unjoined replica admits only its own image, so without this it never
   reaches the leader. The Admit names the member id that process minted at
   its start: **every restart of that VM before it joins needs a new Admit**,
   and so does the next VM of the roll.

4. Wait for the new replica's line to read `joined=true serving=true` and for
   `roll_safe=true`, then repeat step 3 for the next VM. Replace the leader
   last.

5. Decree the new image alone:

   ```sh
   c8s cds ha decree pins \
       --config cds-config.yaml --operator-key operator.key \
       --base-version 13 --platform sev-snp --vcpus 4 \
       --image-manifest cds-manifest-new.json \
       --to cds-1.example.org --cds-pin cds-pin-both.json
   ```

6. Write the new pin document for the clients and the nodes:

   ```sh
   c8s cds ha pin-policy --config cds-config.yaml --cds-pin cds-pin-both.json \
       --out cds-pin.json --decree-out pins-applied.json
   ```

   Nodes already running follow the decree themselves. Nodes added from now on
   take the images from the decree: runbook 10.

## 7. Recover a cluster that lost its majority

Break-glass. The writes the lost voters committed and the survivor never
received are gone, and a cut-off replica that comes back must not serve beside
the recovered one.

1. Confirm, outside the cluster's hosts, that the lost VMs are destroyed: a
   cloud console, the hypervisor, the power state. From inside the cluster a
   live majority that is cut off looks exactly like a lost one.

2. Read the survivor and keep its `version=`. Name a surviving voter: a
   replica that held no vote may be missing writes the cluster committed.

3. Sign the Recover and post it to the survivor:

   ```sh
   c8s cds ha decree recover \
       --config cds-config.yaml --operator-key operator.key \
       --target cds-3.example.org --cds-pin cds-pin.json \
       --base-version 14 --resume-version 14 \
       --i-understand-recover-is-break-glass
   ```

   The survivor carries the cluster on alone and then takes the other replicas
   back as new members.

4. Follow it with a `rotate-key` decree where a lost replica could come back:
   every leaf must then be issued again, and anything that returns holds a
   retired key.

If the other side of the cluster saw the Recover first, it fences itself and
reports the decree as its doubt. Once the doubted member has rejoined, or its
VM is destroyed, lift the doubt:

```sh
c8s cds ha decree dismiss-recover \
    --config cds-config.yaml --operator-key operator.key \
    --base-version 14 --recover-intent <intent id from ha status> \
    --to cds-3.example.org --cds-pin cds-pin.json
```

## 8. A halted cluster

Every replica stopped at the same log entry: `ha status` shows `serving=false`
with the same reason on every line, and each replica logs it every minute. The
cluster keeps its leader and its membership and serves nothing. No committed
write is lost while the VMs run.

**Keep the VMs running.** The log lives in memory, so restarting them all is
what loses the cluster, not the halt.

1. Read the reason on any line. Two kinds say different things:

   - *stalled on a command*: a write into the replica's own store has not
     returned. The cause is under the VM, usually a host that stopped
     answering its disk. Fix that, and the replicas serve again by
     themselves, in the order they stopped.
   - *cannot apply a committed log entry*: applying it failed on every
     replica running this CDS image, and it will fail again on a restart.

2. For the second kind, capture the reason, the leader's `applied=` index and
   the alarm lines, and escalate. Only a CDS image that applies the entry gets
   the cluster out, and a halted cluster applies no decree, so it cannot
   accept that image by itself.

A single replica that stops while the others serve is not this: it stops
serving and exits, and its restart rejoins with the cluster's state.

## 9. Replicas that hold different state

The leader compares what the replicas applied at every checkpoint.

- **`stopped the replicas that hold another state`**: the cluster handled it.
  Each stopped replica exits and rejoins as a new member with the cluster's
  state. Nothing to do; keep the log line, because a replica whose state
  changed under it is a host that touched memory or a disk it should not have.

- **`no majority of the voters holds one state`**: nothing is stopped, because
  no side can be shown to be right. Do this:

  1. Read `checkpoint=` from every replica. It is `<index>:<digest>`, and
     replicas that agree report the same digest at the same index.
  2. Decide which state is the cluster's from outside the cluster: the replica
     whose history you trust, usually the one that led while the writes were
     taken.
  3. Destroy the VMs of the replicas that hold another state. Their
     replacements join as new members and take the leader's state (runbook 2).

Keep the alarm lines: they name each member with its digests and how many
voters agree.

## 10. Add a node after a CDS image was retired

A node follows the cluster's pin decrees, so it must not take one that still
names a retired CDS image. A node already running holds the newer decree and
refuses older ones. A node added later needs the floor in its own document:

```sh
c8s cds ha pin-policy --config cds-config.yaml --cds-pin cds-pin.json \
    --decree-out pins-applied.json
c8s node launch-config add-agent --bundle bundle --name node-7 \
    --pin-decree pins-applied.json
```

The document then pins the images that decree names and carries the version it
applies at as the node's pin floor: a replayed older decree, including one that
still named the retired image, is refused. A node that reboots forgets the
decree it followed and starts from its own document again, which is why the
floor belongs in the document rather than in the node's state.
