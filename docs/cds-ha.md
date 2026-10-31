# A highly available CDS

One cluster's CDS can run as several confidential VMs instead of one. The
replicas share one mesh CA, one allowlist and one secret store, and they agree
on every change through a replicated log. A client reaches whichever replica
answers: the certificate it gets, the policy that admits it and the secrets it
reads are the cluster's, not that replica's.

The host is not trusted with any of it. Each replica admits a peer only after
the peer's certificate proves a CDS image the cluster accepts, booted on the
same launch file. The operator's instructions arrive as signed decrees through
an ordinary object store, and the store is never trusted: a replica acts on
the signature, not on the object.

What CDS does for a cluster is unchanged, and this page assumes it:
[operator.md](operator.md) for running it,
[measurements.md](measurements.md) for what pins it,
[armtls.md](armtls.md) for the attested channel.

The procedures are in [cds-ha-runbooks.md](cds-ha-runbooks.md), the alarms in
[cds-ha-alerts.md](cds-ha-alerts.md).

## Versions

A cluster counts the operator commands it has applied. That count is its
**version**. Every decree an operator signs names the version it applies on
top of (`--base-version`), so two operators cannot apply conflicting commands
in either order, and a decree the host replays later applies to nothing. The
cluster reports its version in `c8s cds ha status`.

A node keeps a **pin floor**: the lowest version at which it takes a decree
naming the CDS images it trusts. A node launched today never follows a decree
the operator signed before the set its own launch document carries.

## What the launch file starts and what it fixes

Every replica boots the same `cds-config.yaml`, and clients pin those bytes,
so no field of it changes while the cluster lives. Some fields only start the
cluster; the log rules afterwards.

| Field | Role | How it changes |
|---|---|---|
| `nodes` | the node images the cluster certifies at its Genesis | a `node-images` decree, which carries the whole set |
| `workloads` | seeds the allowlist at every Genesis | operator allowlist writes |
| `ha.voters` | the voter seats the cluster starts with | a `voters` decree, one seat at a time |
| `ha.replicas` | the names and addresses discovery resolves to find the replicas | adding replicas behind a name needs no change; another list is another cluster |
| `ha.board` | the object store an operator may leave decrees in, beside posting them, and the cluster's backups travel through; optional | fixed for the cluster's life |
| `ha.recoveryKey` | the key the leader seals the cluster's backups to; optional, and needs a board | fixed for the cluster's life |
| `clusterID`, `operatorPublicKeys`, `nodeCIDRs`, `leafDNSNames`, `leafDNSPatterns` | as for a single CDS | fixed for the cluster's life |

A field fixed for the cluster's life changes only by writing the file again
under the same `clusterID` and restoring the cluster from a backup, which
keeps its mesh CA, allowlist and secrets
([cds-ha-backups.md](cds-ha-backups.md)). `clusterID` itself never changes: it
is the cluster.

The CDS images a replica may run are not in the file at all: the Genesis
decree carries the first set, and a `pins` decree replaces it.

`c8s cds config new --replica ... --voters 3` writes the file, and `c8s node
launch-config new` writes the same under `--cds-replica` and `--cds-voters`.
`--board-endpoint` and `--board-bucket` (`--cds-board-*`) name the board, and
`--recovery-key` (`--cds-recovery-key`) the key its backups seal to; a file
without them runs a cluster that takes its decrees over the attested channel
alone and keeps its state in the replicas' memory. A file with no `--replica`
runs one CDS, which is the
deployment [operator.md](operator.md) describes.

## Addresses

| Where | Syntax | Who reads it |
|---|---|---|
| `ha.replicas` entry | a DNS name or an IPv4 address, no port | every replica, to find the others |
| `cds.address` in a node document | `<host>:<port>` | a node's credential clients |
| `--url`, `--target`, `--cluster` of the `ha` commands | `<host>[:8443]` | the operator's CLI |

A replica entry must resolve to the replicas themselves. One name may resolve
to several of them, which is how a replica is added without changing the file.
A name that resolves to a load-balanced address is refused: a replica that
cannot tell one peer from another cannot hold an election. A replica raises an
alarm when two members answer at one address.

The ports are fixed. Clients and the operator reach a replica on 8443, and the
replicas reach each other on 8444.

A node names its cluster's CDS by one `cds.address`. Several replicas behind
that one name, or a load balancer in front of them, is what makes a client's
request survive the loss of a replica: ordinary DNS resolution and the
client's own retry do the failover.

## Decrees

An operator instructs a cluster by signing a decree with a key the launch file
pins and posting it to a replica over the attested channel:

```sh
c8s cds ha decree pins --config cds-config.yaml --operator-key operator.key \
    --base-version 12 --platform sev-snp --vcpus 4 \
    --image-manifest manifest.json \
    --to cds-1.example.org --cds-pin cds-pin.json
```

The decree's signature is its authority, so the channel only has to reach an
attested replica of the cluster. A replica hands what it is posted to the
leader, which applies it through the log and answers with the version it
produced or the reason the cluster refused it. The record of what the cluster
applied is `c8s cds ha decrees`, read over the same channel.

`genesis`, `recover` and `admit` are posted to the replica their `--target`
names, which holds the decree until it acts on it. `--out` writes the signed
decree to a file as well, which is what `launch-config add-agent
--pin-decree` reads.

A cluster whose launch file names a board has a second way in: the operator
uploads the decree to `<prefix>/<cluster-id>/decrees/<intent>.json` with their
own credentials, and the leader reads it there. It matters when the replica a
decree is for cannot be reached from where the operator stands, and for a
Recover a majority must see. A leader reads the first 64 objects of its board
per turn, so keep `decrees/` short: a bucket lifecycle rule does the pruning.

| Decree | What it does |
|---|---|
| `genesis` | starts a cluster on one replica that holds none |
| `pins` | replaces the CDS images a replica of the cluster may run |
| `node-images` | replaces the node images the cluster certifies |
| `voters` | names the voter seats the cluster holds |
| `rotate-key` | mints a new mesh CA key, which forks the mesh |
| `admit` | lets one unjoined replica admit the cluster's images |
| `recover` | break-glass: carries one surviving voter on alone |
| `dismiss-recover` | lifts the doubt a Recover left on the cluster |

`--expires-in` (10 minutes by default) bounds how long a cluster may adopt a
decree. It is not the replay protection: a decree that applies once moves the
version past it, and a decree for one replica names the member id that process
minted at its start.

## Starting a cluster

The replicas boot, find each other, and wait: a cluster exists only once a
Genesis decree starts it. The operator reads the member id and the mesh CA of
one replica over the attested channel, signs them into the decree, and posts it
back to that replica. It mints the mesh CA, seeds the allowlist from the launch file's
`workloads`, and begins with the image sets the decree carries. The others
join it. Runbook 1 has the steps.

A Genesis is refused where the target already holds a cluster, so starting a
cluster twice takes a deliberate second decree. Starting a cluster again under
one cluster id is an **availability** step, not a way to change what the
cluster holds: the new cluster has a new mesh CA, an allowlist seeded from
`workloads` again, no secrets, and it resumes above the version the operator
names, so nodes keep taking the newest pin decree. Every leaf issued under the
old CA stops being trusted.

## Voter seats

A cluster has as many voter seats as its log says: `ha.voters` at Genesis,
then whatever a `voters` decree names. The first replicas to catch up fill
the seats; every other replica follows the log without a vote and serves
reads. Replicas and seats therefore scale apart: five replicas can hold three
seats.

A voter keeps its vote while it answers. One that has failed its heartbeats
long enough to count dead is replaced by a caught-up replica, and the seat
change itself goes through the log, one seat at a time, so the cluster keeps a
majority throughout. A process that exits and restarts is a new member of the
cluster: it rejoins, catches up, and takes over the seat of the member it
replaced at that address.

## Reading the cluster

```sh
c8s cds ha status --config cds-config.yaml --cds-pin cds-pin.json
```

One attested client per replica, one line each, then one line per alarm. The
command exits non-zero when a replica answers nothing, does not serve, serves
another cluster, or holds another version or mesh CA than the first. Only the
leader knows the seats and the state digests, so another replica reports those
as `-`. Every value a replica reports is quoted: the replica is what the
command audits, not what it certifies.

`c8s cds ha decrees` reads the record of applied decrees, with every signature
checked against the keys the launch file pins. `c8s cds ha pin-policy` reads
the pin decree the cluster applied and writes the pin document it makes, which
is what a client pins and what `--cds-pin` takes during an image roll.

`/readyz` answers for one replica: it serves when it holds the cluster,
follows the log, and holds a read lease its leader confirmed. A replica that
cannot reach a leader stops serving rather than answering from the state it
still holds.

**roll_safe** is the other gate, and the leader alone answers it: the seats
are filled by voters that answer, none of them is retiring, and every staying
voter holds the newest seat change. It is the gate to wait for between the
replicas of a roll, and `ha status` prints it as `roll_safe=true`.

## The CDS images a replica may run

The cluster's log holds the set, and all of it is one decree's work:

- the replicas admit each other by it;
- clients and nodes pin CDS by it;
- an Admit decree hands one unjoined replica the set, so a replica of a new
  image can reach a leader still running the old one.

Replacing the VMs therefore goes in four steps: pin both images, replace the
VMs one at a time behind `roll_safe` with an Admit each, pin the new image
alone, then write node documents from the new pin document. Runbook 6 has the
steps. An Admit is bound to one member id, so every restart of a replica
during the overlap needs a new one.

## The node images the cluster certifies

The cluster certifies the node images its log names, and a `node-images`
decree replaces that set. An upgrade is two decrees with the node relaunches
between them: first the old and the new image together, then the new image
alone. No launch file, client pin or CDS VM changes for it. Runbook 5 has the
steps.

For a verifier this moves where the set comes from. The launch file's `nodes`
is only the set the cluster started from, so
`c8s verify --kind cds --served-policy-file cds-config nodes` fails after the
first `node-images` decree. The expected set is the node document the operator
signed into the decree in force, and `c8s cds ha decrees` says which decree
that is:

```sh
c8s cds ha decrees --config cds-config.yaml --cds-pin cds-pin.json
c8s verify https://<cds-address> --kind cds --served-policy-file nodes-v13.json ...
```

A replica also publishes the set it enforces at `/measurements`, which is what
`c8s verify` reads and compares. Expecting that same answer proves nothing:
keep the signed node document.

Nodes follow the pin decrees themselves. A node's enforcer reads
`/ha/pins` from a CDS it already pins, checks the operator signature and the
launch-file digest, refuses anything below its pin floor, and hands the images
to its credential clients.

## The mesh CA

The cluster holds one mesh CA key for its life. Past half the certificate's
validity the leader signs a new certificate under the same key through the
log, so every replica serves the same one and running workloads keep their
trust anchor. Replacing the key is the `rotate-key` decree: every leaf must be
issued again under the new key, which is why the command asks the operator to
say so.

## When the cluster stops serving

A replicated CDS fails closed. Three reasons are worth telling apart, and
`ha status` names each:

- **No majority.** Fewer voters answer than a majority. No replica serves,
  because none can confirm a read. Bring the replicas back; the cluster
  continues on its own.
- **Fenced.** The cluster holds the doubt of a Recover decree. Fencing is what
  keeps a cut-off replica from being recovered into a second cluster beside
  this one. Bring the member back, or dismiss the Recover. Runbook 7.
- **Halted.** Every replica stopped at the same log entry, because applying it
  failed on all of them, or because the store under them stopped answering.
  The cluster keeps its leader, its membership and its log, and serves
  nothing. Runbook 8.

Recover is the break-glass answer to a majority that is gone for good: one
surviving voter carries the cluster on with the state it holds, and the writes
the lost voters committed and it never received are gone. The replicas destroy
nothing by themselves, and the cluster refuses to serve on both sides of a
split, so the operator's confirmation that the lost VMs are destroyed is what
the step rests on.

## Replica divergence

Every replica keeps a rolling digest of what it applied and records a state
digest at every checkpoint the leader proposes. The leader compares them:

- a replica that differs from a majority of the voters is stopped, and comes
  back as a new member with the cluster's state;
- a leader that differs from a majority of the other voters hands the cluster
  over and leaves;
- where no majority holds one state, nothing is stopped automatically,
  because no side can be shown to be right. Runbook 9.

A replica also recomputes the digests of every snapshot it ships, and a
snapshot whose content does not match them is refused.

## What a replica keeps

Nothing survives the process. The log, the snapshots and the mesh CA key live
in memory, and the allowlist database lives on a tmpfs the unit owns. A
restarted replica is a new member that takes the cluster's state from the
leader, which is also why losing a majority at once loses the cluster. The one
copy outside the replicas is the sealed backup the leader appends to the
board, which a Restore starts the cluster again from
([cds-ha-backups.md](cds-ha-backups.md)).
