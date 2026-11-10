# CDS replica sets (stateless HA)

A CDS can run as a fixed set of 1, 3 or 5 replicas. The replicas hold no state on disk.
The policy log is a signed hash chain kept in an untrusted store (the cluster's Kubernetes API, or an etcd).
The mesh CA key lives only in replica memory and moves replica to replica over attested TLS.

The store orders writes with one compare-and-swap. Signatures prove every entry.
Gossip between the replicas bounds staleness. No replica computes a value the others must agree with:
a replica only verifies, adopts and relays.

## Configuration

The CDS launch file names the set:

```yaml
ha:
  endpoints: ["10.0.0.11:8443", "10.0.0.12:8443", "10.0.0.13:8443"]
```

`c8s cds config new --ha-endpoint <host:port> ...` writes it.
The order is the slot order. All replicas boot the same launch file, so they share one measurement.

Replica flags (none of them is measured; a wrong value costs availability, not safety):

| flag | meaning |
|---|---|
| `--ha-self` | this replica's endpoint. Without it, the replica asks every endpoint for its status and takes the one that names its own member key |
| `--ha-store-etcd` / `--ha-runtime-dir` | an etcd client file, given directly or as `etcd.yaml` of the runtime disk. Without it, the store is the Kubernetes API of the cluster's control plane, reached with the credential `c8s cds ha store-credential` posts |
| `--ha-store-memory` | a single replica keeps the chain in its own memory |
| `--ha-gossip-interval` | T (default 2s) |
| `--ha-peer-timeout`, `--ha-store-timeout` | per-exchange and per-store-call timeouts |
| `--ha-chain-warn-entries`, `--ha-chain-warn-bytes` | the chain-size warning thresholds (an ERROR is logged at each multiple; v1 never prunes) |

The Kubernetes store is the control plane the workers join, outside every TEE, and it is trusted for nothing.
`c8s worker control-plane render` creates its account, `c8s-cds/cds-store`, which may get, create and update the ConfigMaps of `c8s-cds`.
`c8s worker control-plane credentials` also writes `c8s-cds-store.kubeconfig`, a token of that account, which `c8s cds ha store-credential --file` posts to the replicas.
Each replica must reach the API server it names.

## The chain

An entry is a signed body: `{v, cluster, seq, prev, type, payload}`.
- The body is signed with `operatorauth.SignDetached`.
- An entry's hash is SHA-256 over its body alone, so a re-encoded signature does not change it.

Entry types:

| type | payload | signed by |
|---|---|---|
| `genesis` | endpoints, one member key per slot, operator keys, the mesh CA public key, the accepted builds | an operator key of the launch file |
| `policy` | a whole canonical allowlist | an operator key |
| `routes` | the route manifest in the router's envelope | an operator key |
| `accepted` | the whole set of accepted CDS builds (pin + version); every pin binds the one launch file | an operator key |
| `operator-keys` | the new writer keys | a current operator key |
| `member` | slot → member key | a current member key (written by a giver at handoff) or an operator key |
| `nodes` | the whole set of node images the CDS certifies (a measurements document); every entry binds a launch | an operator key |

Notes on the rules:
- Raising the build floor means writing an `accepted` set without the old builds. `c8s cds ha raise-floor` does that.
- Until the first `nodes` entry, a replica certifies the launch file's `nodes`. After one, `/attest`, the sandbox-digests callback and `/measurements` all follow the newest entry.
- There is no log key. A head is vouched for by the replica that serves it over attested TLS.
- Gossip is signed with member keys.

The store holds:
- the head `{v, cluster, seq, hash}` at `cds-<cluster>-head` (ConfigMap) or `/cds/<cluster>/head` (etcd);
- each entry at `cds-<cluster>-e-<hash>` (immutable ConfigMap) or `/cds/<cluster>/entries/<hash>`.

## Reads, writes and gossip

**Read** (every issuance, `/allowlist`, `/routes`, `/ha/chain`):
1. The replica reads the store head linearizably.
2. If the store is ahead, the replica walks the prev links (bounded) and adopts the verified entries.
3. If the store is behind on the replica's chain, the replica writes it forward. This covers rollback and wipe.
4. If the store is on another branch, the replica halts.
5. The replica then serves only if all of these hold:
   - it is the member of its slot;
   - its own attested build is accepted;
   - it is not halted;
   - a majority of the set, counting itself, answered one of its pings sent within T.

**Write** (`POST /ha/entries`):
1. The replica reads the store head, as for a read, and refuses unless it serves.
2. It verifies the entry after its head and puts it.
3. It swaps the head with the store's compare-and-swap.
4. Only after that swap succeeds does it hold the entry.
5. It then runs one gossip round. The write is **done (200)** only if a majority, counting the writer, then holds the entry.

Other answers:
- 202: committed, not confirmed. The write may have been applied.
- 409: another write won, or the entry does not follow the head. Nothing was applied.
- 422: the entry is invalid.
- 503: refused.

**Gossip**, every T/2:
- A ping carries the sender's head. The pong carries the receiver's head and the entries the pinger lacks.
- Both are signed with member keys.
- A pong counts toward serving only if it echoes the ping's nonce, and only while that ping was sent within the last T.
- A newer head is adopted from the peer, and the store is then written forward.
- Two different entries at one seq halt the replica. A halt is the only alarm that stops service.

## Genesis, joining, handoff

1. A replica boots pending, with a fresh member key and a fresh CA key.
2. `c8s cds ha genesis` collects every pending replica's member key and the first replica's CA key, signs entry 0 and posts it.
3. That replica writes entry 0 create-if-absent once the store answers.
4. The other replicas join by handoff. A replica whose store already holds a chain is no genesis candidate.

A giver hands the keys to a replica that answers "pending" at a slot's endpoint:
1. It checks the joiner's attestation against the builds accepted at its head.
2. It writes the `member` entry, which must be done.
3. It checks the joiner again, with a new attested connection, under the builds accepted at the new head.
4. It sends the chain, the CA key, any dropped branches and the store credential.

A giver whose own build is no longer accepted still gives (U1). A halted replica gives nothing.

## Fork recovery

Two entries at one seq halt the replicas that see both. `c8s cds ha resolve --seq S --keep H --endpoints ...`:
- reads every replica's status;
- refuses if a replica does not answer, unless it is named with `--assume-lost`, which needs `--lost-head`: the highest seq the lost replica may have held;
- refuses if a replica on the dropped side answered a write done at or after S;
- refuses if the dropped entry is the CLI's acknowledged head.

Each replica then drops the other branch. A replica holding the kept entry writes it over the store. A replica that held the dropped entry serves again only once it holds the kept one, from the store or a peer: the kept entry may be a done write.

A replica reports a fork at the first seq where it found two entries, which can be above the seq where the branches split. When a replica is still halted after the resolve, the command names the seq to resolve next.

Once the set serves again (it waits up to `--settle-timeout`, 30 s), the command writes the kept chain's allowlist again as a policy entry, above every head a replica held before the resolve and above `--lost-head`.
A node that pulled a dropped branch's allowlist then sees a higher version and fetches the kept one.
If the kept chain has no policy entry, the command says so; write the allowlist with `c8s allowlist`.

Every done write prints `committed head N (hash)`.

## What nodes pin

A worker document names `cds.chain: "<seq>:<hash>"` ([launch-configuration.md](launch-configuration.md)): the genesis, or a later entry as a reboot floor. nri-image-policy then:
1. reads the chain (the entries verify by signature);
2. requires the pinned entry and a chain that extends what it verified before;
3. confirms the head over attested TLS with a replica of a build accepted at that head;
4. when the accepted builds change, rewrites in place the CDS pins its own clients load and the copy its pods mount, moves its allowlist pull to them, and hands them to its sandbox-digests endpoint. The chain counts as followed only once all of this is done, so a failed step is retried at the next pull.

nri-image-policy holds the chain in memory, so after a restart it reads the chain again from genesis. On a long chain the first follow can take a while. Each chain request has the pull timeout; the whole read has none. Until the read finishes, the node uses its launch pins. Checkpoints that let a node start from a later entry are follow-up work.

Every CDS client of the node sends the pin in the `C8s-Cds-Genesis` header. A replica names the pin back only when its chain holds that entry. A client refuses any other answer, so a set re-rooted under the same measurement is refused.
The clients that do this: get-cert, the sidecars, allowlist-proxy, cds-attest and nri-image-policy.

## Operator CLI (`c8s cds ha`)

| command | does |
|---|---|
| `status` | every replica's status |
| `genesis --cluster --version` | signs entry 0 (`--image-policy-file` pins the replicas and is the first accepted build) |
| `accept-image --new-pin --version [--floor] [--force]` | accepts a build, optionally evicting builds below a version |
| `raise-floor --to [--force]` | evicts builds below a version |
| `accept-node --worker-document --worker-image` | admits a worker document: writes a `nodes` entry adding the worker image bound to the document's digest, after you confirm the facts it prints |
| `store-credential --file` | posts the store kubeconfig (one https server, inline CA, a token, a namespace) to every replica |
| `resolve --seq --keep [--assume-lost --lost-head] [--settle-timeout]` | settles a fork |

Notes:
- Every command takes `--endpoints`; a write goes through the first replica that serves. `--url` names one replica instead.
- A set that a majority of the members' running builds are not in is refused without `--force` (U2).
- `accept-image` and `raise-floor` re-read the chain and retry a write another write beat (409) for up to `--retry-for` (default 1m).
- `c8s allowlist` and `c8s routes` write to a replica set as chain entries. A replica answers the old `PUT /allowlist` and `PUT /routes` with 409; a single replica still takes `PUT /secrets`.
- The CLI records, per cluster (`--state-dir`, default `c8s/cds-ha` in the user config directory), the genesis and the last head a write was answered done for. It refuses a replica serving a chain without that head, or of another genesis.
- A write that may have been applied exits 3.

## Deployment and upgrades

- Replicas must reach the node network: at issuance a replica dials the requesting node's sandbox-digests endpoint on port 1019.
- Routers and nodes reach the set through one endpoint name. Put the replicas behind DNS with a short TTL (for example 60 s) or a health-checked load balancer, and take a dead replica out of the name.
- A set of more than one replica serves no secrets and keeps no sandbox ledger (see Secrets).

Upgrade the CDS build in this order:
1. `accept-image` the new build.
2. Roll the replicas to it, one at a time.
3. Render the operator and system objects again: the operator first, the system objects only once a node with the new image exists.
4. Replace the nodes.
5. `raise-floor` to evict the old build.

After a `raise-floor`, a new worker needs a fresh worker document: an old one pins the evicted CDS build, and `accept-node` refuses it.

## Failures

| failure | effect |
|---|---|
| one replica (a minority) dies or is cut off | the others serve; a replacement at its endpoint joins by handoff and writes its member entry |
| fewer than a majority reachable | every replica refuses (503 "unconfirmed") |
| store unreachable | reads, issuance and writes refuse; no halt |
| store wiped or rolled back | written forward from replica memory, the head moving every 64 entries so a re-seed cut short keeps its progress; after a failure the next attempt waits (250 ms, doubling to 10 s); no replica serves below what it holds |
| store withholds from a minority | that replica adopts newer entries from its peers within about T and writes its store forward (a WARN, not a halt). It refuses a write (503) while a member's latest gossip names a head above the store head it read |
| store withholds from a replica that takes writes before gossip reaches it | its write can take a seq the set already took: at most one write is done, the replicas that see both halt, `resolve`. The host can halt the set this way at any time |
| store accepts two swaps at one seq | at most one of the writes is done (two majorities intersect); the replicas that see both halt; `resolve` |
| a store head that does not verify (or claims a huge seq) | refused, bounded work |
| all replicas lost | the CA key is gone: re-root with a new cluster ID and re-pinned node launch documents |

Accepted windows and residuals:
- Under withholding, a replica may serve a stale head for at most T of its own monotonic time.
- If the host pauses a VM whose clock stops, the window is unbounded in wall time.
- A host that withholds the store from every replica but the writer, and cuts the writer off, can keep the others stale until an outside check notices (the CLI's acknowledged head).
- With the vendor co-signature removed, an operator can accept a build of their own, which could read the keys.
- A member whose build is no longer accepted still counts toward quorums until it is replaced.
- Pod clients (get-cert, the sidecars, allowlist-proxy, cds-attest routing) read the node's CDS pins on every TLS handshake, so a long-running one keeps reaching CDS after the replica set moves to a new build. A pin file that does not parse, mid-rewrite, fails that one handshake; the next one reads it again.
- v1 never prunes the chain. Each entry is one ConfigMap in the cluster's etcd, and a re-seed after a wipe takes time linear in its length.

## Secrets

Secrets and the sandbox ledger are served only by a single replica. A set of more than one replica refuses them.
