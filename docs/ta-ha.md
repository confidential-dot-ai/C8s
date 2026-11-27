# Trust Authority replica sets (stateless HA)

A Trust Authority can run as a fixed set of 1, 3 or 5 replicas. The replicas hold no state on disk.
The policy log is a signed hash chain kept in an untrusted store (the cluster's Kubernetes API, or an etcd).
The mesh CA key lives only in replica memory and moves replica to replica over attested TLS.

The store orders writes with one compare-and-swap. Signatures prove every entry.
Gossip between the replicas bounds staleness. No replica computes a value the others must agree with:
a replica only verifies, adopts and relays.

## Configuration

The Trust Authority launch file names the set:

```yaml
ha:
  endpoints: ["10.0.0.11:8443", "10.0.0.12:8443", "10.0.0.13:8443"]
```

`c8s ta config new --ha-endpoint <host:port> ...` writes it.
The order is the slot order. All replicas boot the same launch file, so they share one measurement.

The launch file's `nodes` is the initial authorization set and may be empty.
Every image it contains must bind a launch (`approver_key`, `launch_file` or `launch_file_digest`).
Signed `nodes` entries must be nonempty and every image must bind a launch.
A replica refuses to start on a launch file with an unbound entry, and `accept-node` refuses to extend such a set.

Replica flags (none of them is measured; a wrong value costs availability, not safety):

| flag | meaning |
|---|---|
| `--ha-self` | this replica's endpoint. Without it, the replica asks every endpoint for its status and takes the one that names its own member key |
| `--ha-store-etcd` / `--ha-runtime-dir` | an etcd client file, given directly or as `etcd.yaml` of the runtime disk. Without it, the store is the Kubernetes API of the cluster's control plane, reached with the credential `c8s ta ha store-credential` posts |
| `--ha-store-memory` | a single replica keeps the chain in its own memory |
| `--ha-gossip-interval` | T (default 2s) |
| `--ha-peer-timeout`, `--ha-store-timeout` | per-exchange and per-store-call timeouts |
| `--ha-chain-warn-entries`, `--ha-chain-warn-bytes` | the chain-size warning thresholds (an ERROR is logged at each multiple; v1 never prunes) |

The Kubernetes store is the control plane the workers join, outside every TEE, and it is trusted for nothing.
`c8s worker control-plane render` creates its account, `c8s-cds/cds-store`, which may get, create and update the ConfigMaps of `c8s-cds`.
`c8s worker control-plane credentials` also writes `c8s-cds-store.kubeconfig`, a token of that account, which `c8s ta ha store-credential --file` posts to the replicas.
Each replica must reach the API server it names.

### Signed policy input from Kubernetes

With the Kubernetes chain store, generate the Trust Authority launch configuration with
`c8s ta config new --ha-input-configmap policy-input` alongside its required
inputs and `--ha-endpoint`. This writes the optional `ha.inputConfigMap` field;
an absent or empty field disables consumption. The verified launch file selects
the input, with no runtime override. Changing its name changes the launch-file
binding: regenerate the configuration and pin before launching the replacement.
Use a ConfigMap name outside the reserved `cds-<cluster>-` prefix. Etcd and memory
stores do not support this input.
Install the usual store credential and establish genesis first. The consumer
waits until the replica serves; replacing the credential updates its API client
and namespace for subsequent polls.

The ConfigMap must contain only `binaryData.entry`, holding one base64-encoded
native signed entry file, with no `data` fields. For example:

```sh
kubectl -n c8s-cds create configmap policy-input \
  --from-file=entry=policy.entry --dry-run=client -o json |
  jq '.binaryData.entry = (.data.entry | @base64) | del(.data)' > policy-input.json
```

This generates a local manifest; publish it through the system that manages the
input ConfigMap. The namespace must match the store credential. The decoded
file is limited to 1 MiB, including its encoding and whitespace. Trust Authority accepts only
non-genesis `policy` and `routes` entries through this input, using the same
validation, commit and confirmation path as `POST /ha/entries`.

Polling runs independently of gossip, every five seconds normally, with jittered
backoff up to one minute for unavailable or unconfirmed input. Reading the input
uses `--ha-store-timeout`; submission uses its own store and peer timeouts.
Unchanged confirmed or rejected artifacts are not submitted
again unless the verified head changes. Uncertain submissions retry the original
body and signature while that artifact remains published. Keep it published until
attested observation confirms acceptance. Replacing or deleting it ends its retries;
missing, deleted or invalid input never clears accepted policy.

Logs report the file digest, supplied entry identity, observed head and outcome.
An entry identity read from input is unverified until acceptance; logs do not
replace attested observation. The publisher needs write access only to this input
object, never to accepted chain objects. Trust Authority only reads the input and needs no
operator private key. Kubernetes synchronization does not establish Trust Authority acceptance
or application readiness.

### Starting without workers

Pass an explicit node document to `--node-pins`, even when no worker is admitted.
For SEV-SNP workers, save this as `empty-nodes.json`:

```json
{"schema_version":"1","tee":"sev-snp","measurements":[]}
```

Use `"tdx"` for TDX workers. This is the worker family; the Trust Authority VM may use a
different TEE. The empty form requires `--ha-endpoint`; a standalone Trust Authority
requires initial node pins.

1. Generate the Trust Authority configuration with `--node-pins empty-nodes.json` and one
   `--ha-endpoint`. Boot that measured Trust Authority with a reachable chain store; for a
   disposable bootstrap test, `--ha-store-memory` supplies the store.
2. Run `c8s ta ha genesis` with the generated `ta-pin.json`. Genesis establishes
   the chain and accepted Trust Authority build; it admits no workers.
3. Create the worker document with that Trust Authority pin and the genesis entry in
   `ta.chain`. Run [`c8s ta ha accept-node`](launch-configuration.md#admitting-a-worker-document)
   with the document and worker image measurements. The signed entry admits
   that image bound to the document's exact digest.
4. Launch the worker with that document. Until its admission commits, Trust Authority
   refuses its node certificate and attested inventory callbacks. Changing the
   document requires another admission.

## The chain

An entry is a signed body: `{v, cluster, seq, prev, type, payload}`.
- The body is signed with `operatorauth.SignDetached`.
- An entry's hash is `SHA-256("c8s-cds-chain-entry-v1\x00" || body)`, where `\x00` is one zero byte and `body` is the exact signed body. The signature is excluded.

Entry types:

| type | payload | signed by |
|---|---|---|
| `genesis` | endpoints, one member key per slot, operator keys, the mesh CA public key, the accepted builds | an operator key of the launch file |
| `policy` | a whole canonical allowlist | an operator key |
| `routes` | the route manifest in the router's envelope | an operator key |
| `accepted` | the whole set of accepted Trust Authority builds (pin + version); every pin binds the one launch file | an operator key |
| `operator-keys` | the new writer keys | a current operator key |
| `member` | slot → member key | a current member key (written by a giver at handoff) or an operator key |
| `nodes` | the whole set of node images the Trust Authority certifies (a measurements document); every entry binds a launch | an operator key |

Notes on the rules:
- All accepted builds use the same TEE family and Trust Authority launch file. Each pin
  includes that family's required guest registers; TDX pins need RTMR[1] and
  RTMR[2] ([image pins](measurements.md)).
- Raising the build floor means writing an `accepted` set without the old builds. `c8s ta ha raise-floor` does that.
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

Retry an uncertain write by posting the same signed entry, body and signature,
to `POST /ha/entries`. If the replica holds that exact entry, it appends nothing
and does not reapply the payload. It runs a fresh gossip round as in step 5 and
returns the original entry's head, even when later entries exist; the old policy
does not become active again.

Overlapping retries of the same body and signature share one in-progress round.
Every caller still checks the store and serving state; completed rounds are not
cached for later retries. Cancelling the request that started the round can leave
its waiters unconfirmed; they retry the unchanged entry.

A newly signed copy of the same body has the same entry hash but is not an exact
retry and is refused (409). An exact retry remains valid after its signing key is
retired, because the held entry was verified under the authority at its original
position. The replica must still be serving. Seeing the entry in a chain read
alone does not establish confirmation.

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
2. `c8s ta ha genesis` collects every pending replica's member key and the first replica's CA key, signs entry 0 and posts it.
3. That replica writes entry 0 create-if-absent once the store answers.
4. The other replicas join by handoff. A replica whose store already holds a chain is no genesis candidate.

A giver hands the keys to a replica that answers "pending" at a slot's endpoint:
1. It checks the joiner's attestation against the builds accepted at its head.
2. It writes the `member` entry, which must be done.
3. It checks the joiner again, with a new attested connection, under the builds accepted at the new head.
4. It sends the chain, the CA key, any dropped branches and the store credential.

A giver whose own build is no longer accepted still gives (U1). A halted replica gives nothing.

## Fork recovery

Two entries at one seq halt the replicas that see both. `c8s ta ha resolve --seq S --keep H --endpoints ...`:
- reads every replica's status;
- refuses if a replica does not answer, unless it is named with `--assume-lost`, which needs `--lost-head`: the highest seq the lost replica may have held;
- refuses if a replica on the dropped side answered a write done at or after S;
- refuses if the dropped entry is the CLI's acknowledged head.

Each replica then drops the other branch. A replica holding the kept entry writes it over the store. A replica that held the dropped entry serves again only once it holds the kept one, from the store or a peer: the kept entry may be a done write.

A replica reports a fork at the first seq where it found two entries, which can be above the seq where the branches split. When a replica is still halted after the resolve, the command names the seq to resolve next.

Once the set serves again (it waits up to `--settle-timeout`, 30 s), the command writes the kept chain's allowlist again as a policy entry, above every head a replica held before the resolve and above `--lost-head`.
A node that pulled a dropped branch's allowlist then sees a higher version and fetches the kept one.
If the kept chain has no policy entry, the command says so; write the allowlist with `c8s allowlist`.

Every done write prints `confirmed head N (hash)`: Trust Authority confirmed the entry at N. A `submit-policy` retry can confirm an entry that later entries already follow, so N is not always the chain's newest head; `status` shows that.

## What nodes pin

A worker document names `ta.chain: "<seq>:<hash>"` ([launch-configuration.md](launch-configuration.md)): the genesis, or a later entry as a reboot floor. nri-image-policy then:
1. reads the chain (the entries verify by signature);
2. requires the pinned entry and a chain that extends what it verified before;
3. confirms the head over attested TLS with a replica of a build accepted at that head;
4. when the accepted builds change, rewrites in place the Trust Authority pins its own clients load and the copy its pods mount, moves its allowlist pull to them, and hands them to its sandbox-digests endpoint. The chain counts as followed only once all of this is done, so a failed step is retried at the next pull.

nri-image-policy holds the chain in memory, so after a restart it reads the chain again from genesis. On a long chain the first follow can take a while. Each chain request has the pull timeout; the whole read has none. Until the read finishes, the node uses its launch pins. Checkpoints that let a node start from a later entry are follow-up work.

Every Trust Authority client of the node sends the pin in the `c8s-cds-pin` header. A replica names the pin back only when its chain holds that entry. A client refuses any other answer, so a set re-rooted under the same measurement is refused.
The clients that do this: get-cert, the sidecars, allowlist-proxy, ta-attest and nri-image-policy.

## Operator CLI (`c8s ta ha`)

| command | does |
|---|---|
| `status` | every replica's status |
| `genesis --cluster --version` | signs entry 0 (`--image-policy-file` pins the replicas and is the first accepted build) |
| `prepare-policy --cluster --genesis --expect-head --file --policy-sha256 --out` | signs a reviewed canonical policy into a new native entry file without submitting it |
| `verify-policy --cluster --genesis --expect-head --file --policy-sha256` | checks a signed successor against the reviewed policy digest and current attested head without submitting it |
| `submit-policy --cluster --genesis --expect-head --file` | submits a prepared policy entry unchanged, without an operator private key |
| `observe-policy --cluster --genesis --expect-head --file` | verifies held policy confirmation and saves the confirmed head without submitting the entry |
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
- The CLI records, per cluster (`--state-dir`, default `c8s/ta-ha` in the user config directory), the genesis and its highest acknowledged confirmed head. It refuses a replica serving a chain without that head, or of another genesis. Without a record, writes require a genesis signed by `--operator-key` or explicitly pinned with `--genesis <hash>`.
- A write that may have been applied exits 3, as does a `c8s allowlist` write to a single Trust Authority that no answer confirmed. A genesis no answer confirmed exits 3 too and names its hash: once `c8s ta ha status` shows the replicas hold it, pass that hash as `--genesis`. One applied write exits 1 instead: Trust Authority confirmed it, but the local record names another genesis, or another hash at the same seq. The error says so; check `c8s ta ha status` for a fork.
- A successful CLI write syncs its acknowledged-head record, the state directory and that directory's parent before printing success. Before submitting a write, it creates the state directory if needed, creates and removes a file in it, and syncs it, so an unusable `--state-dir` refuses without submitting. Endpoint selection and genesis discovery can read replica status before this check. `genesis` also reads the cluster's record first and refuses one of another genesis. Concurrent commands retain the highest acknowledged head; retrying an equal or older head persists that record again. If Trust Authority accepts a write but the local record is not saved, the command exits 3 and names the accepted head. The new record may already be visible despite that error.
- Keep `--state-dir` on persistent, trusted local storage that supports file and directory sync. Its path must remain stable during use. The CLI needs read and write access to the state directory and read access to every physical ancestor through the filesystem root. Each directory must support sync. On preparation and every record save, it syncs this directory chain even when it already exists, including directories left by an interrupted or failed attempt. Symlinks and their lexical parent directories must already be durable. The `.chain` cache remains best effort; it does not replace the acknowledged-head record.

### Prepare a reviewed policy

Review the canonical allowlist file and obtain its SHA-256 independently of the
preparation command. Supply the intended cluster, trusted genesis and expected
predecessor independently too. Replace the uppercase placeholders:

```sh
c8s ta ha prepare-policy \
  --url https://TA_HOST:PORT --image-policy-file ta-pin.json \
  --state-dir durable-state --cluster CLUSTER --genesis GENESIS_HASH \
  --expect-head SEQ:HEAD_HASH --operator-key operator.pem \
  --file canonical-policy.json --policy-sha256 POLICY_SHA256 \
  --out policy.entry.json
```

The command requires attested HTTPS under the supplied Trust Authority pins and refuses
`--insecure`. It checks the target, expected head and remembered acknowledged
floor before establishing a genesis record or updating its verified-chain
cache. An explicit genesis remains binding when a record already exists.

The file must already contain canonical allowlist bytes, with no trailing
newline, and be at most 1 MiB. `c8s allowlist export <file>` writes the
allowlist Trust Authority serves in that form: compact JSON of the normalized document. No
command rewrites an edited file into it, so re-serialize an edited file the same
way before computing its SHA-256. Preparation rejects a hash mismatch or
noncanonical input and preserves the exact checked bytes in the policy payload.
It refuses an existing output path, or one in a missing directory, before it
contacts Trust Authority. It validates the authorized signature and entry against the
verified predecessor, then creates a mode-0600 file containing the native `body`
and `sig`, and syncs it before reporting success.

Signing authorizes the entry at that position. Preparation does not submit it,
acknowledge its head, cache it as accepted policy or reserve its sequence. If
another entry takes that position, prepare a replacement with a new expected
head and output path; the original artifact stays unchanged.

### Verify a signed successor before publication

Check the signed artifact against the independently reviewed policy hash and the
head it is meant to extend:

```sh
c8s ta ha verify-policy \
  --url https://TA_HOST:PORT --image-policy-file ta-pin.json \
  --state-dir durable-state --cluster CLUSTER --genesis GENESIS_HASH \
  --expect-head SEQ:HEAD_HASH --file policy.entry.json \
  --policy-sha256 REVIEWED_CANONICAL_ALLOWLIST_SHA256
```

The command verifies the native signature, canonical policy bytes and saved
acknowledged floor, then requires fresh, serving status at exactly that
predecessor. It returns the full artifact hash, the candidate allowlist hash,
the predecessor and the proposed entry head.
`current_entries` contains the latest held `policy` and `routes` entries, with
their exact bodies and signatures. A missing type has no entry in the verified
log; `{}` identifies a bootstrap log without either type. These entries describe
the held predecessor and do not establish confirmation. An already-held candidate is refused;
use observation for accepted history. Validation sends only GETs, loads no
operator key and leaves the artifact, records and cache unchanged.

This does not confirm the predecessor or candidate, reserve a position, or prove
Git review or application readiness. Deployment tooling must independently check
the accepted Git baseline and phase gates. Another write can invalidate the
successor after validation. An absent local record is first use; callers must
detect and recover lost established state. ConfigMap size and byte round-trip
checks belong to publication. Any failed validation withholds JSON and exits 1.

### Submit a prepared policy

Transfer the reviewed entry file to the delivery machine. Supply the cluster,
trusted genesis, Trust Authority image pins and original predecessor independently of that
file. The delivery machine needs no operator private key:

```sh
c8s ta ha submit-policy \
  --url https://TA_HOST:PORT --image-policy-file ta-pin.json \
  --state-dir durable-state --cluster CLUSTER --genesis GENESIS_HASH \
  --expect-head SEQ:HEAD_HASH --file policy.entry.json
```

Submission verifies the policy log, the recorded acknowledged-head floor and the
entry's signature under the operator keys at its predecessor. It requires
attested HTTPS and sends the file's exact bytes without rewriting or signing.
It leaves the input file and verified-chain cache unchanged.

An exact retry is allowed after later policies or operator-key rotation. Keep
`--expect-head` at the artifact's original predecessor. Finding the entry in the
log does not establish success: Trust Authority must freshly confirm that entry, and the CLI
must persist its acknowledgement. A retry confirms the original entry; it does
not make that policy current again or lower a newer local acknowledgement.

After exit 3, retain the artifact and rerun the same submission to establish
confirmation. A refused retry does not undo an earlier acceptance. If another
entry occupies the position, an operator must review and prepare a replacement
against the new head; submission never rebases the artifact.

### Observe a policy delivered by another writer

After ConfigMap consumption or manual delivery, check the unchanged artifact:

```sh
c8s ta ha observe-policy \
  --url https://TA_HOST:PORT --image-policy-file ta-pin.json \
  --state-dir durable-state --cluster CLUSTER --genesis GENESIS_HASH \
  --expect-head SEQ:HEAD_HASH --file policy.entry.json
```

The independent pins and predecessor have the same meaning as for submission.
Observation sends only reads and needs no operator key. It verifies exact body
and signature membership, then requires a fresh, serving replica to report a
matching held head and recorded confirmation of the entry or a descendant.
With `--endpoints`, it checks replicas in order until one supplies a verified
confirmation. Each attempt verifies the log and status from the same endpoint.
It saves that confirmation before printing JSON. `entry` identifies the artifact,
`confirmed` its confirming head, and `held` the observed head. `current` says
whether the artifact still supplies policy; `policy` identifies the policy entry
at `held`, and `policy_sha256` hashes its canonical allowlist bytes.
A newer held head need not be confirmed. These results
prove neither Git publication nor application readiness.

Missing confirmation, a changed head or a failed local save exits 3 without
success output. Retry observation. Replica restart can lose confirmation records;
the consumer or explicit manual submission must confirm again. Observation never
submits automatically. Keep `--state-dir` on durable storage: an absent record is
treated as first use, so callers must detect and recover lost established state.

## Deployment and upgrades

- Replicas must reach the node network: at issuance a replica dials the requesting node's sandbox-digests endpoint on port 1019.
- Routers and nodes reach the set through one endpoint name. Put the replicas behind DNS with a short TTL (for example 60 s) or a health-checked load balancer, and take a dead replica out of the name.
- A set of more than one replica serves no secrets and keeps no sandbox ledger (see Secrets).

Upgrade the Trust Authority build in this order:
1. `accept-image` the new build.
2. Roll the replicas to it, one at a time.
3. Render the operator and system objects again: the operator first, the system objects only once a node with the new image exists.
4. Replace the nodes.
5. `raise-floor` to evict the old build.

After a `raise-floor`, a new worker needs a fresh worker document: an old one pins the evicted Trust Authority build, and `accept-node` refuses it.

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
- Pod clients (get-cert, the sidecars, allowlist-proxy, ta-attest routing) read the node's Trust Authority pins on every TLS handshake, so a long-running one keeps reaching Trust Authority after the replica set moves to a new build. A pin file that does not parse, mid-rewrite, fails that one handshake; the next one reads it again.
- v1 never prunes the chain. Each entry is one ConfigMap in the cluster's etcd, and a re-seed after a wipe takes time linear in its length.

## Secrets

Secrets and the sandbox ledger are served only by a single replica. Its secret
endpoints are mounted even with empty initial nodes; workload release still
requires an admitted inventory and the usual [authorization checks](secrets.md#what-the-ta-checks).
A set of more than one replica refuses secrets.
