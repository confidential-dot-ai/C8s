# Secret release

A secret is a value CDS keeps in its own memory, addressed by a store path. CDS
— the Certificate Distribution Service, the one in-cluster pod that verifies TEE
evidence, signs the certificate each pod run gets, and holds C8s policy —
releases it only to a pod whose containers match a workload entry whose grant
covers that path. A workload entry is one named set of container images with the
command, mounts, and environment each may run; its grant lists the store paths
that entry may read or write. Both are allowlist policy: fields in
[allowlist-entries.md](allowlist-entries.md), steps in
[workloads.md](workloads.md), names in [glossary.md](glossary.md). A secret is
not a Kubernetes Secret: nothing is written to the API server.

## When it is served

CDS serves the secrets endpoint only when it can establish what a pod runs. It
needs its own `--armtls-platform` (the chart's `cds.armtlsPlatform`, which
`c8s install --hardware-platform` sets), `--measurements`, and node addresses
bounding its callback to a node's admission inventory — the node service that
records which containers each pod has run (`--sandbox-inventory-cidr`, or host
routes from the live node list). Miss one and CDS logs a warning naming it and
serves nothing, so a pod asking for a secret retries until that is fixed. Where
the operator has no node inventory at all, such a pod is refused at admission.

Release is gated on a `secrets` grant in the workload entry. An entry without
one releases nothing, so writing the grant is what turns release on; it is
operator-signed policy and takes effect without a restart —
[allowlist-and-capabilities.md](allowlist-and-capabilities.md).

The store is bounded per entry (`--secrets-max-paths-per-workload`, default 64)
and overall (`--secrets-max-paths`, default 1024); the chart sets both. One
value is bounded by `--secrets-max-value-bytes`, default 4096 and never below
32, which the chart leaves unset. An operator-written path counts against the
store bound only, never against an entry's. A path bound refuses the write and
evicts nothing — a path holds the only copy of its value — and names the bound
that stopped it. Raising one needs a restart, which empties the store — see
[Restarts](#restarts).

## What CDS checks

Every request carries three things: the pod's leaf, the short-lived certificate
CDS issued for this pod run with its sandbox ID — the identifier of that one run
— stamped in; a single-use challenge CDS issued for this request; and a fresh
sandbox token, the admission inventory's signed statement binding the pod's key
and that challenge to that sandbox ([armtls.md](armtls.md#sandbox-identity)). A
release therefore binds to one caller. CDS then checks, in order:

1. The TLS stack verifies that the client certificate chains to the mesh CA, the
   CA CDS generates in its own memory and signs pod certificates with. A
   self-issued certificate is not enough here: its sandbox ID is peer-chosen.
2. The sandbox ID comes from that verified certificate.
3. The sandbox token verifies against the inventory CDS bound to that sandbox at
   certificate issuance — so nothing else answering on the inventory port can
   vouch for it — carries this request's challenge, and names the same sandbox.
4. That inventory reports what the sandbox has run.
5. The reported set, minus the containers C8s injects, matches exactly one
   workload entry — whole-entry matching, not membership, and the rule itself is
   in [allowlist-and-capabilities.md](allowlist-and-capabilities.md).
6. That entry's grant covers the requested path.

Any failure refuses: an unreachable inventory, an unknown sandbox, an empty
container set, an ambiguous match, an entry with no grant. The client learns
only that it was refused; the reason goes to the CDS log. An ungranted path
answers `404`, as one holding nothing does, so the API cannot enumerate it.

The containers C8s injects are the sidecars the pod-injector webhook adds to
every confidential pod ([Fixed sidecar mounts](#fixed-sidecar-mounts)). They are
dropped before matching, so an entry never enumerates them. One is dropped only
when the node that admitted it reports a platform role, and only the node's base
allowlist — the entries it holds itself, not any CDS serves — binds one: to an
injected invocation together with the exact mount table the webhook gives it,
and to the mesh endpoint together with the webhook's arguments and credential
volume. A pod's own container running an injected invocation with mounts of its
own holds no role, stays in the match, and blocks a release the entry does not
admit it for.

The grant belongs to the entry, not to a container, because the released file
lands on a volume every container in the pod can read. An entry holding a grant
must therefore pin every container's command line and mounts: left loose, the
host could change what a container runs and the pod would still match the entry
that holds the grant — [allowlist-entries.md](allowlist-entries.md). Where the
file lands inside the pod is not policy; only the store path is.

## The file appears after your container starts

CDS releases only once every main container is running, because that is when the
sandbox matches a whole workload entry. The fetcher is therefore a sidecar: it
starts alongside the workload, is refused while the set is incomplete, and
writes when it completes. An init container would be asking before its siblings
exist and would deadlock the pod it gates. So a consumer waits for its file:

```sh
until [ -f /run/c8s/secrets/DB ]; do sleep 1; done
```

Retries back off from 5 to 30 seconds and never stop by default: a large image
pull can delay the main containers for many minutes.

The first pod to ask for a store path that holds no value has CDS generate one
there and then, provided the entry's grant covers that path for write, so no
caller ever chooses what another will later read. Under a read-only grant the
request answers `404` until an operator writes the value. Values CDS cannot
invent — an API token, a database password, a wrapped key — an operator writes
with `c8s secrets put`. A measurement pin proves only that the peer is an
attested build, and several instances can share one, so such a write also pins
the mesh CA you hold out of band: that is what tells your CDS from another at
the same measurement — [workloads.md](workloads.md).

## Fixed sidecar mounts

The C8s image's entry pins the sidecar mount tables; destinations are fixed:

| Mount | Destination | Mounted into |
|---|---|---|
| credential volume | `/etc/c8s/certs` | the injected containers only |
| secrets volume | `/run/c8s/secrets` | `c8s-secret` read-write, every other container read-only |
| discovery volume | `/run/c8s/discovery` | the injected containers that use it |

`confidential.ai/c8s-cert-dir`, `confidential.ai/c8s-secret-dir`, and
`confidential.ai/c8s-discovery-mount-path` are refused unless they name these.

The secrets volume is memory-backed. A pod may declare it only as a
memory-backed `emptyDir`, and may not use the `c8s-secret` container name at
all: a `hostPath` there would write a released value to host-visible storage.
For the same reason an ephemeral container may not mount C8s material or target
a container of an injected pod. The inventory socket directory
`/run/c8s/workload-claims` is a platform mount no entry rule names.

## What the inventory reports

The admission inventory answers with two views of one sandbox: `digests`, the
image digests that certificate issuance gates on, and `containers`, each
distinct launch — digest with its `argv`, environment evidence, and observed
mounts — which release matches against. Both omit duplicates. `argv` is the
effective command line a container ran, so release holds a sandbox to what its
images were told to do, not only to which images ran.

Mount evidence records each destination's class and storage, never the node
path. `mounts: []` means no bind mounts were seen; a missing or null field means
the evidence is unavailable, on which `exact` and `deny` mount policies fail
closed. Environment evidence is bounded, and a container whose share of it is
missing or evicted fails an `env: match` policy; recovery depends on the cause —
waiting until the node applies the policy version, or recreating the pod — and
`c8s secrets explain` names which applies.

`c8s secrets explain --sandbox <SANDBOX_ID>` reports the decision as CDS makes
it: what the inventory says is running, what was dropped, how each entry
measures against the rest, and why a container was rejected. It answers to the
operator key — the operator's signing key whose public half CDS pins for policy
writes — and never carries a value. The sandbox ID is on the pod's certificate,
and `c8s verify` prints it.

### The report is a high-water mark

Both views describe every container ever admitted in the sandbox, not those
running now. A live snapshot would let a pod hide a container at the moment it
is asked — kubelet removes and recreates one across a `CrashLoopBackOff` — and
so present a set it does not have: a victim entry's containers plus an extra
image that exits, the secret collected in that window and read when it restarts.
The cost is that a pod which ever ran an image outside its entry never receives
a secret, which is the correct direction for a release decision.

## Restarts

A CDS restart destroys every secret, and you must roll every workload that holds
one: the store is process memory and there is no persistence. For an entry with
a write grant the failure mode is worse than losing the values — a pod recreated
after the restart finds its path empty and is given a new value while its
siblings hold the old one, and nothing reports the split. A read-only consumer
instead stays refused until the value is written back.

Treat a released value as ephemeral for the life of the CDS process. The
sandbox-to-inventory bindings go with it, so a certificate that outlives a
restart has none until its next renewal and is refused meanwhile.
[operator.md](operator.md) lists everything else a restart drops.
