# Allowlist and capabilities

How C8s decides which container images may run, which commands they may run
with, and — for future key-management integration — which secret paths they may
read and write. This document complements [`armtls.md`](armtls.md) (how the allowlist is bound
into attestation).

> **Trust model.** The host, hypervisor, and Kubernetes control plane are
> untrusted; the trust boundary is the TEE. The image *reference* a pod presents
> (`docker.io/vllm/vllm-openai:v0.6.3`) is chosen by the untrusted host and is
> not bound to the bytes that run. The image *digest* is. So every trust decision
> in this design keys on the digest — the reference is a label for humans, never
> a lookup key.

## The model

The allowlist is a map of named **workload entries**. Each entry pins an
init/main container set. Every container binds a **digest** to the process
policy (`command`, `args`) permitted for those bytes, optionally to the
environment values it may launch with (`env`) and the bind mounts it may receive
(`mounts`), and the entry as a whole may carry a secret-store grant (`secrets`).
The entry name is operator-chosen; the entry `label` and per-container `image`
are informational. Policy is always resolved by container digest.

A **component entry** admits one of C8s's own images (the operator, CDS,
attestation-api, armtls-mesh, volumed, the router's nginx) with one container
per shape the chart renders it in: `command` `exact` at the image's entrypoint
or the container's command, `args` `exact` at the rest of the rendered argv,
and `mounts` `exact` at the rendered mount table. The C8s image's entry also
lists the sidecars the webhook injects (`get-cert`, `probe-file`, `get-secret`,
`get-volume`): `command` pinned to the invocation, `mounts` `exact`, and `args`
`any`, because the SAN and file paths are per pod. An image that may run
however it is invoked is an entry with `command` and `args` both `any`. Nothing
distinguishes either shape from any other entry: it is matched, stamped and
diffed like the rest, and the same digest may also appear elsewhere under a
narrower policy — see [union semantics](#a-digest-may-run-many-ways).

### Platform roles (`role`)

A container of the NRI plugin's measured base allowlist may carry `role` —
`mesh`, `credentials`, `router` or `acme` — which the enforcer grants to a
container whose verified identity matches that declaration. The field is
YAML-only, so no served document can claim a role.

One rule separates the two kinds of entry: a role entry pins the subcommand it
grants the role for, and the arguments and mounts that subcommand is fixed
with; an entry holding no role pins nothing. So a role is granted per
component, not per image, and the same image's other subcommands hold none.

The node's `mesh` policy binds each role to its reserved UID and the
destinations it dials; the router, which answers external traffic, is bound
instead to the namespace whose pods serve its ports and the ports it answers
on there, and `acme`, which proves control of the public names, to the ports a
pod of that namespace may reach outside the mesh in the clear. See
`docs/armtls.md`.

### Document shape

```json
{
  "schema": "c8s.allowlist/v1",
  "workloads": {
    "cds-3f2a9c8b1e2f": {
      "label": "ghcr.io/confidential-dot-ai/cds@sha256:<cds>",
      "initContainers": [],
      "containers": [
        {
          "digest":  "sha256:<cds>",
          "image":   "ghcr.io/confidential-dot-ai/cds@sha256:<cds>",
          "command": { "policy": "any" },
          "args":    { "policy": "any" }
        }
      ]
    },
    "vllm-llama": {
      "label": "docker.io/vllm/vllm-openai:v0.6.3",
      "initContainers": [],
      "containers": [
        {
          "digest": "sha256:<vllm>",
          "image":  "docker.io/vllm/vllm-openai:v0.6.3",
          "command": { "policy": "exact", "argv": ["python3"] },
          "args":    { "policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server", "--model", "/models/llama-3.1-8b"] }
        }
      ]
    }
  }
}
```

`schema` is the format identity. It is the first field of the canonical
serialization (`allowlist.Canonical`), so any holder of an equivalent document
reproduces the same bytes and pins the exact format. It also makes a malformed
or foreign body fail loud instead of parsing as an empty (and therefore deny-all
or, worse, allow-nothing-changed) allowlist.

#### Entry names

An entry name must match `[A-Za-z0-9][A-Za-z0-9._-]*` — it is used verbatim as a
URL path segment — and be at most **63 bytes**, the Kubernetes label-value
length, so the same string can also be a `confidential.ai/cw` selector value and
a matched-workload leaf stamp (`docs/armtls.md`).

The grammar is enforced everywhere. The 63-byte bound is enforced only where
entries are **written**: `PUT /allowlist`, `PUT /allowlist/workloads/{name}`,
and the CLI. A document *served* by CDS is parsed leniently, because the bound
was introduced after entries could already have been stored and one legacy name
must not fail the whole document for every puller in the cluster. An over-long
entry is dropped from a served parse with a warning: its digests stop being
admitted by that consumer (fail-closed), and it could never have been stamped on
a leaf in the first place.

**Migration.** An over-long entry created before the bound is still served by
CDS and still counts toward the document's canonical digest, but no pod can be
named for it and every consumer ignores it. Rename it — `c8s allowlist apply`
under a new name followed by a delete of the old one — and pods matching it start
getting named leaves. The lenient served parse is a compatibility measure for
one release; do not rely on it.

The grammar is slightly wider than what the injection webhook accepts for the
`confidential.ai/cw` label: `a-`, `a_` and `a.` are valid entry names but are
not valid label values. It is not tightened here, because that would
retroactively invalidate stored entries.

## Process policy: command and args

An image digest already pins the image's baked `ENTRYPOINT`/`CMD` — they are in
the OCI config the digest covers. So a process policy does not restate the
image's defaults; it constrains what a pod may **run** for those bytes. This
matters because an image with an overridable entrypoint can otherwise be pointed
at an arbitrary command — credential extraction, a reverse shell — while keeping
an allowlisted digest.

The two policy fields mirror the Kubernetes container fields an operator already
sets: `command` overrides the image `ENTRYPOINT`, `args` overrides `CMD`.

### What the enforcers see

The host NRI plugin gates container start and observes the container's
**effective argv**: the OCI
`process.args`, which is the already-merged result of the image config and any
pod-spec `command`/`args` override. They do not see the override as an override,
and they do not fetch the image config. Policy is matched against that effective
argv:

- **`command`** is matched as an exact **prefix** of the argv (it may be several
  tokens — `/docker-entrypoint.sh nginx`, `/bin/sh -c`, `python3`).
- **`args`** governs the **remainder** of the argv after the command prefix.

Each field is one of:

| policy  | `command` (a prefix)                     | `args` (the remainder)          |
|---------|------------------------------------------|---------------------------------|
| `exact` | argv must **start with** its `argv`      | the remainder must **equal** its `argv` |
| `any`   | no prefix constraint                     | the remainder is unconstrained  |
| `deny`  | the whole argv must be empty (see below) | there must be **no** remainder  |

So the boundary between the two is `len(command.argv)` when `command` is `exact`,
and `0` when it is `any` — which makes every combination well-defined: `command
exact + args any` pins the executable and lets flags vary; `command exact + args
exact` pins the whole argv; `args deny` means "no arguments beyond the command".

An exact command names bytes in the image, and that only holds while no mount
the pod chose covers them. So when `mounts` is `any`, a container is admitted
only if no non-platform mount sits at or above the pinned executable's absolute
path: a volume bound over `/c8s`, or over `/app` for `/app/c8s`, would run the
pod author's bytes under the pinned name. Under `deny` there is no such mount
and under `exact` the operator declared every mount, so neither is checked. A
relative executable is resolved by the container's `PATH`, which admission
cannot follow; pin an absolute path. The check runs wherever mounts are
observed: at the plugin's start-phase admission, which always observes them,
and at CDS matching.

An absent policy normalizes to `deny`, so a minimally specified container is
maximally restrictive. `command: deny` requires an empty argv and therefore can
never start (a workload that wants any argv should say `command: any`); `lint`
flags it. `derive` reads `command`/`args` off a pod spec and fills what the spec
leaves unset the way the runtime does: an unset command is the image's
`ENTRYPOINT`, and unset args are its `CMD` when the command is unset too. It
reads the image config with `crane`, as `inspect-image` does.

### A digest may run many ways

A single digest can appear under several containers — in one entry or across
entries — each with a different policy. Admission at the per-container gate is
the **union**: the container is admitted if its effective argv satisfies *some*
allowing container's command and args policy. This is deliberate. A shared base
image (busybox, a distroless runtime) is legitimately invoked with different
command lines by different workloads; the operator allowlists each invocation,
and any of them may run those bytes.

The precision this trades away: at the single-container gate the effective policy
for a digest is the union of every entry that lists it, because the host controls
which pod pairs a digest with which argv. `lint` surfaces this — it warns when one
entry widens a shared digest to `any`, because that becomes the effective
container-level policy for the digest everywhere. The narrower, entry-scoped
guarantee is recovered at [cert issuance](#where-its-enforced) — for an entry
that is distinguishable. An entry whose every container another entry admits
under any argv, and which that entry needs nothing more running for, is
**shadowed**: every pod it describes matches both, so it is never the unique
match and `lint`, `apply` and `add` refuse it. To tighten a seeded any-argv
entry, edit it; do not add a narrower entry for the same image beside it.

## Environment policy (`env`)

`env` constrains the complete OCI launch environment: `exact` requires
equality, so all names and values must match, including image defaults and
runtime additions. `deny` requires an observed empty environment; `any` permits
any environment. `match` requires exactly the listed variable names and applies
each variable’s matcher. Missing env evidence fails `exact`, `deny`, and `match`. An empty
`exact.values` normalizes to `deny`, and an absent policy defaults to `any`.

```json
"env": { "policy": "exact", "values": {"PATH": "/usr/bin:/bin", "MODEL_DIR": "/models"} }
```

```json
"env": { "policy": "match", "variables": {"MODE": {"exact": "production"}, "GPU_SERIAL": {"present": true}} }
```

Each variable requires exactly one matcher: `exact` pins its string value,
including `""`; `present: true` accepts any value, including empty. Missing or
additional variables are rejected. An empty `variables: {}` requires an observed
empty environment. The allowlisted program and its dependencies must be safe for
every possible value of a variable matched with `present`. `lint` rejects
`present` on `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
`GLIBC_TUNABLES`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONHOME`,
`PYTHONSTARTUP`, `NODE_PATH`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`,
`_JAVA_OPTIONS`, `PERL5LIB`, `PERL5OPT`, `RUBYLIB` and `RUBYOPT`, because the
host would choose what code is loaded. The list is not exhaustive: check what
else your program's runtime reads from its environment.

Supply these policies per container through `c8s allowlist derive --env-file`.
The NRI plugin enforces env after cumulative NRI adjustments. The admission
inventory carries the complete environment digest for CDS workload matching and
secret release, plus per-variable digests bound to their names for images a
`match` policy lists ([bounds](secrets.md#what-the-inventory-reports)). Names
are visible; raw values are omitted, but digests allow guessing low-entropy
values. The node omits per-variable evidence for environments over 128
variables or 4 KiB of names, so `derive`, `lint` and `apply` reject a `match`
policy past either limit; set `enableServiceLinks: false` on pods that use
`match`. Deferred CDI edits leave env and
mount evidence unavailable, so constrained policies reject those launches.

Consumers that predate `match` reject the whole allowlist when it contains one,
and nodes that predate it report no per-variable evidence. To start using
`match`:

1. Upgrade CDS, the node images and every other allowlist consumer.
2. Add the `match` policies.
3. Wait until every node that runs the affected pods has applied the published
   version: its plugin logs `pull loop: allowlist refreshed` or, when it
   started after publication, `initial allowlist pulled from CDS`, with a
   version at or above the one `c8s allowlist list` reports
   ([refresh](#refresh-and-anti-rollback)). A pod recreated earlier is admitted
   against the old policy.
4. Recreate the affected pods. Restarting their containers is not enough: the
   sandbox's admission history keeps the records from the old node software.

A workload's containers of `match`-listed images may together need at most
512 KiB of per-variable evidence, about 40 containers at both limits. Restarts
with new environments are not covered
([bounds](secrets.md#what-the-inventory-reports)).

## Mount policy (`mounts`)

`mounts` constrains bind mounts in the final OCI specification. The node
classifies each source rather than trusting the destination alone: a hostPath,
an `emptyDir`, and a ConfigMap can all be placed at the same destination while
carrying very different authority over the container.

An absent policy is `deny`, which permits only the platform mounts defined by
the C8s NRI plugin in the node image. The plugin checks both destination and
source ownership against this baseline:

| Destination | Required source |
| --- | --- |
| `/etc/hosts` | The current pod's kubelet `etc-hosts` file. |
| `/etc/hostname`, `/etc/resolv.conf`, `/dev/shm` | The current sandbox's corresponding containerd file or directory under the standard containerd or RKE2 root/state directories. |
| `/dev/termination-log` | A file in the current pod and container's kubelet `containers` directory. |
| `/var/run/secrets/kubernetes.io/serviceaccount` | The current pod's kubelet projected volume named `kube-api-access-*`. |

These mounts are also permitted implicitly by `exact`. A matching destination
alone does not establish platform ownership. `any` leaves mounts unconstrained;
`exact` requires the observed non-platform set to equal its concrete rules:

```json
"mounts": {
  "policy": "exact",
  "rules": [
    {"destination": "/var/cache/app", "kind": "emptyDir"},
    {"destination": "/mnt/c8s-data/config", "kind": "data"}
  ]
}
```

When deriving an entry, `--mounts=any|deny` applies one policy to every
container it derives:

```sh
c8s allowlist derive app pod.json --env=any --mounts=any > entry.json
```

`--mounts-file` takes explicit per-container policies instead: the file maps
container names to policies and must include every init and main container the
entry declares; missing or unknown names are rejected. `derive` drops C8s's own
injected containers from its input and names them on stderr, so a pod read back
after admission derives the same entry as the manifest it was admitted from. For
a pod with an init container named `seed` and main containers named `frontend`
and `worker`, save this as `mounts.json`:

```json
{
  "seed": {"policy": "deny"},
  "frontend": {
    "policy": "exact",
    "rules": [
      {"destination": "/var/cache/app", "kind": "emptyDir"},
      {"destination": "/mnt/c8s-data/config", "kind": "data"}
    ]
  },
  "worker": {"policy": "deny"}
}
```

```sh
c8s allowlist derive app pod.json --env=any --mounts-file mounts.json > entry.json
```

Here `pod.json` contains the Kubernetes object with digest-pinned images and
explicit command/args. Choose the policies to match the workload's actual
mounts; the pod spec alone cannot establish source class or storage protection.
Omitting both flags leaves each container's mount policy at `deny`.

Lint includes mount rules when checking whether workload entries are
indistinguishable. It also rejects exact `PATH`, `LD_LIBRARY_PATH`, `PYTHONPATH`,
or `NODE_PATH` values whose search directories overlap a declared `data` mount:
those directories could load mounted content as code. The deprecated
`lint --cvm-mode` flag has no effect; NRI observes both environment and mounts.

A `host` rule pins an exact source path and mount-level access mode:

```json
{"destination":"/config","kind":"host","source":"/etc/service","readOnly":true}
```

The source is the clean absolute path in the final OCI specification, after
containerd resolves symlinks. An omitted `readOnly` requires a writable mount.
Host evidence carries a SHA-256 source commitment and the access mode through
inventory and release matching. Host-backed workloads remain host-dependent;
the path pin grants access to the contents at that node path. Read-only mode
applies to the mount itself; nested mounts retain their own flags. Recursive
read-only/write mount options leave the host source commitment unavailable.

A read-only host **file** from the node image can use mount kind
`nodeRootFile` instead of `host`, so it is not treated as operator-supplied
executable content:

```json
{"destination":"/usr/bin/nvidia-smi","kind":"nodeRootFile","source":"/usr/bin/nvidia-smi","readOnly":true}
```

A `nodeRootFile` rule takes the same `source` and requires `readOnly: true`.
The bind it admits must carry node-root provenance: a regular file reached
directly through the node's read-only dm-verity root. The enforcer opens the source without symlinks or
intervening mounts, checks the active kernel table for a single strict read-only
dm-verity target, and compares its SHA-256 root hash with `roothash=` in the
measured boot command line. Writable overlays, foreign verity devices, bind
aliases, directories and missing evidence do not qualify.

The node image must meet this precondition:

- `/` is mounted read-only directly from one dm-verity device, with no overlay
  over it. State overlays on other directories are fine, but files under an
  overlaid or separately mounted directory never qualify.
- The kernel command line carries exactly one `roothash=` for that device.
  `usrhash=` and a verity `/usr` alone do not count.
- The verity table is a single `verity` target over the whole device, hashed
  with SHA-256. Its optional parameters are limited to
  `restart_on_corruption`, `panic_on_corruption`, `restart_on_error`,
  `panic_on_error`, `ignore_zero_blocks` and `try_verify_in_tasklet`. Forward
  error correction (`veritysetup --fec-device`), `ignore_corruption`,
  `check_at_most_once` and any other option leave provenance unavailable.

A node that fails the precondition denies every `nodeRootFile` rule. With the
allowlist enabled, the enforcer logs `node-root provenance unavailable` at
startup, as a warning when the command line declares `roothash=`. A denied
launch of an image with a `nodeRootFile` rule logs `node_root_unavailable` with
the node-wide cause, or, on a measured root, a reason saying the source is not
a plain read-only bind of a regular file on that root. The C8s node
image meets the precondition, and `make test-node-guest-image-immutable-root`
checks that its initrd opens the root device without extra verity options. The approved node launch measurement authenticates the image,
including its kernel command line and root hash; no separate file hash is needed.
Customer verification must approve that measurement. A dev image or an unchecked
measurement does not become trustworthy merely because it uses dm-verity.

Blocking adjustment validation checks provenance before creation, and the
persisted launch is checked again. Provenance travels with the mount evidence
through inventory, admission history and CDS workload matching, so `nodeRootFile`
bytes are bound to the attested node image.

Lint permits `nodeRootFile` rules on `PATH` and loader search paths. Host rules
and data mounts retain search-path rejection. Source, destination and
access-mode constraints still apply. Use `allowlist derive --mounts-file` to
supply the rules. This covers the measured NVIDIA files in [issue #868](https://github.com/confidential-dot-ai/C8s/issues/868) without a
blanket NVIDIA exemption or lint bypass.

Provenance requires a plain bind mount (`bind` type or a `bind`/`rbind` option,
with only access and propagation flags). Any other mount type or option, such
as an overlay naming the verified file with another `lowerdir`, gets no
provenance. The sandbox policy (`policy.sandbox`) exempts a bind from the
host-bind check only when an allowlist entry admits the container under an
`exact` mount policy whose `nodeRootFile` rule names that destination and
source. That entry can be CDS-served. Every other bind stays a host bind,
including a measured file under mount policy `any`, under a `host` rule, or
with the allowlist disabled. A read-only `nodeRootFile` rule does not stop an
entry from carrying a secrets grant; a `host` rule does (see
[Secrets](secrets.md)).

The reserved `verityDigest` field is rejected as not supported on every kind. This exception is scoped to read-only regular files.
It does not implement whole-volume provenance, arbitrary dm-verity volume trust,
directory mounts, IMA/IPE policy, dependency approval, or a general prohibition
on interpreters reading executable scripts from data. Keep exact env/mount
policies and review arguments and dependencies. Existing permissive policies
retain their behavior.

Upgrade CDS/CLI consumers and every node enforcer before publishing
`nodeRootFile` rules. An enforcer that has not been upgraded does not know the
kind, so it refuses the served document and keeps its last good policy; it
never applies the rule as a plain host rule. Baked enforcers require a
node-image rebuild.

The pod UID embedded in a kubelet source must equal the pod being admitted, and
containerd sandbox sources must name its exact sandbox. These runtime IDs prove
local ownership only and are not serialized into the stable allowlist.

| Observed source | Class | Storage | `exact` behavior |
|---|---|---|---|
| Node-created platform mount at its fixed destination | `platform` | not relevant | admitted without a rule |
| The node inventory's socket directory, bind-mounted read-only by the node policy itself into an injected pod's socket consumers | `platform` | not relevant | admitted without a rule |
| Current pod's `emptyDir` on tmpfs | `emptyDir` | `memory` | requires a matching `emptyDir` rule |
| Current pod's `emptyDir` whose backing chain reaches encrypted boot scratch | `emptyDir` | `encrypted` | requires a matching `emptyDir` rule |
| Another pod's `emptyDir` | `host` | `unknown` | requires an explicit host rule |
| Mapping merely named `scratch` | `emptyDir` | `unknown` | denied |
| Missing or inconsistent scratch evidence | `emptyDir` | `unknown` | denied |
| Plain disk-backed `emptyDir` | `emptyDir` | `unknown` | denied |
| ConfigMap, Secret, projected, PVC, CSI, local data, or a subpath | `data` | observed | requires a matching `data` rule under `/mnt/c8s-data/` and memory or encrypted storage |
| Reserved `c8s-volume-*` placeholder or propagated volume | `data` | observed | requires the same `data` rule, including before volume propagation |
| Host path | `host` | `unknown` | requires a matching source, destination, and read-only mode |

The Linux observer resolves tmpfs directly. For disk storage it resolves the
containing mount and walks the device-mapper slave graph. A writable overlay
mounted at a directory the measured image declares in `/usr/lib/confai/state.d`
is the initrd's state overlay, whose upper layer lives on the boot scratch
mapping; the observer proves that mapping from sysfs, because the upper
directory the initrd recorded belongs to a mount namespace `switch_root`
discarded. Any other overlay is followed to its upper directory. The current
scratch contract requires the exact `scratch` mapper, a crypt device UUID, and
ancestry reaching the virtio device with serial `confai-scratch`. The serial or
mapper name alone is never proof.

### Storage on the measured node image

The kubelet keeps pod volumes under `/var/lib/kubelet/pods`, inside the `/var`
state overlay, whose upper layer is the encrypted boot scratch. So on the
measured node image a ConfigMap volume and a disk-backed `emptyDir` observe as
`encrypted`, while a Secret, projected or downward-API volume and a
`medium: Memory` `emptyDir` observe as `memory`. Both satisfy `emptyDir` and
`data` rules. A node without encrypted scratch (a GKE or AKS node, or a kind
node) observes ConfigMap and disk-backed volumes as `unknown`, so the chart
backs every component volume with tmpfs: `medium: Memory` `emptyDir`s, and
its ConfigMaps as projected volumes. Its component entries then hold on any
node.

The baked local-path provisioner creates `hostPath` persistent volumes under
`/var/lib/local-path-provisioner`. Their bytes sit on the same encrypted
overlay, but the container's mount source is the volume's host path, not the
pod's volume directory, so it observes as `host` with a per-claim source no
rule can name. A CSI volume (a GCE PD, an Azure Disk, an EBS volume) is its
own block device, so it observes as `unknown`. A component entry therefore
cannot admit `cds.persistence` on any supported node, and the chart refuses
`cds.persistence.enabled=true` unless the image policy runs in `audit` mode.
The chart's defaults use no persistent volume.

On the measured image this holds even though the bytes are encrypted: CDS's
entry pins `/mnt/c8s-data/cds` with an exact `data` rule, and a local-path
volume observes as `host`, so the rule refuses it by kind before storage is
considered. CDS's store is therefore a memory `emptyDir`, and every new CDS
pod starts with an empty store beside the image's seed layer (see
[Bootstrap](#bootstrap)) and its version counter reset. Each
node's plugin keeps the highest version it applied (see
[Refresh and anti-rollback](#refresh-and-anti-rollback)), so after a CDS
restart a plugin that had applied version N ignores the restarted CDS's
versions up to N: it keeps enforcing its last policy, operator-added entries
included, and takes no new write until CDS counts past N or the plugin itself
restarts. Re-applying the operator's entries after the restart both restores
them in CDS and advances the counter.

The initrd that creates scratch and generates its random in-memory key is part
of the measured node image. Before RKE2 starts, `scratch-enforce` verifies the
crypt mapping and backing device and writes a record tied to the current boot ID
and device number under `/run/c8s`. NRI requires that record as well as the live
backing chain. Fresh key creation remains an attested-initrd property; failure
to establish any runtime evidence remains `unknown` and is denied.


## Secret grants (`secrets`)

An entry may grant secret-store paths to the workload it names. The subject is
the **entry**, not a container — see [`secrets.md`](secrets.md) for the model and
for what the admission inventory contributes to a release decision.

```json
"secrets": { "policy": "allow", "read": ["/tenant-a/**"], "write": ["/tenant-a/session"] }
```

- `allow` or `deny` only; there is deliberately no `any`.
- An `allow` grant requires every container to pin its argv (`command` and
  `args` `exact` or `deny`) and its mounts (`deny`, or `exact` with no `host`
  rule). The write path refuses the entry; release refuses one stored earlier.
- `write` requires `read`.
- Paths are absolute and clean (no `.`/`..`); the only wildcard is a trailing
  `/**` (subtree), which matches strictly beneath its base.
- A grant that releases nothing is omitted from the canonical document, so an
  entry without one serializes exactly as it did before the field existed.

CDS enforces this grant at `GET`/`POST /secrets/*`. Writing a grant is what
turns release on: an entry without one releases nothing
([`secrets.md`](secrets.md#when-it-is-served)). An operator supplying a value at
`PUT /secrets/*` is authorized by the operator key instead
([`secrets.md`](secrets.md#operator-supplied-values)).

Filesystem location is not an authorization boundary — a workload owns its own
filesystem once a value is inside it — so a grant names store paths only. An
install still setting the per-container `paths` field needs
[`secrets.md`](secrets.md#upgrading).

## Declared exits (`egress`)

A pod in the mesh sends TCP out of the pod only through its mesh endpoint,
to the cluster resolver, or to its node's CDS (which serves the allowlist and
the other public routes without authentication). An entry may declare
`egress`: up to 8 exits, each a CIDR range and one TCP port, that a pod this
entry matches reaches directly, uncaptured.

```json
"otel-collector": {
  "containers": [{"digest": "sha256:…", "command": {"policy": "exact", "argv": ["/otelcol"]}, "args": {"policy": "deny"}}],
  "egress": [{"cidr": "203.0.113.7/32", "port": 443}]
}
```

- The protocol is always TCP. A `cidr` must have no host bits set, and an
  exit is listed once. The exits are part of the signed canonical document,
  so they are visible to anyone reading `GET /allowlist`. An entry without
  exits carries no `egress` key, so its bytes and digest do not change.
- The node grants a pod its entry's exits once the pod's workload containers
  match that entry, by the same rule secret release uses (the injected mesh
  and credential containers are left out). From then on every workload
  container of that pod must keep that match; one that does not is refused.
  The exits are fixed for the pod's life: a changed or removed exit applies
  when the pod is recreated.
- The node refuses an exit that overlaps the cluster's pod or Service ranges
  from its measured mesh policy, or a loopback, link-local or multicast
  range; a node whose policy names no cluster ranges grants no exit. The
  container whose start would have completed the match is refused with the
  reason.
- An exit is a way out of the TEE for whatever the workload sends. It is not
  inspected: whether its payload is acceptable (for example, telemetry with
  no customer content, sent to a relay the operator controls) is for the
  operator to decide and for relying parties to weigh.
- Exits open when the match completes, so an init container that runs
  before every main container exists cannot use them.

## Host privilege

The allowlist bounds which bytes run. It says nothing about what those bytes
are *handed*, and on a node CVM that is the whole difference between a tenant
container and node root: `privileged: true`, `hostNetwork`, a `hostPath` of
`/`, or a device node all give an allowlisted image the node's memory, the
volume plaintext and the admission plugin itself. Pod Security Admission in the
node image does not close it — it is control-plane admission, and the operator
owns the control plane.

So the NRI plugin applies a second, fixed policy to every container: the
**sandbox policy**. It is not a language for modelling OCI fields; it is one
rule shared by every workload, checked on the OCI spec containerd persisted —
the same final phase the env check runs in, after every plugin's adjustments.
A container is denied when it holds any of:

- a host ipc, network, pid or uts namespace;
- a bind mount whose source the pod does not own — every mount the kubelet and
  containerd stage lives under the pod's kubelet directory
  (`/var/lib/kubelet/pods/<uid>/`) or its containerd sandbox directory, matched
  as a clean-path prefix, so anything else is a `hostPath`;
- a device node, a CDI device, or a host network device moved in;
- an OCI hook, which names code outside the reviewed image and entrypoint;
- a container sysctl;
- the marks of a privileged container: no cgroup namespace, or a writable
  `sysfs`/`cgroupfs` mount.

A missing pod or container spec reads as every violation at once: unobservable
is denied, not assumed safe. Denials log the whole observation node-locally, so
a reviewer can write the missing rule from the record; the message the kubelet
surfaces names only the violated rules, which are the pod's own spec.

`policy.sandbox` selects `enforce` (deny), `audit` (record and admit) or `off`
(do not observe). A parsed config with no value enforces.

### What the node TCB is, and who may declare it

Some containers must hold host privilege — the RKE2 static pods, Cilium,
C8s's own node-level components. They are the node's trusted computing base,
and the exemption belongs to whoever measured them.

`allowlist.node_tcb: true` in the plugin's boot config marks that config's
`allowlist.base` document as the node TCB: a container that base admits —
digest, argv, env and mounts together — is exempt, and nothing else is. `policy.exempt_namespaces` does not reach it: the frozen snapshot
admits an image the allowlist would deny, never a host privilege the pod spec
claims. The node image sets it because its base is measured with the image
(`node-guest-image/c8s/image-policy.yaml.in`). A chart-rendered boot config
must not: that base comes from chart values, which the cluster admin the
policy defends against chooses.

A CDS-served document cannot express the marker: it is a boot-config key, not
an allowlist field, and both allowlist parse paths reject unknown fields.
Node-TCB status is a property of a measured boot config, never of a document.

### What NRI does not show

NRI v0.12.3 (`api.LinuxContainer`) carries namespaces, devices, mounts,
hooks, CDI devices, sysctls, net devices and the seccomp policy. It does **not**
carry the fields containerd also generates: Linux capabilities, the `privileged`
flag itself, `no_new_privs`, masked and readonly paths, the AppArmor profile,
and a read-only root. So this policy *infers* privilege from the cgroup
namespace and writable `sysfs`, and sees no capability set at all. The
measured runtime wrapper reads the bundle's `config.json` instead and refuses
the create for a container of a member pod that holds more than the floor
(`docs/node-exec-mode.md`); outside a mesh policy, a pod adding
`CAP_SYS_ADMIN` without any other privilege still passes here.

Two more limits: the host user namespace is the Kubernetes default, so its
absence is no evidence and `hostUsers: false` is not required; and a cgroup v1
node has no cgroup namespace on any container, so the privileged inference
would refuse everything there.

The exemption is only as narrow as the base entry. The chart's component
entries pin each container the chart renders to its exact argv and mount
table, so restaging one with another executable, another argument (nginx's
`-g load_module` or `-c`, a `--kubeconfig` whose exec credential plugin
client-go would run), or another volume is refused. Every ConfigMap, Secret
and PVC a component mounts sits under `/mnt/c8s-data/` and every hostPath
source is named, so no volume reaches the code an entrypoint loads. The
chart spells out each component's command rather than relying on the image's
ENTRYPOINT and CMD, and refuses an unescaped `$(NAME)` in a component's argv:
the kubelet would expand it from env, `envFrom` or a service variable. On a
bare-metal install without the attestation-api socket, CDS, the mesh and the
router sidecars find the node-baked attestation-api by node address. Under a
fail-closed policy, or with `nriImagePolicy.enabled=false` (the node image's
baked plugin, whose mode the chart cannot see), the chart writes it as
`$(NODE_IP)`. The binary reads that from the `node-ip` file the image policy
plugin (a host process, from the host's own view) or the node image's
`nri-node-ip.service` writes into the socket directory, never a pod, mounted read-only at `/run/c8s/node-ip` from a host path the entry
pins. The plugin rewrites the file in place, and the binary rereads it and
restarts when it names another address
(see [`armtls.md`](armtls.md) for when the plugin publishes a change). The render refuses `$(HOST_IP)` in a component's argv there: the binary
would read it from the `HOST_IP` variable, and a restaged pod could set that
to name its own `/verify`. Under an audit policy the chart keeps `HOST_IP`,
since nothing is refused anyway. Node images before this release publish
`node-ip` readable by root only; with `nriImagePolicy.baked=true` the pins
installer makes it world-readable, and with the installer off the components
need a node image that publishes it so. Two residuals stay open. `env` is
matched by name (see [Bootstrap](#bootstrap)), so a pod can no longer add
`LD_PRELOAD`, `BASH_ENV` or `NGINX_ENVSUBST_*`, or move `PATH`. `KUBECONFIG`,
`HOME` and `HTTP_PROXY` are not a vector: the operator, CDS
and the mesh build their Kubernetes client from the in-cluster service
account only, and the attestation-api clients ignore proxy variables. Off a node image, the router's
`nginx.conf` is the content of a listed ConfigMap: a `load_module` directive in
it loads code that no argument names
([#871](https://github.com/confidential-dot-ai/C8s/issues/871)). A node image
ships `nginx.conf` and the TLS snippets read-only in
`/usr/lib/c8s/router-nginx`, and its seed pins nginx to that host mount, so a
ConfigMap mounted in their place is refused. The
local-path helper runs `/bin/sh /script/setup` from a `/script` ConfigMap with
args and mounts `any`, so any pod running the helper digest can supply its own
script ([#872](https://github.com/confidential-dot-ai/C8s/issues/872)). Both
content residuals need the content pinned, or an image that carries the file. The node image's generated RKE2 system
entries still admit their digests under `command`, `args` and `mounts` of
`any`, so the control plane can restage one of those images — several ship a
shell — as a privileged tenant pod and the base admits it. Closing that means
pinning argv in the generated entries, which is systemfloor's to do; the
plugin already matches the whole entry, so a pin takes effect as soon as it is
measured.

## Where it's enforced

Two independent points enforce, at different strengths:

1. **Host NRI plugin** (`nri-image-policy`), per container. Resolves the image
   digest and checks the effective argv at creation, validates env after
   cumulative NRI adjustments, and rechecks the final OCI spec before start —
   where it also applies the sandbox policy above. Fail-closed before the
   allowlist first loads; the plugin runs inside the node CVM and is the
   primary admission gate.

2. **CDS at cert issuance**, in `resolveSandboxWorkload`. Before signing a leaf
   for a pod, CDS asks that pod's own inventory which images its sandbox is
   running (`docs/armtls.md`, "Sandbox identity"). Every reported digest must be
   allowlisted as some entry's container, checked against one atomic allowlist
   snapshot. Membership only: issuance lands mid-lifecycle, where the running
   set is a strict subset of the declared one, so requiring a whole entry would
   deny ordinary states
   ([getcert-workload-binding.md](getcert-workload-binding.md), Corner 4).
   Additionally — and without changing the membership contract — when the
   high-water `(digest, argv)` inventory uniquely matches one workload entry,
   the leaf is stamped with that entry's name and the snapshot's version and
   canonical digest (OID `…1.5`, `docs/armtls.md` "Matched workload"), which is
   what `c8s verify --workload/--allowlist` enforces against the mesh-CA chain.

### What each layer can and cannot promise

Per-container digest+argv admission holds at both points. **Combinations**
("only this image set may run together") are **not enforced anywhere today**.
NRI sees containers one at a time and cannot detect a
*missing* container, so they cannot enforce a combination; CDS sees the whole
reported set but only at issuance, which lands mid-lifecycle when that set is
still a subset of the declared one, so it checks membership rather than
composition ([getcert-workload-binding.md](getcert-workload-binding.md),
Corner 4). The honest guarantee is therefore: **per-container digest + argv
everywhere; no combination gating.**

Combination gating wants a point where the pod is complete and the decision is
worth blocking on. **Secret release is that point** ([`secrets.md`](secrets.md)):
it happens once every main container is up, so it can require a whole entry
rather than membership. That gates a secret, not container start — making a
combination itself *attested* is the RTMR3 per-workload-measurement path, which
is not implemented and is out of scope here.

### The injected-container carve-out

C8s injects its own init containers into every confidential pod — `c8s-cert`
(get-cert) and `c8s-cert-wait`, joined by `c8s-secret` and `c8s-volume` when the
pod asks for them. They pass the issuance gate by **digest**, not by name: the
injected image is seeded as its own entry, so a workload entry never has to
enumerate C8s's own sidecars. Matching rests on nothing the host writes, and the
container *name* is one of those things; the names identify injection only over
authored input, where admission reserves them and `c8s allowlist derive` drops
them. get-cert runs with per-pod dynamic arguments, which is exactly why the
sidecar shapes in the C8s image's component entry carry `command: exact` at
the invocation (`/c8s get-cert`) and `args: any`. Their mounts are `exact`:
the webhook mounts at fixed destinations, and each optional mount (discovery,
reload-watch) is a separate container of the entry, so admission is the union
across them. The inventory socket the NRI plugin adds is a `platform` mount and
needs no rule. Before
matching, a container whose image is admitted with open args for its
invocation and running one of the invocations the webhook injects is dropped
from the candidate set
([`secrets.md`](secrets.md#the-injected-drop-set)). The same image in any other
mode — for example, an application's `cds-attest` — is not injected, and the
entry must declare it.

## Distribution and trust

CDS serves the allowlist over an armTLS channel that consumers pin to CDS's
launch measurement. The document body is not itself signed; its integrity in
transit is the attested channel. Provenance of the *write policy* is checkable:
`c8s cds verify --operator-keys` cross-checks the key set CDS serves at
`/operator-keys` — fetched over the attested serving cert — against the
operator's own bundle. The serving certificate itself commits neither the key
set nor the seed (see [`armtls.md`](armtls.md)). The canonical serialization
(`allowlist.Canonical`) is deterministic — fixed field order, sorted map keys,
sorted container and path lists — so any holder of an equivalent document
reproduces the same bytes.

Writes are authorized by an operator EC key. The `c8s allowlist` CLI mints a
short-lived token bound to the exact method, path, and body (so a captured token
cannot be replayed against a different payload) and CDS verifies it against the
operator public keys it pins. Each token authorizes one request to any
operator-token endpoint (allowlist, routes, secrets): CDS remembers every spent
token and answers a replay with 409. CDS answers 503 when it verifies a token
but cannot record it as spent; nothing ran, so retry with a fresh token. Without
`cds.persistence.enabled` that memory resets with CDS, so CDS refuses every
token issued before its start plus `--jwt-clock-skew`; after a restart, wait
that long and mint a fresh token.

### Refresh and anti-rollback

Consumers poll `GET /allowlist` and refresh on a changed version (the ETag
counter). The served document **swaps wholesale, gated by a monotonic epoch**
(the version counter): a consumer applies a pulled document only if its version
is greater than the last applied, and ignores a regression. This matters because
policy can *tighten* (narrow `args`, revoke a `secrets` grant, remove an entry);
a plain additive merge would let a host that withholds an update keep a laxer
policy live forever. Epoch-gated replacement makes a withheld or rolled-back
update fail toward the last-known-good policy, not toward the laxest one; a CDS
outage degrades to "stale", never to "open". The high-water-mark is
process-local, so this rejects rollback only within a consumer's lifetime: after
a restart the first version seen is
trusted and state re-syncs from CDS. CDS's own counter resets with its store,
which is in memory on every supported node, so a CDS restart leaves each
plugin on its last policy until the counter passes it again (see
[Storage on the measured node image](#storage-on-the-measured-node-image)). A reboot-durable guarantee needs an
attested freshness / monotonic-counter mechanism the host cannot reset — a
tracked follow-on.

`nriImagePolicy.refresh.interval` sets the poll, so a node runs the previous
document for up to one interval after CDS commits a write; a node has taken a
write once the `allowlist_version` its plugin's `GET /healthz` reports (on the
health socket, beside the readiness status) is at or above the one
`c8s allowlist list` reports. The plugin also logs each refresh as
`pull loop: allowlist refreshed` with that version. The reported version is the
one applied, so a pull the anti-rollback check ignored does not move it.

The host NRI plugin also carries a **base enforcement allowlist** in
`allowlist.base`, baked into its boot config and never changed by a pull.
Either a base entry or a served entry must satisfy the launch constraints.
Both sources check argv at preliminary admission, then argv, environment, and
mounts at final admission; unavailable evidence fails constrained policies.
The chart's component entries carry the same exact argv and mount pins in the
base as in the served seed, leaving only the environment open, so the platform
can start before CDS is reachable; the node image's generated RKE2 system
entries leave command and args open.

### Allowlist history

CDS keeps an append-only history of every document it served, in the
allowlist database. Each write that changes the document appends an entry,
and so does CDS's start when the document differs from the last entry; a
fresh database starts with the document CDS first serves. A write that leaves
the document unchanged bumps the ETag but appends nothing. A policy digest is
`sha256:<hex>` of the exact bytes `GET /allowlist` serves. The routes are
unauthenticated reads like `GET /allowlist`, and the router and
`c8s allowlist-proxy` pass them through:

| Route | Returns |
|---|---|
| `GET /allowlist/history` | `{"entries":[{"position","version","digest","published_at","signed"}]}`, oldest first |
| `GET /allowlist/objects/sha256/<hex>` | The exact bytes of a document in the history |
| `GET /allowlist/objects/sha256/<hex>/signature` | Its operator signature, as `text/plain`; 404 when unsigned |

CDS refuses to start when a stored document no longer hashes to its digest.
Without `cds.persistence.enabled`, the history restarts with each CDS start.

#### Operator-signed allowlists

A document's operator signature is the write token of a `PUT /allowlist`
whose body is exactly its canonical bytes; the token's `pbh` claim hashes that
body. `c8s allowlist upload` sends canonical bytes, so its writes are signed.
A per-workload write (`add`, `apply`, `edit`, `delete`) signs nothing:
upload the whole document to sign it. A signature belongs to a document, not
to an entry, so `signed` is true on every entry with that digest. `operatorauth.VerifyStored` checks a
stored token: signature, method, path and body, but not its expiry.
`pkg/operatorauth/testdata/operator_signature_vector.json` is a test vector
for other verifiers.

#### Change policy

To move from policy P to policy Q without stopping running workloads:

1. Upload P∪Q, a document holding every entry of both.
2. Roll the workloads onto Q's images.
3. Upload Q.

Each step is one signed entry in the [allowlist history](#allowlist-history),
so every policy a node enforces along the way carries the operator's
signature.

### Measured policy history

On a TDX node, the NRI plugin can extend RTMR[3] with each allowlist it pulls
before applying it. RTMR[3] then holds the operator-key seed followed by the
digest of every policy the node enforced since boot. A policy digest is
`sha256:<hex>` of the exact bytes `GET /allowlist` served. A rolled-back
document is neither measured nor applied, a document the node fails to
measure is not applied, and a return to an earlier document does not extend
again.

Set `nriImagePolicy.measurePolicies: true` to turn it on. The chart renders
it as `allowlist.pull.measure_policies` in the plugin's boot config, and with
`nriImagePolicy.baked` patches it into the node image's config through
`set-cds-pins`; a plugin from a node image that predates the key ignores it.
Under `node.baked` the image owns the plugin config, so the
chart refuses the value. The key requires `allowlist.pull.url` and
`workload_claims.socket_dir` set to the default runtime directory, and is a
no-op on SEV-SNP, which has no runtime register. On TDX without the launch
operator key, or with a journal that no longer matches the register, the
plugin applies no pulled allowlist and keeps enforcing the one it holds: at
startup, the base allowlist alone. Other failures to open the register are
retried on each pull.

> [!WARNING]
> Measuring is off by default. Three kinds of check still require the bare
> operator-key seed and reject a node that measures: armTLS verifiers built on
> attestation-go releases that predate runtime extensions, flat RTMR[3] pins
> (`--rtmrs 3=…`, `allowlist.pull.cds_rtmrs`), and
> `c8s verify --image-policy-file` with an `approver_key`. Producers find the
> journal only under the default `nriImagePolicy.hostPaths.runtimeDir`,
> mounted beside the attestation-api socket, so the chart refuses
> `measurePolicies` with any other directory or without
> `attestationApi.enabled`. A node stops measuring, and so stops applying new
> policies, after 256 of them (the most a certificate carries) until it
> reboots.

The plugin journals the digests, one per line in extend order, at
`<nriImagePolicy.hostPaths.runtimeDir>/measured-policies`, a tmpfs that dies
with the register. These readers carry the list outside any transcript; a
verifier trusts it only as far as it replays against a quote's RTMR[3]:

- **armTLS evidence.** A TDX process that attests itself reads the journal
  after obtaining its quote, at `/run/nri-image-policy/measured-policies`
  or, in an injected sidecar, `/run/c8s/workload-claims/measured-policies`.
  It sends the list with the evidence: in the armTLS certificate extension,
  in the CDS `/attest` request as `runtime_extensions`, and in the router's
  discovery document. The anchored image pins CDS, armTLS peers,
  `c8s allowlist` and `c8s secrets` enforce accept the seed followed by any
  prefix of the list that replays. The replay proves which policies the node
  enforced, not that they are acceptable.
- **Router.** Wherever the router mounts the runtime directory, the chart
  passes `cds-attest --measured-policies-file`, which adds the list to
  attest-pq and attest-lb bundles as `measured_policies`. An absent or
  unreadable journal omits it.
- **cred-release.** It accepts its own binding as the seed followed by a
  prefix of the list, and carries the list in its armTLS certificate and in
  its `/attest` response.
- **`c8s get-kubeconfig`.** On TDX it takes the list from the verified
  cred-release certificate, whose self-signature under the attested key
  covers it, and for the fresh report from the `/attest` response on that
  verified channel. It accepts RTMR[3] as the seed extended by the
  `--workload-image` chain, optionally followed by a prefix of the list that
  replays. An extend after the workload chain passes whenever the node lists
  it. With `--attest-url`, the fresh report is checked against the
  certificate's list, which fails after a policy the certificate predates
  until cred-release renews its certificate.

The list is read after the quote is produced, so it may hold extends the
quote does not. Verifiers use the longest prefix that replays.

## Bootstrap

The chart renders the seed (`--allowlist-seed`) from the resolved component
digests, argv-pinned platform entries, and `bootstrapAllowlist.workloads`. Each
component digest becomes one entry named `<image basename>-<first 12 hex of
digest>-<first 8 hex of the SHA-256 of its containers>`, the basename cut to
41 characters. It lists one container per shape the chart renders the image in,
derived from the same pod templates the workloads render, so the two cannot
drift: `command` exact at the entrypoint (`c8sComponents[].entrypoint`,
`router.nginx.entrypoint`) or the container's own command, `args` exact,
`mounts` exact, and `env` `match` over exactly the variables the container
launches with: containerd's `HOSTNAME` (`present`), the image config's `Env`
(`c8sComponents[].imageEnv`, `router.nginx.imageEnv`, pinned `exact`), the
kubelet's `KUBERNETES_*` variables for the API server's Service, and the
container's own `env` (a constant `exact`, a `valueFrom` `present`). Loader
variables are never listed, so `match` refuses a pod that adds one. Component
pods and the pods the webhook injects into set `enableServiceLinks: false`, so
the set does not depend on the Services in the namespace; a workload that read
service-link variables must resolve the Service by DNS. The chart refuses to
render a component container with `envFrom` or an optional key reference. The
injected sidecar shapes match the variables the webhook sets on them. The
chart refuses to render a component hostPath under `/var/run`: containerd
resolves symlinks in a hostPath source and `/var/run` is a symlink to `/run`
on some nodes only, so the node reports no single path for it. The chart refuses to render a component container whose
argv references one of its own variables (`$(NAME)`): the value would differ
per node. An operator-authored `workloads` entry named `<image basename>-<first 12 hex
of digest>` replaces the entry whole in the rendered seed and in the host
plugin's base, and one named for the installer's digest replaces the
installer's argv-pinned entry; keep the host-sweep script and its pause in
it, or `c8s uninstall` cannot replay them. The same component entries feed the host
plugin's base allowlist, as does every operator entry that leaves args,
environment and mounts unconstrained, whether its command is `any` or pinned,
and every operator entry for a component's digest whatever it pins; other
operator entries are seed-only. `c8s allowlist lint` reports a container
pinned to a component executable (`/c8s`, `/app/c8s`, `/attestation-api`, or
`/docker-entrypoint.sh nginx`) with `args`, `mounts` or `env` `any` as an
error, which also blocks `upload` and `apply`; an injected sidecar shape may
leave only its `args` open. CDS seeding retires a stored chart-generated entry
that left a component's args, mounts or env open once the seed generates a
replacement for its image, so an upgrade from a release that seeded `env: any`
drops those entries. Because the seed now holds `match` policies, every
allowlist consumer must understand them first
([Environment policy](#environment-policy-env)): upgrade the node images
before or with the chart. With `deriveComponents`
off, such a container does not cover a component for the render guard. The
name is a function of the digest and the policy because CDS seeds
**additively by name**: an image bump, or a configuration change that alters
a component's argv, environment policy or mounts (`operator.extraArgs`,
`statusMirror.enabled`, the installer's boot config), adds the new entry
beside the old one, which pods still running the old shape keep matching
while they recycle, and which a rollback matches again. The argv-pinned
installer entries are named the same way. The seed never overwrites an entry
the store already holds, so an edit made with `workload apply` survives a
restart, while a deleted entry returns on the next CDS start for as long as
the chart still renders it — to remove an image, roll the chart with it gone.

On a chart-managed install, CDS reads its seed once, at start: anyone with
write access to the seed ConfigMap could otherwise publish entries without an
operator token. A configuration-only upgrade keeps CDS running, so publish the
new release's entries through it, signed with your operator key, before you
upgrade:

1. Run the upgrade's values through `helm template` and save the
   `allowlist-seed.json` of the `<release>-cds-allowlist-seed` ConfigMap as
   `seed.json`.
2. Note the highest `allowlist_version` any node's image policy plugin
   reports on `GET /healthz`.
3. Publish the seed: `c8s allowlist apply seed.json`. Each entry replaces the
   live entry of that name whole.
4. Check that `c8s allowlist list` reports a version above the one you noted.
   If it does not, CDS restarted since the nodes last pulled, and they ignore
   its versions up to the one they hold ([Refresh and
   anti-rollback](#refresh-and-anti-rollback)). Each `apply` raises the
   version by one, so for a small gap, run it again until the version passes.
   For a larger gap, restart the image policy plugin on each node that
   reports a version at or above it: restart containerd there (on RKE2, the
   `rke2-server` or `rke2-agent` unit), one node at a time. A restarted
   plugin applies the version CDS serves, whatever it held before. A node at
   or above an older version may hold a policy the restarted CDS never
   served.
5. Wait until every node has taken the write: its plugin reports an
   `allowlist_version` at or above the one `c8s allowlist list` reports.
6. Run the upgrade.

An override that narrows a component (an entry named `<image>-<first 12 hex
of the digest>`, see above) needs one more change: the store still serves the
generated entries it replaces, which admit what the override forbids, and
`apply` refuses an override that such an entry shadows. Publish it in one
write that retires them, in place of step 3:

```sh
c8s allowlist export live.json
jq --slurpfile seed seed.json --arg override OVERRIDE \
  '($override | capture("^(?<base>.+)-(?<digest>[0-9a-f]{12})$") | .base[:41] + "-" + .digest + "-") as $shape
   | .workloads |= (with_entries(select(.key | startswith($shape) | not)) + $seed[0].workloads)' \
  live.json > next.json
c8s allowlist upload next.json
```

`OVERRIDE` is the override's entry name. The filter cuts its image segment to
the 41 characters a generated shape keeps. Pods that still run the narrowed-away
launch keep running, but cannot restart under it. A CDS that seeds the
override at start retires those entries itself.

On a measured node image (`node.baked`), the seed is the file the image
holds, the same baked seed the node's image policy plugin enforces through its
base allowlist. CDS reads it once at start and keeps it as a fixed layer
beside the store (`--seed-layer`, which the chart sets only there). The
launch document's signed `workloads`, if any, are seeded into the store at
start instead (`--allowlist-seed`): they are served like any stored entry,
and the first upload replaces them.

- The seed never enters the store. `GET /allowlist` serves the stored
  document alone, byte for byte the one an operator signed, and names the
  seed in a `C8s-Allowlist-Seed: sha256:<hex>` header. An upload replaces the
  stored document only, so it may carry application entries alone and cannot
  drop C8s's own. `c8s allowlist upload` skips its core-component check when
  CDS names a seed.
- `/attest` and `/secrets` decide on both layers. On a name both hold, the
  seed's entry wins, as the node's base allowlist admits it too.
- A leaf whose pod matched a seed entry is stamped with the seed's digest
  (SHA-256 of its canonical bytes) and the store version. CDS serves the
  seed's canonical bytes at `/allowlist/objects/sha256/<hex>`. The seed is
  not in the allowlist history and carries no operator signature. get-cert
  does not renew a leaf stamped with the seed on an upload.
- The seed changes only with a new node image.

The steps above that publish the seed with `apply` are for chart-managed
installs; on a measured node image there is nothing to publish.

Known limitations:

- The chart-managed store has no durable backing or version handoff yet, so
  a recreated CDS loses operator writes and counts from a version below the
  one the nodes hold.
- Without `cds.operatorKeys`, a chart-managed CDS accepts no write, so
  nothing can publish a new release's entries. An upgrade that changes a
  shape, a `cds.image.digest` bump included, fails the CDS shape guard below
  or leaves the new pods refused, and restarting CDS does not help, since its
  version starts below the nodes'. Adding the keys later changes CDS's mounts,
  which is such an upgrade. To upgrade in place, set `cds.operatorKeys` when
  you install; otherwise uninstall the release and install the new one.

A rollback that keeps CDS running needs no publication: the store still holds
the previous release's entries, unless an override retired them (see above).
A rollback to a release without that override needs its generated entries
back: publish its seed as described next. A rollback across an upgrade that recreated
CDS does need one. The new store and the updated boot bases need not admit
the previous CDS or installer, and `helm rollback` reapplies the stored
manifests without the upgrade guard below. Before you roll back, save the
`allowlist-seed.json` of the seed ConfigMap in
`helm get manifest <release> --revision <previous>`, publish it with
`c8s allowlist apply`, and wait for every node as in steps 2 to 5.

CDS itself is recreated, not rolled, so it cannot publish its own new shape:
the old CDS stops before the new one starts. The chart records CDS's shape,
named as its generated entry, on its Deployment, and an upgrade that changes
CDS's image, command line or mounts fails until you publish the entry that
admits the new shape. A plain `cds.image.digest` bump changes the shape too.
The error names the entry to publish, which is your override when one admits
CDS, and the `cds.publishedShape` value. To publish it:

1. Run the failed upgrade's values through `helm template` with
   `--set cds.publishedShape=NAME`, where `NAME` is the value from the
   error, and save the `allowlist-seed.json` of the
   `<release>-cds-allowlist-seed` ConfigMap.
2. Copy the entry the error names into a file and publish it as in steps 2
   to 4 of the configuration-only procedure above, with
   `c8s allowlist apply ENTRY_FILE`. Without operator keys, nothing can
   publish it to the running CDS (see the known limitations above).
3. Wait until every node has taken the write, as in step 5 of that
   procedure.
4. Rerun the upgrade with `--set cds.publishedShape=NAME`.

When it seeds, CDS deletes a stored entry the seed replaces if it pins a
component executable with `args` or `mounts` `any`: an entry under a generated
name (`<image>-<first 12 hex of the digest>`, a `-<8 hex>` shape, or
`c8s-router-*`) that the seed lacks, for an image the seed now generates
another entry for. These are the open entries releases before the pinned
shapes seeded as `<image>-<12 hex>`. Kept beside the pinned shape, an open
entry would keep the bypass open, since a container is admitted when any
entry for its digest admits it. A pod of the previous release that restarts
before its rollout replaces it is refused. Operator entries under other names
are not touched; `c8s allowlist lint` reports such an entry for a component as
an error, and you delete it with `c8s allowlist delete <name>`. A rollback
seeds the previous release's entries again, since their names are free.

Old shapes with exact `args` and `mounts` stay admitted until you retire them.
To retire them once no pod runs them and no rollback needs them:

1. Export the live allowlist: `c8s allowlist export live.json`.
2. Save the release's seed: `kubectl get configmap <release>-cds-allowlist-seed -n <namespace> -o jsonpath='{.data.allowlist-seed\.json}' > seed.json`.
3. List the stale shapes: `c8s allowlist lint --seed seed.json live.json`. Each `is a stale shape` warning names a generated entry, `c8s-router-*` included, whose image the seed now generates under another name.
4. Delete each one: `c8s allowlist delete <name>`. The chart moved its ConfigMap, Secret and PVC mounts under
`/mnt/c8s-data/` (nginx reads `/mnt/c8s-data/nginx/nginx.conf`, or
`/usr/lib/c8s/router-nginx/nginx.conf` on a node image, CDS keeps its
database under `/mnt/c8s-data/cds`), so an upgrade rolls every component pod.
The webhook now pins the injected sidecars' mounts too. It refuses a pod
whose `confidential.ai/c8s-discovery-mount-path` is anything but
`/run/c8s/discovery` or whose `confidential.ai/c8s-reload-watch-mount-path`
is anything but `/mnt/c8s-data/c8s-reload-watch` (likewise
`c8s-cert-dir` and `c8s-secret-dir`), and one whose discovery or
reload-watch volume is of a kind the sidecar's mount table cannot admit.
Running pods keep their mounts, but their next create fails, so a rollout or
an evicted replica of such a workload is refused after the upgrade. Before
upgrading, remove those annotations, point `c8s-discovery-out` and
`c8s-reload-watch-paths` at files under the fixed paths, and make the
application read there; see
[Fixed sidecar mounts](secrets.md#fixed-sidecar-mounts).
A measured node image carries the pins in its base as soon as it is rebuilt. During an upgrade an enforcer that pulls the old document shape
before CDS restarts admits only workload containers until its next pull.

When the router runs with digest-pinned nginx and c8s images and
`deriveComponents` is on, the seed also carries `c8s-router-<first 12 hex of the
entry's SHA-256>`: every nginx and c8s-image container of the router pod,
pinned to the exact command line and mount table the chart renders, like the
component entries. nginx, `cds-attest` and `allowlist-proxy` are required
main containers; `acme`, `c8s-cert` and `c8s-cert-wait` are init containers,
admitted but not required. It is the
only entry the router pod matches, so the router's mesh leaf is stamped with
that name. An upgrade that changes the router's image repositories, digests,
arguments or mounts seeds a new entry beside the old one. Until that entry
is published, the router's leaf stays unnamed. Old entries persist like the
digest-named ones; remove them with `c8s allowlist delete`. Remove a
superseded `c8s-router-*` entry after the upgrade: when the two differ only in
image repositories, both match the router pod, and so do two that differ only
in an init container's arguments while it is not running. CDS then issues the
router's leaf unnamed. To supply your own
router entry instead, add it under `bootstrapAllowlist.workloads` and set
`router.attest.expectedWorkload` to its name; the chart then seeds no
`c8s-router-*` entry and passes that name on unchecked. The chart does not
check whether your entries match the router pod: an entry that also matches it
beside the seeded one makes the match ambiguous, and CDS issues the router's
leaf unnamed. An explicit `c8s-router-*` value must equal the seeded entry's
name, or the render fails.

Busybox and the NRI installer provide general-purpose shells, so the chart
admits their configured invocations through argv-pinned entries and excludes
those digests from the local floors. Their first startup may wait for the
plugin's first successful policy pull and kubelet retry. The chart escapes every `$` in
those scripts as `$$`, so the kubelet's `$(NAME)` expansion hands the runtime
the script the seed pins, including a component argument the operator
escaped as `$$(NAME)` that the install script embeds.

## CLI

`c8s allowlist` reads and mutates the allowlist. Reads are unauthenticated (the
armTLS channel provides integrity); writes are signed with the operator key you
supply via `--operator-key` (or `C8S_OPERATOR_KEY`). Persistent flags: `--url`,
`--measurements`/`--measurements-file` (armTLS pins), `--timeout`,
`--operator-key`, `-o text|json`, `--insecure`.

```
c8s allowlist
  list                              entry summary table
  get <name>                        one entry as canonical JSON
  export [file]                     write the full canonical document
  diff <file> [--exit-code]         entry/field diff vs the live allowlist
  add <digest> <image>              entry admitting the image under any command line
  derive <name> <file|->            entry from a live Pod/Deployment (pipe to apply)
  apply <file|-> [--dry-run]        upsert entries (whole-entry replace)
  edit <name>                       fetch, $EDITOR, diff, confirm, apply
  delete <name>...
  upload <file>                     replace the whole allowlist (diff-first, required-components guard)
  lint <file|-> [--online] [--strict] [--seed <file>]
  inspect-image <ref>               show an image's digest + baked entrypoint/cmd
```

`add` writes an entry named `<image basename>-<first 12 hex of digest>`, the
name of the operator override that replaces the chart's generated entry for
that digest in the seed.

Deleting a chart-seeded component entry does not lock its image out: the NRI
plugin's base allowlist still admits it. To block a
compromised component image, roll the chart with the bad digest replaced.

### Editing and applying

Whole entries are the unit of a write. `apply` and `edit` replace an entire entry
and show the field diff first; nothing field-merges, so no command can silently
clobber a sibling field. `edit <name>` is the fetch → `$EDITOR` → lint → diff →
confirm loop, and the signed write is always a separate, reviewed `apply`.

### Footguns the CLI removes

- **No raw `""`/`"*"` on the command line.** Policies are keywords (`deny`,
  `any`) or an argv captured verbatim after `--`; the tri-state sentinels live
  only inside files. Nothing can be shell-globbed or silently emptied.
- **The wrong shape errors, never half-works.** A malformed entry or name fails
  validation instead of partially applying.
- **Signed writes are diff-first and lint-first.** `upload`/`apply` run the
  offline lint and print the diff before the write. A lint error blocks the
  write; `--strict` makes warnings block it too.

### lint

`lint` catches the semantic traps before a write: an entry that admits nothing
(both lists empty), a `command: deny` container that can never start, a
shared digest whose union is widened to `any` by some entry — an `any`-policy
entry for a digest silently makes every narrower entry for it unenforced at the
per-container gate — and tag-form labels (which can move under the operator).
`--online` cross-checks digests against the registry with
`crane`; `--strict` turns warnings into a non-zero exit for CI.

Two entries declaring the same containers with the same argv policy are an
**error**, not a warning: release requires exactly one entry to describe a
sandbox, so entries of the same shape either both match or neither does, and
every pod resolving to them is refused whichever grant was meant. Nothing a
workload can do resolves it. A [shadowed](#a-digest-may-run-many-ways) entry
is an error for the same reason. The shape compared is digests and argv policies per
container list — the image label and the secret grant are excluded, since two
entries alike but for their grants are exactly the case worth catching.

`apply` and `add` run that check against the served allowlist as well as the
file, because the entry a new one collides with is usually one already there.

## Operator credentials

Generating an operator key and pinning its public half is unchanged; see the
README and [`operator.md`](operator.md). Rotating the pinned set rolls CDS, and
a verifier detects a changed write policy by comparing the served
`/operator-keys` list against its own bundle. Secret grants (`secrets`) are
managed with the same `edit`/`apply` flow.

To check node-root provenance against a real dm-verity table on a disposable
Linux build host with root, `mkfs.ext4`, `veritysetup` and loop devices:

```sh
go test -c -o /tmp/nri-verity.test ./internal/cmds/nri-image-policy
sudo bash node-guest-image/tests/mount-verity-test.sh /tmp/nri-verity.test
```

The script creates a private mount namespace and a disposable verity image. The
test confirms that the device passes as the measured root only when the boot
command line carries its `roothash`, and fails with any other hash.
CI also runs this test and merges its instrumented coverage into the coverage
gate. To collect its profile, build the test binary with `-coverpkg=./...` and
pass an existing coverage directory as the script's second argument. It does not
boot an attested node or deploy a GPU workload.
