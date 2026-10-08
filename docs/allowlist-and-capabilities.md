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

An image that may run **however it is invoked** — a C8s component whose argv
is per-pod — is an entry whose container `command` and `args` are both `any`.
Nothing distinguishes such an entry from any other: it is matched, stamped and
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

An absent policy normalizes to `deny`, so a minimally specified container is
maximally restrictive. `command: deny` requires an empty argv and therefore can
never start (a workload that wants any argv should say `command: any`); `lint`
flags it. Because `command`/`args` map 1:1 to the Kubernetes fields, `derive` (on
its own branch) reads them straight off a pod spec, and `inspect-image` shows an
image's baked `ENTRYPOINT`/`CMD` so an operator can see what to pin.

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
any environment. Missing env evidence fails `exact` and `deny`. An empty
`exact.values` normalizes to `deny`, and an absent policy defaults to `any`.

```json
"env": { "policy": "exact", "values": {"PATH": "/usr/bin:/bin", "MODEL_DIR": "/models"} }
```

The NRI plugin enforces env after cumulative NRI adjustments, and the admission
inventory carries an environment fingerprint for CDS workload matching and
secret release.

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

The pod UID embedded in a kubelet source must equal the pod being admitted, and
containerd sandbox sources must name its exact sandbox. These runtime IDs prove
local ownership only and are not serialized into the stable allowlist.

| Observed source | Class | Storage | `exact` behavior |
|---|---|---|---|
| Node-created platform mount at its fixed destination | `platform` | not relevant | admitted without a rule |
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

Some containers must hold host privilege — the RKE2 static pods, Canal,
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

The exemption is only as narrow as the base entry. The node image's generated
system entries admit their digests under `command`, `args` and `mounts` of
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
them. get-cert runs with per-pod dynamic arguments,
which is exactly why the seeded component entries carry `command: any, args:
any`: their argv is not fixed and must not be argv-policed. Before matching, a
container admitted that way and running an injected entrypoint is dropped from
the candidate set ([`secrets.md`](secrets.md#the-injected-drop-set)).

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
operator public keys it pins.

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
trusted and state re-syncs from CDS. A reboot-durable guarantee needs an
attested freshness / monotonic-counter mechanism the host cannot reset — a
tracked follow-on.

`nriImagePolicy.refresh.interval` sets the poll, so a node runs the previous
document for up to one interval after CDS commits a write; a node has taken a
write once its plugin logs `pull loop: allowlist refreshed` with a version at or
above the one `c8s allowlist list` reports.

The host NRI plugin also carries a **base enforcement allowlist** in
`allowlist.base`, baked into its boot config and never changed by a pull.
Either a base entry or a served entry must satisfy the launch constraints.
Both sources check argv at preliminary admission, then argv, environment, and
mounts at final admission; unavailable evidence fails constrained policies.
Generated system-image entries explicitly allow mounts and leave the other
launch fields unconstrained so the platform can start before CDS is reachable.

## Bootstrap

The chart renders the seed (`--allowlist-seed`) from the resolved component
digests, argv-pinned platform entries, and `bootstrapAllowlist.workloads`. Each
unrestricted component digest becomes one entry named `<image basename>-<first 12 hex of
digest>` with a single container under `command: any, args: any, env: any, mounts: any`; an
operator-authored `workloads` entry of the same name replaces it whole in the
rendered seed. Operator entries with unconstrained command, args, environment,
and mounts also feed the host plugin's base allowlist; constrained entries
are seed-only. The
name is a function of the digest because CDS seeds **additively by name**: an
image bump adds the new digest's entry beside the old one, which pods still
running the old image keep matching while they recycle. The seed never
overwrites an entry the store already holds, so an edit made with `workload
apply` survives a restart, while a deleted entry returns on the next CDS start
for as long as the chart still renders it — to remove an image, roll the chart
with it gone. During an upgrade an enforcer that pulls the old document shape
before CDS restarts admits only workload containers until its next pull.

Busybox and the NRI installer provide general-purpose shells, so the chart
admits their configured invocations through argv-pinned entries and excludes
those digests from the local floors. Their first startup may wait for the
plugin's first successful policy pull and kubelet retry.

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
  lint <file|-> [--online] [--strict]
  inspect-image <ref>               show an image's digest + baked entrypoint/cmd
```

`add` writes the same entry the chart seeds for a bootstrap digest, under the
same name (`<image basename>-<first 12 hex of digest>`), so a later chart bump
that derives the digest adds nothing.

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
