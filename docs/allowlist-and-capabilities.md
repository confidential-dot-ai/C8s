# Allowlist and capabilities

Under the fail-closed image policy, a container starts on a C8s node only where
an allowlist entry names its image digest and the launch that digest is given.

Guarantee:
[Only allowlisted code runs](guarantees.md#only-allowlisted-code-runs),
[No privileged way in](guarantees.md#no-privileged-way-in).

The allowlist is the operator's policy of workload entries: named container
sets, each binding an image digest to the command line, environment, and mounts
that image may run with. Every field:
[allowlist-entries.md](allowlist-entries.md).

The image reference a pod presents is chosen by the untrusted host and is not
bound to the image that runs. The digest is. So no admission decision reads the
reference, the entry name, or the container name; every one of them keys on the
digest. The entry name is load-bearing elsewhere: it is stamped on a matching
pod's certificate and is the `confidential.ai/cw` annotation's value.

A pod admitted by the served allowlist must name its image by digest
(`name@sha256:...`): a tag is resolved when the node checks it, not bound to the
image the runtime starts, so a tag reference is refused with `image must be
referenced by digest`. Only the base allowlist keeps tags, for the images the
node image carries, and so do pods in mesh-exempt platform namespaces, which
never receive workload traffic. A worker keeps no tags: its registry is its
control plane's.

## The model

One entry declares init and main containers. Each container pins a digest with
its `command`, `args`, `env`, and `mounts` policy; the entry as a whole carries
a secret grant and its `egress` entries. An absent `command`, `args`, or
`mounts` policy means deny, and a digest no entry names never runs.

A digest may run several ways, because admission at the per-container gate is
the union across entries: a base image two workloads share is admitted for a
container of either pod if either entry admits that launch. A shared image is
legitimately invoked differently, but one entry widening a shared digest widens
it everywhere, which `c8s allowlist lint` reports.

Decisions about a whole pod instead need exactly one entry to match, which it
does only when every container running in the pod is one it declares and every
main container it declares is running. Secret release, the matched-workload
stamp — the entry name written into the pod's certificate — and the `egress`
entries rest on that match, so two entries no running set can tell apart are a
lint error.

## Where and when it is checked

Two independent points enforce, at different strengths. The node's admission
plugin (`nri-image-policy`) runs in the node CVM, below the API server, and
sees every container three times:

| Point | What it reads | What it checks |
|---|---|---|
| Container creation | the digest and the effective argv | `command` and `args` |
| Adjustment validation | the same, plus environment and classified mounts, after every plugin's edits | the whole launch policy |
| Container start | the OCI spec containerd persisted | that policy again, then host privilege |

Validation is the hook whose refusal always rejects creation, and the node image
registers the plugin as a required validator of the container runtime, so the
runtime starts no container while the plugin is disconnected. Before the first
pull lands only the base allowlist admits — the entries the plugin carries in
its own boot config ([Bootstrap](#bootstrap)); `nriImagePolicy.policy.mode:
audit` admits anyway and logs denials.

In a pod CVM the plugin also verifies the selected image against containerd's
content and unpacked rootfs before measuring it ([Pod image
binding](#pod-image-binding)), and the runtime wrapper starts the created
process only with a one-use permission from the live plugin
([node-exec-mode.md](node-exec-mode.md#pod-admission-before-start)).

CDS — the Certificate Distribution Service, the VM outside the cluster that
serves this policy and signs each pod's certificate — checks again when it
issues a pod's certificate: it asks that pod's own admission inventory which
images the sandbox runs and requires every reported digest to be allowlisted,
against one atomic snapshot ([armtls.md](armtls.md#sandbox-identity)). That is
membership, not the whole entry, because issuance lands mid-lifecycle, where the
running set is a subset of what the pod declares; when the set does match
exactly one entry, CDS stamps the leaf with its name
([armtls.md](armtls.md#matched-workload)). Neither point gates a combination of
images, since the plugin sees one container at a time: secret release is where a
whole entry is required ([secrets.md](secrets.md)).

## What a launch policy constrains

A process policy constrains what a pod may run instead of the image's baked
`ENTRYPOINT` and `CMD`, because an image with an overridable entrypoint can
otherwise run any command under an allowlisted digest.

An environment policy covers the complete launch environment, image defaults
and runtime additions included. Pin it whole:

```json
"env": {"policy": "exact", "values": {"PATH": "/usr/bin:/bin", "MODEL_DIR": "/models"}}
```

Or list exactly the variables the container launches with, each pinned or only
required to be present:

```json
"env": {"policy": "match", "variables": {"MODE": {"exact": "production"}, "GPU_SERIAL": {"present": true}}}
```

A `match` policy rests on per-variable evidence, which a node records only for a
digest its applied policy lists; missing evidence fails closed. To start using
`match`:

1. Upgrade every allowlist consumer to one release, then publish the policies
   ([upgrade.md](upgrade.md)).
2. Wait until every affected node logs `pull loop: allowlist refreshed` — or
   `initial allowlist pulled from CDS`, if it started after you published — at a
   version at or above the one `c8s allowlist list` reports.
3. Recreate the affected pods; a restarted container keeps the sandbox's earlier
   records, which the match must admit too.

Mounts are classified by what the node can prove about the source, not by the
destination alone: a `hostPath`, an `emptyDir`, and a ConfigMap can arrive at
the same path with very different authority. The classes are `platform` (the
node's own, admitted without a rule), `emptyDir`, `data`, `host`, and
`nodeRootFile`, a read-only file the node proves came from the measured
dm-verity root. The destination still participates: a platform mount is
recognized by destination and source together, and a `data` rule only under
`/mnt/c8s-data/`, where operator-supplied content must sit, on storage the node
proves memory-backed or encrypted — which no persistent volume is
([operator.md](operator.md)).

## Host privilege

The allowlist bounds which images run. It says nothing about what a container
is handed, and on a node CVM that is the whole difference between a tenant
container and node root: `privileged: true`, `hostNetwork`, a `hostPath` of
`/`, or a device node hands an allowlisted image the node's memory, the volume
plaintext, and the admission plugin itself.

So the measured node image's plugin applies a second, fixed policy to every
container at start. A container is denied when it holds a host ipc, network,
pid, or uts namespace; a bind mount whose source the pod does not own; a device
node, a CDI device, or a host network device; an OCI hook; a container sysctl;
or the marks of a privileged container, which are no cgroup namespace or a
writable `sysfs` or `cgroupfs`. Privilege is inferred, not read: the runtime
view carries no privileged flag, `no_new_privs`, masked paths, or AppArmor
profile, and an unobservable namespace reads as a violation, so a pod or
container spec the plugin cannot see is denied rather than assumed safe. The
kubelet event names the violated rules; the whole observation stays in the
node's own log.

A host bind is set aside when an allowlist declaration hands it to that launch:
one that pins the launch (command, args and mounts not `any`, the environment
constrained), admits that launch whole, and names the bind in its `exact` mount
policy — a `host` rule by source and access mode, a `nodeRootFile` rule also by
node-root provenance. The base and a served document both grant, and one
declaration has to grant the bind on its own; `mounts: any` grants nothing.
Only that bind is set aside: every other violation still denies the container,
and a writable `host` rule grants write access to the node path it names.

A pod's host ports are the one host privilege the exemption below never
excuses: the node's own pods take the node's network, so a published port is
the pod's own doing. NRI carries no port mapping, so the plugin reads the
mappings containerd recorded for the sandbox, checked against the pod's name,
namespace and UID. Unless an entry declares every one of them, the sandbox is
refused before a container of it exists and containerd takes the port mappings
down with it. A container of such a pod then runs only under an entry that
declares those mappings and admits its launch; the mesh and credential clients
the node injects into a member pod are not held to it, as no entry declares
them. A record the plugin cannot read, one that puts the sandbox on the node's
network where NRI shows its own, and a mapping bound to a single node address
each refuse the pod; a sandbox containerd no longer has decides nothing about a
container already running. A pod on the node's network maps no host port of its
own: the kubelet records its container ports as host ports there, which name
the node's.

A container's capabilities are read, not inferred: the runtime view carries
none, so the plugin reads the OCI spec containerd stored for the container.
Every capability in the spec's five sets — bounding, effective, permitted,
inheritable and ambient — has to be in the node's default set (the container
runtime's default less `NET_RAW`, `SETUID` and `SETGID`) or declared by the
entry that admits the whole launch. A container on a platform role holds none,
whatever an entry declares. A spec the plugin cannot read, one describing no
process, and one naming no capability sets each refuse the container, whatever
the sandbox policy mode; a container containerd no longer has decides nothing
about one already running. A pod in a namespace the measured mesh policy
exempts keeps the capabilities the runtime gave it, as it does under the
runtime wrapper's floor
([node-exec-mode.md](node-exec-mode.md#the-privilege-floor)), and so does a
worker's static pod whose launch a base entry pins.

The measured runtime wrapper holds the same containers to the same bound at
the create, for the containers its floor covers and whatever the plugin's
state: beyond the node's default set, a container holds only the capabilities
the plugin recorded for its launch at the check whose failure fails the create
([node-exec-mode.md](node-exec-mode.md#the-privilege-floor)).

The chart renders this policy off on every lane it installs
(`nriImagePolicy.policy.sandbox: off`), because the exemption below rests on a
measured base and a chart-rendered base is the cluster admin's to choose. What
remains there is control-plane admission the operator owns: the chart's
`<release>-deny-host-namespaces` policy, refusing host namespaces, host ports,
and `hostPath` volumes to pods outside the release, router, `kube-system` and
`local-path-storage` namespaces, the set every cloud install exempts
([operator.md](operator.md)).

Some containers must hold host privilege: the worker's static pods. They are
the node's trusted computing base, and the exemption belongs to whoever
measured them. C8s's own node-side services are host units on a worker, which
this policy never sees. A boot config can mark its own base allowlist as the
node TCB, and nothing else exempts a container. The measured
node image sets that marker, since its base is measured with the image; a
chart-rendered base must not, and no served document can claim it: the marker is
a boot-config key, not an allowlist field.

A worker ([launch-configuration.md](launch-configuration.md)) answers to a
control plane outside its TEE. That control plane picks the image a pod runs,
writes every API pod's spec, and can read the values in the static pods'
launches, so a worker's measured config (`worker: true`) exempts one case and
nothing more: a kubelet static pod (sandbox annotation
`kubernetes.io/config.source: file`, which the kubelet sets itself and writes
`api` for every API pod) under an entry that pins its launch — command, args
and mounts not `any`, and the environment constrained. Its manifest comes from
the worker's own staging, out of the measured image and the document the launch
bound.

No other pod is exempt. An API pod holds the host binds, host ports and
capabilities an entry declares for its launch, as the router does, and no other
host privilege. A static pod's entry, which the worker's floor marks
`staticPod: true`, grants no host bind, host port or capability, and a boot
config whose static-pod entry declares host ports or capabilities is refused.

A worker's config also names no mesh-exempt namespace, so the mesh protects
every API pod with its own network namespace wherever the control plane puts
it; a static pod is the node's own and is never a member, on any node. It names
no credential attestation port: its credential clients verify through the
node's attestation socket.

An open entry admits its image, and the pod is sandboxed like any other, the
host network included.

GPU devices are set aside outside the node TCB too. containerd applies the
edits of the CDI devices a container requests (the CRI `CDIDevices` field or a
`cdi.k8s.io/` annotation) before the plugin sees the spec, so they arrive as
plain device nodes, hooks, and bind mounts. For devices of the kinds
`k8s.device-plugin.nvidia.com/gpu` (the NVIDIA device plugin's spec) and
`nvidia.com/gpu` (the node's `nvidia-ctk cdi generate` spec), the plugin
re-expands the requested devices from the spec files in `/etc/cdi` and
`/var/run/cdi`, which only node code writes, and sets aside exactly the device
nodes, hooks (stage, path, args, and env), and bind mounts (source, destination,
and read-only flag) that expansion produces. Any other device node or hook, a
device of another kind, and a device that no spec or two specs define stay
violations, and so does a spec that changed between containerd's read and the
plugin's. The container still needs an allowlist entry, and the CDI bind mounts
still have to match that entry's mount policy. An entry pinning the launch the
injection leaves — the variables the spec sets, the binds it adds — declares
capabilities for it like any other entry, recorded at the create for the
runtime wrapper's floor
([node-exec-mode.md](node-exec-mode.md#the-privilege-floor)). A device an NRI
adjustment asks for instead is resolved by the runtime after the plugin has
answered, so its device nodes, hooks and binds reach the container with nothing
to attribute them to, and the container is refused.

A measured base can also tag a container with a platform role, the identity
C8s's own node-side invocations run under. It grants the role only with the
argv and the exact mount table that invocation is given, so a pod's own
container running the same invocation with mounts of its choosing holds no role
([secrets.md](secrets.md)). What this policy cannot see, the runtime wrapper
reads from the container's bundle ([node-exec-mode.md](node-exec-mode.md)).
A base entry may also list `execs`, the exact commands the wrapper lets
through into a running container of its bytes, YAML-only for the same reason
([node-exec-mode.md](node-exec-mode.md#granted-execs)).

## Writing policy

Reads are unauthenticated: consumers fetch `GET /allowlist` over armTLS —
mutual TLS whose certificates carry TEE evidence — pinned to CDS's launch
measurement, and that attested channel is the document's integrity in transit.
Writes are authorized by an operator EC key whose public half CDS pins: the CLI
mints a short-lived token bound to the exact method, path, and body, so a
captured token cannot be replayed against another method, path, or body, and
each token authorizes one request, so it cannot be replayed at all (CDS answers
a replay with 409).

`PUT /allowlist` is the one write: it carries the whole document, and the token
that authorized it is that document's signature ([below](#allowlist-history)).
It takes `If-Match: "N"`, the strong tag of version N, the version that
`GET /allowlist` serves in `X-C8s-Allowlist-Version`: CDS replaces the document
only while the version is still N and answers 412 otherwise, leaving the
allowlist unchanged.
A write without `If-Match` replaces the document unconditionally.

`c8s allowlist add`, `apply`, `edit` and `delete` read the live document, make
their change to it, and write it back under the version they read; on a 412
they re-read, print what the other write changed, and make the change to the
newer document, for a bounded number of attempts. `upload` instead fails,
since its file is the whole document: run it again to see the new diff.

## Refresh and anti-rollback

Every node polls `GET /allowlist` every 5s, the `allowlist.pull.interval` the
chart and the measured node image both fix, and refreshes when the document
changes: CDS tags it with its digest,
`"sha256:<hex>"`, and sends its version in `X-C8s-Allowlist-Version`, and the
response carries `Cache-Control: no-store`. The document swaps wholesale, gated
by that monotone version: a consumer applies a pull only if its version is not
below the last applied, and a 304 raises the last applied version to the one
it names.

Nodes ask for the allowlist in effect (`?requester=node`). The node plugin
sends it over attested TLS to CDS; anything else sending it just gets the
allowlist in effect. An allowlist write takes effect on nodes
`--allowlist-node-delay` (30s) after it is written. CDS issues certificates
under it at once, and router certificates (`--router-cert-ttl`, 20s) last less
than that, so any router still serving advertises it before it
takes effect. A write replaced before it takes effect never does. The first
allowlist takes effect at once. Requests in flight or queued when a write takes
effect can still reach the new code, and removals wait the delay too. A node image older than this change enforces a
write at once.

This matters because policy can tighten: narrow `args`, revoke a grant, remove
an entry. A merge would let a host that withholds an update keep the laxer
policy live forever; version-gated replacement fails toward the last applied
policy instead — stale, never open. The high-water mark is process-local, so
rollback is rejected only within a plugin's lifetime.

Applying is not only about what starts next. Under `nriImagePolicy.policy.mode:
fail-closed`, the chart's default, every node also rechecks its running
containers — at startup and after each document it applies — and kills those
the document no longer admits, outside the exempt namespaces. Enforcing the
running set is not a switch: every C8s lane does it. Those are namespaces a boot config lists as holding platform pods
the allowlist does not describe, admitted against the image repositories the
same boot config carries for them (Corner 8 of
[getcert-workload-binding.md](getcert-workload-binding.md)). So removing or
narrowing an entry stops its containers on every node within
`--allowlist-node-delay` plus one refresh interval.

## Bootstrap

Two documents start the platform before CDS serves anything. The base allowlist
is the set of entries each plugin holds in its own boot config, checked ahead of
every pulled snapshot and never changed by a pull, so a node admits the platform
before CDS is reachable and a failed pull never drops it. The chart renders it
from `nriImagePolicy.bootstrapAllowlist`; a measured node image carries it in
the floor its own build rendered, which it bakes at
`/usr/lib/c8s/image-policy.yaml` and staging fills in and writes to
`/etc/nri/conf.d/image-policy.yaml`, where the plugin reads it
([launch-configuration.md](launch-configuration.md#staging-a-worker-document)).

The CDS seed is the component entries this release needs served. The chart
renders them into a ConfigMap from the resolved component digests, its
argv-pinned platform entries, and
`nriImagePolicy.bootstrapAllowlist.workloads`;
`c8s install --allowlist-seed-out` writes the same document for
`c8s cds config new`, which merges it with the operator's tenant workloads
into the configuration the CDS VM boots on. The seed is a render of this
release under the flags the install was given, so it must be written with the
flags the final install runs with, except `--cds-address` and `--cds-pin`,
which name the CDS the seed is written before. `--chart`, `--platform`, `-f`,
`--operator-keys`, `--volumes`, `--workload-ref`, `--namespace` and
`--release` all change the entries; an install whose flags differ from the
seed's finds the CDS serving another shape and refuses. Each component entry's name
carries its image and the digests of its policy, so an image bump or a
configuration change adds an entry beside the old one. Seeding runs once, at
start: it adds every name the store lacks and retires the chart-generated
shapes its seed replaces, leaving an operator entry under any other name
untouched, so an operator edit survives until the CDS VM restarts and a
deleted entry returns then for as long as the configuration carries it.

A cluster of workers runs no chart install, so it has no `--allowlist-seed-out` to
take the seed from. `c8s node-image render` writes the same document instead,
given the digests the worker image's own release published:

```sh
c8s node-image render --output-dir seed \
    --hardware-platform sev-snp --kube-version v1.36.4 \
    --image-digest sha256:<operator/get-cert digest> \
    --armtls-mesh-image-digest sha256:<armTLS mesh digest>
c8s cds config new --allowlist-seed seed/allowlist-seed.json ...
```

The digests must be the release the worker image was built from: a seed from
another release leaves pods waiting in `c8s-cert-wait`.

## Allowlist history

CDS keeps an append-only history of every document it served: a write that
changes the document appends an entry, as does CDS's start when the document
differs from the head. A policy digest is `sha256:<hex>` of the exact bytes
`GET /allowlist` serves. The routes are unauthenticated reads:

| Route | Returns |
|---|---|
| `GET /allowlist/history` | `{"hostPrivilege":{"declaredBySeed","firstOperatorGrant"},"entries":[{"position","version","digest","published_at","signed"}]}`, oldest first |
| `GET /allowlist/objects/sha256/<hex>` | the exact bytes of a document in the history |
| `GET /allowlist/objects/sha256/<hex>/signature` | its operator signature as `text/plain`; 404 when unsigned |

A document's signature is the write token of the `PUT /allowlist` whose body is
exactly its canonical bytes, stored in the same write, so a signed write never
serves its document unsigned. Every operator write is a whole-document write,
so every served document carries the operator's signature except the ones
seeding produces: the seed carries no operator token. A body that is not
exactly the canonical bytes replaces the document but stores no signature.
`apply`, `add`, `edit` and `delete` write the whole resulting document — the
live entries with their change made — so the operator key signs every entry in
it, not only the ones the command names: read the diff the command prints
before confirming it.

`hostPrivilege` reports the host privilege the allowlist declared: an entry
declares it with `hostPorts`, a container `capabilities`, or a `host` mount
rule — a `nodeRootFile` rule names a measured node-image file and declares
none. `declaredBySeed` is whether the measured seed this CDS booted on
declares any. `firstOperatorGrant` names, as `{"digest"}`, the document of the
first operator write that served a declaration the document it replaced did
not serve, and is `null` until one does; a write that moves a declaration to
another entry name grants nothing, and no later write clears the record. Both
last as long as the store: a CDS restart that starts from an empty database
reports its seed again and no grant.

## Measured policy history

On a TDX node the plugin can extend RTMR[3] — a runtime measurement register
the node reports in its evidence — with each allowlist it pulls, before applying
it, so a verifier can replay what the node enforced since boot: proof of what it
enforced, not that it was acceptable. A document the node fails to measure is
not applied. How the register is seeded, journalled, and replayed is
[measurements.md](measurements.md#policy-history). A worker measures: its
image's policy turns it on, and `c8s worker stage` refuses one that does not.

An installed cluster's plugin does not measure, because checks that expect the bare seed reject a node
that measures: armTLS verifiers built before runtime extensions, a pin on one
fixed RTMR[3] value, and `c8s verify --image-policy-file` with an approver key.
It is a no-op on SEV-SNP, which has no runtime register. A node that cannot
measure keeps enforcing the policy it holds — at startup, the base allowlist
alone — and once it reaches the register's per-boot extend cap it takes no
further policy until it reboots.

A Pod CVM (`role: pod`, see [operator.md](operator.md#pod-cvm)) measures each
image digest it admits instead (`measure.rtmr3`, which excludes
`allowlist.pull.measure_policies`: a boot has one RTMR[3] writer). The journal
is seeded with the Pod launch key the initrd staged. The guest authenticates
CDS with the separate image and launch-file policy in its signed launch
configuration. Fetched policies affect admission without extending this image
journal, whose directory is never mounted into Pod containers.
`c8s pod-status serve` carries the retained image list in its armTLS
certificate. The guest exits when its register does not replay its journal.

## Pod image binding

Guest preparation stages each init and application container's pinned digest
from the signed Pod, with the injected endpoint's measured pin, keyed by
container name, so Pod admission never resolves a mutable image name. On every
NRI start callback, before measurement or an admission record, the plugin reads
the pinned manifest or index by digest and checks containerd's saved CRI
configuration digest and the active snapshot's parent layer chain against it,
binding the selected configuration and filesystem to the staged pin. The check
has a five-second deadline and bounded metadata and content reads; missing,
malformed, mismatched or over-limit evidence is an admission error, with no
measurement and no new history entry.
