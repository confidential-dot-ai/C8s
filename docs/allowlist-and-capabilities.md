# Allowlist and capabilities

Why a container may start on a C8s node, and what it may hold once it does. The
allowlist is the operator's policy of workload entries: named container sets,
each binding an image digest to the command line, environment, and mounts that
image may run with. Every field: [allowlist-entries.md](allowlist-entries.md).

The image reference a pod presents is chosen by the untrusted host and is not
bound to the image that runs. The digest is. So no admission decision reads the
reference, the entry name, or the container name; every one of them keys on the
digest. The entry name is load-bearing elsewhere: it is stamped on a matching
pod's certificate and is the `confidential.ai/cw` annotation's value.

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

CDS — the Certificate Distribution Service, the one in-cluster pod that serves
this policy and signs each pod's certificate — checks again when it issues a
pod's certificate: it asks that pod's own admission inventory which images the
sandbox runs and requires every reported digest to be allowlisted, against one
atomic snapshot ([armtls.md](armtls.md#sandbox-identity)). That is membership,
not the whole entry, because issuance lands mid-lifecycle, where the running set
is a subset of what the pod declares; when the set does match exactly one entry,
CDS stamps the leaf with its name ([armtls.md](armtls.md#matched-workload)).
Neither point gates a combination of images, since the plugin sees one container
at a time: secret release is where a whole entry is required
([secrets.md](secrets.md)).

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
view carries no capabilities, privileged flag, `no_new_privs`, masked paths, or
AppArmor profile, and an unobservable namespace reads as a violation, so a pod
or container spec the plugin cannot see is denied rather than assumed safe. The
kubelet event names the violated rules; the whole observation stays in the
node's own log.

The chart renders this policy off on every lane it installs
(`nriImagePolicy.policy.sandbox: off`), because the exemption below rests on a
measured base and a chart-rendered base is the cluster admin's to choose. What
remains there is control-plane admission the operator owns: the chart's
`<release>-deny-host-namespaces` policy, refusing host namespaces, host ports,
and `hostPath` volumes to pods outside the release, router, and `kube-system`
namespaces, the namespaces `hostNamespacePolicy.exemptNamespaces` names, and
`local-path-storage` on an installed cluster (`node.baked=false`)
([operator.md](operator.md)).

Some containers must hold host privilege: the RKE2 static pods, Cilium, C8s's
own node-level components. They are the node's trusted computing base, and the
exemption belongs to whoever measured them. A boot config can mark its own base
allowlist as the node TCB; a container that base admits — digest, argv,
environment, and mounts together — is then exempt, and nothing else is. The node
image sets that marker, since its base is measured with the image; a
chart-rendered base must not, and no served document can claim it: the marker is
a boot-config key, not an allowlist field.

A measured base can also tag a container with a platform role, the identity
C8s's own node-side invocations run under. It grants the role only with the
argv and the exact mount table that invocation is given, so a pod's own
container running the same invocation with mounts of its choosing holds no role
([secrets.md](secrets.md)). What this policy cannot see, the runtime wrapper
reads from the container's bundle ([node-exec-mode.md](node-exec-mode.md)).

## Writing policy

Reads are unauthenticated: consumers fetch `GET /allowlist` over armTLS —
mutual TLS whose certificates carry TEE evidence — pinned to CDS's launch
measurement, and that attested channel is the document's integrity in transit.
Writes are authorized by an operator EC key whose public half CDS pins: the CLI
mints a short-lived token bound to the exact method, path, and body, so a
captured token cannot be replayed against another method, path, or body, and
each token authorizes one request, so it cannot be replayed at all (CDS answers
a replay with 409).

## Refresh and anti-rollback

Every node polls `GET /allowlist` on `nriImagePolicy.refresh.interval` (5s by
default) and refreshes when the version — the ETag counter — changes. The
document swaps wholesale, gated by that monotone version: a consumer applies a
pull only if its version is not below the last applied.

This matters because policy can tighten: narrow `args`, revoke a grant, remove
an entry. A merge would let a host that withholds an update keep the laxer
policy live forever; version-gated replacement fails toward the last applied
policy instead — stale, never open. The high-water mark is process-local, so
rollback is rejected only within a plugin's lifetime.

Applying is not only about what starts next. Under `nriImagePolicy.policy.mode:
fail-closed` with `nriImagePolicy.policy.enforceExisting`, the chart's defaults,
a node also rechecks its running containers — at startup and after each document
it applies — and kills those the document no longer admits, outside the exempt
namespaces. Those are namespaces a boot config lists as holding platform pods
the allowlist does not describe, admitted against a digest set the plugin froze
on its first connect (Corner 8 of
[getcert-workload-binding.md](getcert-workload-binding.md)). So removing or
narrowing an entry stops its containers on every node within one refresh
interval.

One upgrade can stop on this. CDS is recreated rather than rolled — the old pod
stops before the new one starts — so it cannot publish its own new shape. The
chart refuses an upgrade that changes CDS's image, command line, or mounts
until the running enforcers admit it, naming the seed entry to publish and the
`cds.publishedShape` value that confirms it ([upgrade.md](upgrade.md)).

## Bootstrap

Two documents start the platform before CDS serves anything. The base allowlist
is the set of entries each plugin holds in its own boot config, checked ahead of
every pulled snapshot and never changed by a pull, so a node admits the platform
before CDS is reachable and a failed pull never drops it. The chart renders it
from `nriImagePolicy.bootstrapAllowlist`; a measured node image merges it at
boot from the file it bakes at `/usr/lib/c8s/allowlist-seed.json`.

The CDS seed is the document CDS seeds its store from at start. The chart
renders it into a ConfigMap from the resolved component digests, its argv-pinned
platform entries, and `nriImagePolicy.bootstrapAllowlist.workloads`; a measured
node image publishes it from that same baked file, plus the workloads its signed
launch configuration carries. Each component entry's name carries its image and
the digests of its policy, so an image bump or a configuration change adds an
entry beside the old one. Seeding adds every name the store lacks and retires
the chart-generated shapes its seed replaces, leaving an operator entry under
any other name untouched: an operator edit survives a CDS restart, while a
deleted entry returns on the next start for as long as the chart renders it. A
chart-managed CDS reads the seed once, at start; a measured node image's CDS
rereads its file every 30 seconds and seeds it again when it changed.

## Allowlist history

CDS keeps an append-only history of every document it served: a write that
changes the document appends an entry, as does CDS's start when the document
differs from the head. A policy digest is `sha256:<hex>` of the exact bytes
`GET /allowlist` serves. The routes are unauthenticated reads:

| Route | Returns |
|---|---|
| `GET /allowlist/history` | `{"entries":[{"position","version","digest","published_at","signed"}]}`, oldest first |
| `GET /allowlist/objects/sha256/<hex>` | the exact bytes of a document in the history |
| `GET /allowlist/objects/sha256/<hex>/signature` | its operator signature as `text/plain`; 404 when unsigned |

A document's signature is the write token of a `PUT /allowlist` whose body is
exactly its canonical bytes, so `c8s allowlist upload` signs what it writes
while a per-workload write signs nothing.

## Measured policy history

On a TDX node the plugin can extend RTMR[3] with each allowlist it pulls, before
applying it. RTMR[3] is a hardware register the node extends in order and
reports in its evidence, so it ends up holding the operator-key seed followed by
the digest of every policy the node enforced since boot. A document the node
fails to measure is not applied; the plugin journals the digests in extend
order, and components that attest themselves carry that list with their
evidence, which a verifier trusts only as far as it replays against the
register: proof of what the node enforced, not that it was acceptable. Set
`nriImagePolicy.measurePolicies: true` to turn measuring on.

It is off by default because checks that expect the bare operator-key seed
reject a node that measures: armTLS verifiers built before runtime extensions,
a pin on one fixed RTMR[3] value, and `c8s verify --image-policy-file` with an
approver key. It is a no-op on SEV-SNP, which has no runtime register. A node
that cannot measure keeps enforcing the policy it holds — at startup, the base
allowlist alone — and after 256 policies, the most a certificate carries, it
takes no further policy until it reboots.