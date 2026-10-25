# get-cert and the sandbox-identity binding

This is how a pod's mesh certificate comes to name the pod sandbox it was issued
to, and why the indirection that gets it there is safe: nothing the caller sends
names its pod — the kernel and the node's admission record do. Certificate
formats and verification rules live in [armtls.md](armtls.md); terms left
undefined here are in [glossary.md](glossary.md).

## The actors

- **get-cert** — the injected `c8s-cert` sidecar: generates the leaf key, builds
  the CSR, redeems a sandbox token, publishes the credential generation.
- **The admission inventory** — part of the admission plugin
  (`nri-image-policy`), the node process containerd launches to admit or deny
  every container. It serves the token route on a node-local Unix socket, which
  cannot enumerate sandboxes, and the identity and digests routes on port 1019
  over mutually attested armTLS, which cannot mint identity.
- **CDS** — verifies the evidence and the token, asks the inventory what the
  sandbox runs, checks those images against the allowlist (the operator policy
  of workload entries every node enforces), signs the leaf.
- **The relying party** — `c8s verify --sandbox-id … --mesh-ca …`, or a mesh
  peer reading the ID off a chain it verified.

## Step by step

1. get-cert fetches the CDS challenge first, so one single-use nonce binds both
   the token and the evidence REPORTDATA. The token needs no clock of its own.
2. get-cert posts its CSR public key and that challenge to the socket, naming no
   PID, pod, or container (Corner 1).
3. The inventory binds the caller from the kernel. It signs nothing unless two
   things hold for that sandbox: the admission plugin still verifies it as a
   protected mesh member, and no container of it was ever refused. Then it
   signs the token with an in-process key.
4. get-cert forwards token and signature — no credential for the key — in its
   `/attest` body. It forwards no image digests; it has none.
5. CDS reads the inventory host from the unverified token to pick a dial target
   inside the operator's node bound, fetches the signing key from `/identity`
   there, verifies the token and the evidence, then asks `/digests/{sandboxID}`
   and requires every image reported to be allowlisted before it signs and
   stamps.
6. The relying party pins. `--mesh-ca` is mandatory with `--sandbox-id`: the ID
   sits in the leaf's signed area, not in REPORTDATA, so CDS's signature is what
   authenticates it.

## Corner 1 — get-cert sends no PID; the kernel reports it

If a caller could name a PID, a pod, or a container, a malicious pod would name
a victim's and the binding would be worthless. So the caller names nothing. On
`accept` the kernel attaches the peer's credentials to the socket; the inventory
reads the PID with `SO_PEERCRED`, resolves it to a container through
`/proc/<pid>/cgroup`, and maps that container to a sandbox from its own
admission record.

A bare PID can be recycled between the credential read and the `/proc` read, so
the inventory also takes an `SO_PEERPIDFD` pidfd, pinning that exact process
instance, and re-checks liveness after the cgroup read and before it releases a
token. A peer that exited, or a pidfd it could not obtain, is refused: the pidfd
landed in Linux 6.5 and supported nodes run newer kernels.

## Corner 2 — the cgroup resolver picks the shallowest tracked container

A container's cgroup path can hold more than one 64-hex component: the runtime
may nest the sandbox ID above the container scope, and any process can nest a
child cgroup. The resolver returns every candidate, shallowest to deepest, and
the inventory takes the shallowest that is a tracked container. A process can
only move itself deeper, into cgroups it creates, so a caller that names a child
cgroup with a victim's container ID still resolves to its own container; taking
the deepest match is the exploitable choice.

## Corner 3 — the digests answer is one flat set for the sandbox, not a per-role split

`/digests/{sandboxID}` answers with two views of one sandbox — a deduplicated
digest set and a per-container view, both high-water marks, described in
[secrets.md](secrets.md#what-the-inventory-reports). Issuance gates on the
digest set, and three things follow for a certificate. The set carries no roles,
so it cannot tell an init container from a main one; what constrains how an
image runs is the per-container argv policy the plugin enforces at every launch
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)). A platform
role, in the other view, binds to a whole launch — digest, argv, environment and
mounts — so no pod spec can claim one. And the answer is **all or nothing**: an
unresolved digest fails the whole request, and a known sandbox with no
containers answers empty, which CDS refuses.

## Corner 4 — the sandbox ID binds at first issuance; the gate is membership only

There is one certificate per pod, not one per container. get-cert publishes it
on the pod's credential volume, which only the injected containers may mount — a
pod that mounts it into a workload container is rejected by the injection
webhooks — so the identity is the pod's, and get-cert only fetches and renews
it.

The sandbox ID resolves at the first issuance, because get-cert's own container
is already tracked when it asks. The image gate cannot be that strict: issuance
lands wherever the pod happens to be — only the sidecar up, a user init
container still running, main containers coming up over a window, completed init
containers removed for good — so requiring the running set to equal a workload
entry would deny ordinary states, permanently for a pod with init containers.
Membership is subset-safe, and
[allowlist-and-capabilities.md](allowlist-and-capabilities.md) owns that rule: a
sandbox ID means *this key belongs to pod X*, not *pod X runs exactly workload
Y* ([armtls.md](armtls.md#matched-workload)).

- **A refused container costs the sandbox its identity.** Every refusal a hook
  returns in enforcing mode is recorded against the sandbox, and the token route
  then answers 403 for that pod's life. A creation refusal is lifted when a
  container of that name is later admitted, so a pod created between an
  allowlist write and this node pulling it gets its identity once the retry
  passes. Killing a running container the applied allowlist no longer admits is
  not such a refusal: the pod loses the container, not its identity.
- **A plugin restart empties the inventory, and the startup check refills it.**
  NRI replays the full container list whenever the plugin connects, whatever the
  kill knob says. Until it completes, a callback gets a 404 or an empty set,
  which CDS refuses; a partial set still issues a membership-only leaf. The same
  replay takes each running member pod back under the mesh gate: the gate proves
  the namespace the runtime reports is the sandbox's own, verifies the ruleset
  live in it, and re-checks each listed container; a pod any of that fails for is
  refused for its life, and a member's renewal otherwise survives the restart.

## Corner 5 — the inventory is not control-plane-redirectable, at either end

**get-cert's target is compiled, not injected.** The socket path is a baked
constant in measured code. The node's admission plugin bind-mounts the socket
directory into the pod's socket consumers read-only, as an NRI/OCI mount, and
the injection webhook only adds the socket's supplemental group; neither passes
a path. A kernel path has no resolution step, while any hostname would be
redirectable through control-plane-configured DNS. `SO_PEERCRED` works only
across a same-kernel socket, which is what proves co-location: an HTTP call to a
genuinely attested peer would pass a measurement check and still answer for the
wrong pod.

**CDS's callback target is bounded by the operator, and the port is the
identity.** The token carries no credential for its signing key, so the host it
names is read unverified and used for one thing, picking a dial target; a wrong
value yields a key the signature fails under. The parse accepts only routable
unicast IP literals inside the operator's node bound. What establishes the
inventory's identity is where the key comes from: `/identity` on port 1019, a
privileged port in the node's own network namespace, over mutually pinned
armTLS.

## Corner 6 — what CDS actually trusts (it can't inspect the running container)

No component outside a pod can see its running images — and the evidence, which
proves the requester is a measured TEE holding the CSR key, says nothing about
them. So CDS trusts a chain, weakest link last:

- The **sandbox ID** comes from the kernel, through a key only a node can serve.
  get-cert cannot choose it and cannot forge the token; all it can do is present
  none, which costs it the ID.
- The **ground truth for what runs** is the inventory, asked directly, at
  issuance, over a mutually attested channel. The requester supplies no list, so
  there is none to cross-check.
- CDS's **backstop is the allowlist**: every reported digest is re-checked, so a
  compromised inventory cannot smuggle a non-allowlisted image past issuance. It
  can report a combination no entry authorizes, which the stamp catches.
- The **remaining assumption is an honest inventory on an honest node**: the key
  narrows to a node, not a process, so anything that can bind port 1019 there
  can sign for any sandbox that node admitted — including a privileged node
  DaemonSet, already root inside the node CVM.

## Corner 7 — who creates the socket, and why a hostile host can't inject one

The installer does not create the socket. The `c8s-nri-image-policy-worker`
DaemonSet lays down the plugin binary, its boot config, a containerd drop-in
registering it as required, and the runtime directory, root-owned with mode
`0711`. The plugin creates the socket at runtime, mode `0660`, group-owned by
the C8s non-root GID the webhook adds to the pod's groups, so the sidecar can
connect.

That makes the socket intra-TCB plumbing between two components already inside
the measurement boundary, not a root of trust: the directory is on tmpfs inside
hardware-encrypted memory, so the hypervisor cannot read or swap anything in it,
and a guest booted with a swapped plugin would not match the launch measurement.
The residual is a co-tenant — a malicious allowlisted pod that could mount the
directory read-write could swap the file first. The directory is root-owned,
get-cert's mount is read-only, and the chart's `deny-host-namespaces` policy
denies tenant `hostPath` volumes outright. Even
then a token CDS accepts must verify under a key fetched from port 1019 inside
the node bound, so the worst a swap achieves is denying the pod its sandbox ID.

## Corner 8 — exempt namespaces admit on a captured digest, not the name

On the hosted lanes the provider owns the platform pods in `kube-system` —
kube-proxy, CoreDNS, the CNI, CSI drivers — whose images are not on the C8s
allowlist, and nothing baked into the node measures them. Admission there needs
a source of truth for the platform images a node runs that the allowlist cannot
supply.

`policy.exempt_namespaces` supplies it without keying admission on a namespace
name, which is metadata the pod's creator chooses. The name is only a capture
selector: when the plugin first connects to a containerd that already requires
it, it resolves each listed namespace's running images to content-store digests
and freezes that set per namespace. A container there is then admitted only if
its resolved digest is in that frozen set; anything else is denied and audited
`exempt_snapshot_miss`, so drift is alertable from the log, and never killed
retroactively — stopping a running kube-proxy or CoreDNS can cut the node. The
exemption only downgrades a denial — the label rules and the allowlist still run
and still audit — and never a host-privilege refusal
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege)).

The captured set is persisted and is loaded, not recaptured, on a restart or
reboot: on a reboot containerd gates every container on this plugin, so the
plugin would see an empty node and freeze nothing. Only the installer rewriting
the boot config recaptures, which is what changing the exempt list does. It
claims nothing a measured node claims: the digests come from an unmeasured store
on an unmeasured host, and anything planted in a listed namespace before that
first connect is captured with the genuine set — which is why the measured node
image leaves the list empty.
