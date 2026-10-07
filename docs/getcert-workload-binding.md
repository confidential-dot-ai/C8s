# get-cert and the sandbox-identity → armTLS cert binding

This walks the **sandbox-identity** path end to end: how a pod's mesh
certificate comes to name the sandbox it was issued to, how CDS gates that
issuance on what the sandbox is actually running, and the several corners that
routinely confuse people. It is the companion narrative to
`docs/armtls.md` (the normative wire spec) — read this for *how the flow
works and why it is safe*, read that for *the byte formats and verification
rules*.

---

## The one-paragraph version

`get-cert` (the injected `c8s-cert` sidecar) asks a local **inventory** —
part of the image-admission component itself (`nri-image-policy`), not a
standalone service — "which pod sandbox am I in?" *without saying who it is*. The inventory learns the caller's identity from
the **kernel** (unix-socket peer credentials), maps it to a sandbox, and
returns a **signed token** naming that sandbox, the requester's key, this
issuance's CDS challenge, and the IP of the node serving its own
identity+digests endpoint. `get-cert` forwards the token to CDS and says nothing
about its own images. CDS dials that endpoint on a fixed **privileged** port to
fetch the key the token is signed under, then asks what the sandbox is running;
it issues only if every image is allowlisted, and stamps the sandbox ID onto the
leaf. A relying party can then pin the workload
(`c8s verify --sandbox-id <id> --mesh-ca ca.pem`) or read a live mesh peer's ID
off the connection with `armtls.PeerSandboxID` (docs/armtls.md, "Reading a peer's
sandbox ID").

---

## FAQ — "wait, isn't this brittle?"

The flow looks indirect on first read. It is indirect on purpose: every
shortcut (let the pod report its own image, name the pod in the request, trust
get-cert outright) is a forgery vector. The answers below are the quick
version; each points at the Corner with the full argument.

**Doesn't the pod already know what image it runs?** It does not report one
either way. A pod is a set of containers; a single container sees its own
rootfs, not the registry *digest* it was pulled as, and nothing about its
siblings — and a malicious container could lie about its own digest regardless.
So the requester's only claim is *which sandbox it is in*; the image set comes
from the component that admitted those containers, asked directly by CDS.
(Corner 3, Corner 6.)

**How does the inventory know which pod is calling — is that operator-controlled?**
No, and that is the crux. get-cert sends no identity at all. When it connects,
the **kernel** stamps the caller's PID onto the socket (`SO_PEERCRED`); the
inventory reads that PID and resolves it PID → cgroup (`/proc`) → container → pod
from its *own* admission record. Every link is kernel/runtime-derived — nothing
the caller or the control plane supplies is used for identity. The kernel doing
the stamping is in the TCB (the node is the CVM). (Corner 1.)

**Does get-cert check it's in a TEE first?** No, and it doesn't need to. It
generates attestation evidence via the local attestation-api, and **CDS**
verifies that evidence — hardware signature chain plus the pinned launch
measurement — before issuing anything. Outside a real TEE the evidence does not
verify, so no certificate is issued. (Step 5; `docs/armtls.md`.)

**How does CDS know to trust get-cert — is it baked into the base image?** For
the image set it does not have to trust get-cert at all: get-cert is a conduit
for a token it cannot forge, and CDS asks the inventory itself. get-cert's own
integrity is still allowlist/measurement-rooted — under node-CVM its image runs
only because nri-image-policy admitted it — and the inventory socket endpoint
is compiled in, so the control plane cannot select its address. (Corner 5, Corner 6.)

**What stops a malicious pod claiming some other workload's identity?** It
cannot mint a token CDS will accept. The token names the sandbox the *kernel*
said the caller is in, so a pod can only ever obtain its own sandbox ID — and
the signing key CDS verifies it under is not a credential the token carries.
CDS fetches that key from the endpoint the token names, on a **privileged port
in the node's own network namespace**, at an address inside the operator's node
CIDRs. A tenant pod has neither (the chart's `deny-host-namespaces` policy
withholds `hostNetwork`, and its IP is in the pod CIDR), so a token it signs
verifies under nothing. What a malicious pod *can* do is present no token at
all, which yields a leaf with **no** sandbox ID — and that fails any
`--sandbox-id` pin. What remains is not forgery but trust in the inventory
itself (Corner 6) and in the mesh CA signature that carries the ID (docs/armtls.md,
"What vouches for the ID").

**Is the token surface secured so a malicious pod can't hijack it?** It is a
unix socket, and there are two separate threats:

- *Impersonating another pod over the socket* — closed by `SO_PEERCRED`. The
  socket's mode gates who can *reach* the inventory, but identity comes from the
  kernel-reported PID, not anything a caller sends, so even a reachable caller
  is bound to its own pod.
- *Replacing the socket file* — the real hijack vector. get-cert mounts the
  socket directory **read-only**, so it cannot swap the socket from inside its
  own pod. The socket lives on a host directory, so a *separate* malicious pod
  that could `hostPath`-mount that directory read-write could swap the socket
  before get-cert connects — a PodSecurity / filesystem-permission concern (the
  socket dir must be unwritable by untrusted pods). The chart's
  `deny-host-namespaces` policy denies every tenant `hostPath` volume.
  `nri-image-policy` supplies the read-only socket-directory mount through NRI,
  below the Pod spec, so credential sidecars need no PodSecurity exception.
  **Who creates the socket, and why the L0 host can't inject one, is
  Corner 7.** (Corner 5, "Why a unix socket".)

---

## The actors

- **get-cert** — runs in the `c8s-cert` native sidecar the webhook injects
  into every `confidential.ai/cw` pod. Generates the leaf key, builds the CSR,
  redeems a sandbox token, drives the CDS attestation flow, writes the cert.
  (`internal/cmds/getcert`)
- **The inventory** — fed by the component that makes the admit/deny decision,
  so it reports what ran on the node whatever that decision was. It serves two
  disjoint surfaces (`pkg/workloadclaims`): `POST /sandbox` on a **local** endpoint
  get-cert dials at a compiled unix socket path, and `GET /identity` +
  `GET /digests/{sandboxID}` on a **network endpoint over mutually-attested
  armTLS**, at the fixed privileged port `workloadclaims.DigestsPort` (1019),
  that only CDS talks to. The token endpoint cannot enumerate other sandboxes;
  the network endpoint cannot mint identity.
  - **node-CVM**: `nri-image-policy` (the host NRI plugin), token route on a
    node-local unix socket. The node is the confidential VM, so the plugin is
    in the TCB.
- **CDS** — verifies the evidence and the sandbox token, calls the inventory
  back for the sandbox's images, checks each against the allowlist store, signs
  the leaf with the mesh CA, stamps the sandbox ID.
- **The verifier** — anyone doing `c8s verify --sandbox-id … --mesh-ca …`, or a
  mesh peer pinning `VerifyPolicy.SandboxID`.

---

## Step by step

1. **get-cert fetches the CDS challenge first.** One single-use nonce then
   binds both the sandbox token and the evidence REPORTDATA, so the token rides
   the issuance's existing freshness rather than a wall clock of its own
   (`internal/cmds/getcert/run.go`, `obtainCert`).

2. **get-cert asks, anonymously.** `--workload-claims` opens the inventory at a
   compiled unix socket address and `POST`s `/sandbox`
   carrying only its CSR public key and that challenge. The request carries
   **no** PID, pod name, or container ID. (See "Corner 1".)

3. **The inventory binds the caller and signs.** On the unix socket it reads the
   peer's PID with `getsockopt(SO_PEERCRED)`
   (`pkg/workloadclaims/peercred_linux.go`), resolves that PID to a container
   via `/proc/<pid>/cgroup` (`cgroup.go`), and maps container → sandbox from its
   own admission record (`SandboxForPeer`). It then signs a token over
   `(version 2, sandboxID, SHA-256(requester pubkey), challenge, inventoryHost)`
   with an in-process P-256 key. Nothing the caller *sent* is used for identity.

4. **get-cert forwards the token.** The envelope — `token` and `signature`, no
   credential for the key — rides the `/attest` request body as `sandbox_token`,
   opaque to get-cert. It forwards **no image digests**; it has none to forward.

5. **CDS resolves the key, verifies, calls back, gates, and stamps.** It reads
   `inventoryHost` from the unverified token purely to pick a dial target,
   requires it to be a routable unicast IP literal inside the node bound
   (`--sandbox-inventory-cidr`, or the live node list when unset), and fetches
   the signing key from `GET /identity` at `<host>:1019` over mutually-attested
   armTLS (`workloadclaims.DigestsClient`, pinning the same measurements
   `/attest` uses, presenting CDS's own armTLS certificate). Only then does it
   verify the signature, and require the token's nonce to be the challenge it is
   consuming and its key digest to name the CSR key. It verifies the requester's
   evidence and CSR policy as usual, then asks `GET /digests/{sandboxID}` at the
   same endpoint. Every returned image must be allowlisted, and an empty set is
   refused. All pass ⇒ it signs the leaf and stamps the sandbox ID into its
   signed area (`internal/cmds/cds/attest.go` `verifySandboxToken` /
   `verifySandboxWorkload`, `internal/issuer/sign.go`).

6. **The relying party pins.** `c8s verify --sandbox-id <id> --mesh-ca ca.pem`
   requires the leaf to chain to the supplied mesh CA and to carry that exact
   sandbox ID. `--mesh-ca` is mandatory with `--sandbox-id`: the ID lives in the
   leaf's signed area, not in REPORTDATA, so CDS's signature is the only thing
   that authenticates it. In-mesh, `VerifyPolicy.SandboxID` is enforced on the
   CA-verified path only (`checkSandboxPin`).

---

## Corner 1 — get-cert sends no PID; the kernel reports it

The most common confusion: *how does get-cert tell the inventory which process to
look up?* It doesn't. If a caller could name a PID (or pod, or container), a
malicious pod would name a victim's and the binding would be worthless.

Instead, when the inventory **accepts** the unix-socket connection, the kernel
attaches the peer's credentials to the socket; the inventory reads them with
`SO_PEERCRED`. The PID comes from the kernel's own accounting of who opened the
socket. The chain is entirely kernel/runtime-derived — `SO_PEERCRED` → cgroup →
container → sandbox — and none of it is caller-supplied.

**Pinning the PID against reuse.** `SO_PEERCRED` returns a bare PID, and the
`/proc/<pid>/cgroup` read happens a few instructions later — a window in which
the peer could exit and the kernel recycle its PID to an unrelated process,
which the inventory would then resolve as the caller. The inventory closes this
by also reading `SO_PEERPIDFD` (Linux 6.5+), a pidfd that pins that *exact*
process instance, and rechecking `peer.IsAlive()` **after** the cgroup read: if
the pinned process exited during resolution — or the pidfd could not be obtained
at all — the answer is refused (`peercred_linux.go`, `Peer.IsAlive`;
`inventory.go`, `callerForPeer`). A supported CC node always has the pidfd:
`SO_PEERPIDFD` landed in Linux 6.5, and SNP hosts require ≥ 6.11, TDX ≥ 6.16, so
its absence is treated as an error and **fails closed**, not tolerated as a
best-effort fallback. This is orthogonal to Corner 2: the pidfd fixes *PID
identity over time*, the shallowest-tracked rule fixes *cgroup-nesting
spoofing*; both are needed.

**PID-namespace subtlety.** get-cert runs in a container where its own PID
might be 1. `SO_PEERCRED` reports the PID *as seen by the reader* — the
nri-image-policy plugin, which runs on the **host** (launched by containerd,
host PID namespace). So the kernel translates get-cert's PID into the host
namespace, and `/proc/<host-pid>/cgroup` on the host resolves to the
container's cgroup. This is why the plugin needs the host PID view and why
`workload_claims.proc_root` is `/proc` (the host's), not a mounted `/host/proc`.

---

## Corner 2 — the cgroup resolver picks the *shallowest tracked* container, not the deepest

A container's cgroup path can contain more than one 64-hex component
(CRI-O nests the sandbox ID above the container scope; an attacker can nest a
child cgroup). The resolver returns **all** candidates shallow→deep and the
inventory picks the shallowest that is a *tracked container*
(`ContainerIDCandidatesForPID`, `inventory.go`).

Why shallowest: a process can only move itself **deeper**, into cgroups it
creates — its runtime-assigned container scope is always an *ancestor* of
anything it nests. So a caller that creates a child cgroup named with a
victim's container ID produces `…/cri-containerd-<attackerCID>.scope/<victimCID>`;
shallowest-tracked resolves to `<attackerCID>` (the caller's own container) and
never to the nested victim. It also skips CRI-O's untracked parent sandbox ID
(it is not a tracked *container*). Taking the last/deepest match — the naive
choice — is the exploitable one.

---

## Corner 3 — the digests answer is one flat set for the sandbox, not a per-role split

`GET /digests/{sandboxID}` returns the **sorted, deduplicated** image digests of
every container the inventory currently tracks in that sandbox — user init
containers included (NRI's `CreateContainer` fires for init and regular
containers alike), and the C8s-injected `c8s-cert` sidecar included too. The
pause/sandbox container is not in the answer: it never reaches the plugin's
`CreateContainer` hook. Unknown sandbox ⇒
404; a known sandbox with no containers ⇒ `{"digests": []}`.

- **Order-independent.** The same images in a different container order answer
  identically, so a reschedule that reorders containers does not churn the
  identity.
- **All-or-nothing.** If the inventory has no digest for a tracked container it
  records an empty one — logged at error when a resolve failed
  (`recordForInventory`), silently on the pre-allowlist hook that does not
  resolve at all (`recordUncheckedForInventory`). Rather than answer with the
  containers it *can* describe — a subset passed off as the whole set — it fails
  the whole request, which CDS treats as fail-closed.
- **CDS checks membership, not composition.** Every image the inventory reports
  must be allowlisted as some workload container. Injected C8s containers are
  seeded as their own entries, so they pass by digest, not by name. CDS does not
  require the set to match a whole workload entry — see Corner 4.

**Matching is set-based over init and main together.** The inventory tracks
admission, not pod-spec roles, so two workload entries differing only in which
role holds an image are indistinguishable here. What actually constrains how an
image runs — the per-container argv policy — is enforced at admission by
nri-image-policy, where the role distinction is not needed
(`docs/allowlist-and-capabilities.md`).

---

## Corner 4 — the sandbox ID binds at first issuance; the gate is membership only

There is **one cert per pod**, not one per container. get-cert writes it to the
shared `c8s-certs` tmpfs, which the webhook mounts read-only into every
container, so the identity is the pod's — get-cert is just the thing that
fetches and renews it. The pod's single cert is minted *before the pod's app
containers are admitted*: the webhook injects `c8s-cert` as a **native sidecar**
(an init container with `restartPolicy: Always`) plus a `c8s-cert-wait` init
gate, and the app containers only start after all init containers pass.

The **sandbox ID** is unaffected by that ordering. get-cert's own sidecar
container is already tracked when it asks, so `SandboxForPeer` resolves at first
issuance and the leaf carries the ID from the start. (This is what the
requester-reports-its-own-images shape could not do: at first issuance it had
nothing to report.)

The **image gate is membership only**, and that is a direct consequence of the
ordering above. Issuance lands wherever the pod happens to be, and the running
set is a strict subset of the declared one in most of those states:

- at first issuance, only the injected sidecar is up;
- while a user init container runs, the main containers do not exist yet;
- main containers come up over a short window, not atomically;
- a restarting container is evicted from the inventory until it is recreated;
- once completed init containers are garbage-collected, `RemoveContainer` fires
  and they leave the set **permanently** — a pod with init containers never
  again runs its whole declared set.

Requiring the running set to equal a workload entry would therefore deny
certificates for ordinary lifecycle states, and in the last case would fail
every renewal for the rest of the pod's life. Membership is subset-safe — any
subset of an allowlisted set is still allowlisted — so it holds throughout.

What this gives up: CDS no longer refuses a pod that mixes containers from two
different workload entries, since each image is individually admitted. That
check wants a *complete* pod and a high-stakes decision to hang off, which is
secrets release, not cert issuance. A leaf's sandbox ID therefore means *this
key belongs to pod X*, not *pod X runs exactly workload Y*.

The **matched-workload stamp** (OID `…1.5`, docs/armtls.md "Matched workload")
is layered on top of this without changing it: when the sandbox's high-water
`(digest, argv)` inventory uniquely matches one allowlist entry, CDS
additionally stamps that entry's name and the policy snapshot's version and
canonical digest onto the leaf. The membership-only issuance contract is
untouched — every state above still gets its (unnamed) certificate, and the
unstamped leaf issued mid-lifecycle *is* the admission cert; the first renewal
after the pod completes resolves the match and *is* the completion cert
(get-cert fast-polls while unnamed, `--unnamed-renew-interval`). A verifier
that pins a workload or allowlist rejects the unnamed leaf; nothing else
changes behavior. A pod that ever ran a foreign container never gets a name —
the high-water inventory carries the same fail-closed semantics as secrets
release, and the named-leaf TTL (`cds.namedCertTTL`) bounds how long an
already-issued name can outlive its match.

Two inventory behaviours that still matter here:

- **An unresolved digest fails the whole answer.** The inventory refuses to
  describe a sandbox it cannot describe completely (Corner 3), so a subset is
  never passed off as the whole set.
- **A plugin restart empties the inventory, and the startup check refills it.**
  The node-CVM inventory is in-memory only. `nri-image-policy` is not a pod — it
  is a host process containerd launches from `/opt/nri/plugins`, and NRI does
  not respawn it on exit — so it restarts when containerd does: a chart upgrade
  that bumps the plugin binary or its config (the installer restarts
  containerd), a node reboot, or a crash. Running containers survive that
  restart, so their digests must be re-derived; NRI replays `Synchronize` with
  the full container list on every plugin start, and `checkExisting` records
  every container it sees. That recovery deliberately does **not** depend on
  `policy.enforce_existing` — that knob gates only the *kill* step, because
  "learn what is running" and "kill what shouldn't be" are separate concerns.
  Until the check completes, a callback landing in between gets a 404 (unknown
  sandbox) or a short set, and CDS refuses; get-cert retries at the next renewal
  interval. That window is bounded by the plugin's initial pull (backoff plus
  fetch timeouts, tens of seconds), against a renewal interval measured in
  hours. One case outlives it: a container created in that window is recorded
  from its image reference alone, so a reference carrying no digest records an
  empty one and its sandbox answers closed until some later record resolves
  that container — in practice the next `Synchronize` replay, not the deferred
  check, which replays only what `Synchronize` listed.
  On the measured node image the same replay carries a second job: with
  `policy.fatal_existing` the plugin separates its first registration since
  boot, where no container may exist at all, from a restart, where the
  containers it finds are re-checked and an unknown one powers the node off
  instead of being killed. See `internal/cmds/nri-image-policy/bootgate.go`.
- **A check that denies one of the containers.** The `c8s-cert` image sits in
  the plugin's base allowlist, so the check always admits it; a tenant app
  image does not, and a check running after the allowlist changed can deny one.
  Recording is independent of that verdict, so both are tracked and the callback
  answers the full set — including the denied image, which CDS then refuses. The
  pod loses its certificate whether or not `enforce_existing` is on, because the
  denied container ran in that sandbox either way; the knob decides only whether
  it is also killed. `mode: audit` does not change this: it suppresses the kill,
  not the record.

**Enforcement is on both sides now.** Issuance refuses a sandbox running an
image the allowlist does not admit; a relying party pinning
`c8s verify --sandbox-id … --mesh-ca …` refuses a pod that carries no or a
wrong sandbox ID.

---

## Corner 5 — the inventory is not control-plane-redirectable, at either end

Two independent properties keep a malicious control plane out of the loop.

**get-cert's inventory target is measured, not injected.** The endpoint is
compiled: `workloadclaims.InventoryEndpoint` (the node-CVM unix socket path).
The platform injects the read-only socket *mount*, never the path.

**CDS's callback target is bounded by the operator, and the port is the
identity.** The token is not self-authenticating: the envelope carries no
credential for the signing key, so `inventoryHost` is read from the *unverified*
token and used for exactly one thing — picking a dial target. A wrong value
yields a key the signature fails under. `parseInventoryHost` restricts it to
routable unicast IP literals — no names (DNS could redirect after the check), no
loopback, link-local, metadata, multicast, or unspecified addresses — and
`InventoryHosts.Contains` additionally requires it to fall inside the node
bound — the operator's `--sandbox-inventory-cidr` CIDRs, or one host route per
node derived live from the node list when unset. With no known node addresses,
CDS refuses every request carrying a token.

What actually establishes the inventory's identity is *where the key comes
from*: `GET /identity` on `workloadclaims.DigestsPort` (1019), a privileged port
in the node's own network namespace, over mutually-attested armTLS. Binding it
needs `hostNetwork`, which the chart's `deny-host-namespaces` policy withholds
from tenant pods; a pod's own IP is in the pod CIDR anyway. Measurement alone
could not make this distinction on node-CVM, where every pod shares the node's
launch digest. Whatever answers must also present a leaf whose measurement is in
the same allowlist `/attest` pins and accept CDS's own attested client
certificate, and CDS returns a generic denial rather than the callback's
outcome, so the requester learns nothing about what it reached. An unreachable
or unpinnable endpoint refuses the issuance rather than downgrading it.

**Neither is an identity proof on its own.** The remaining assumption is the
inventory's honesty about what it admitted (Corner 6), and the fact that the
sandbox ID on the leaf is vouched by the mesh CA signature rather than bound
into hardware evidence (`docs/armtls.md`, "What vouches for the ID"). Making the
pod's images part of a hardware measurement, enforced at `/attest`, is the
stronger close and is unimplemented.

The one surface still on an untrusted path is the **node-CVM** socket mount:
the inventory socket sits on a host directory its NRI plugin bind-mounts into
the sidecar, so a malicious *allowlisted* pod able to mount that directory
read-write could swap the socket file before get-cert connects. That is a PodSecurity /
filesystem-permission concern (the socket dir must be unwritable by untrusted
pods), not a redirectable arg — see
the residual note under "Why a unix socket".

### Why a unix socket, not an HTTP/DNS endpoint

On node-CVM the *token* surface is a **unix socket** (a kernel filesystem path),
never a network/hostname endpoint. That is deliberate; an HTTP endpoint
addressed by name would forfeit three properties:

- **Co-location.** `SO_PEERCRED` works only across a same-kernel socket, so the
  inventory get-cert reaches *is provably the one on its own node* — the real
  admission record for this pod (Corner 1). An HTTP call to another
  genuinely-attested node or pod cannot prove co-location: it would pass a
  measurement check yet answer for the wrong pod (the "any attested TEE passes"
  problem). This is also why authenticating the inventory's armTLS cert would not
  help — a cert proves *measurement*, not that you reached the local inventory.
- **DNS-immunity.** A kernel path has no name-resolution step. Cluster DNS is
  control-plane-configured, so a hostname endpoint would be redirectable
  *regardless of what value is baked in* — baking the name buys nothing. A unix
  socket sidesteps resolution entirely.
- **Non-redirectability.** get-cert bakes the socket path as a compiled
  constant (`workloadclaims.InventoryEndpoint`, in allowlisted/measured code), so
  the control plane cannot change *where* get-cert looks — the platform supplies
  only the socket mount, not the path. A network endpoint would be only as
  fixed as the arg carrying it.

The *identity/digests* surface is a network endpoint precisely because none of
those three apply to it: CDS is not co-located with the inventory, it needs no
peer-credential binding (it names the sandbox the token already vouched for),
and it is reached at a numeric address the operator's CIDRs bound rather than a
resolved name. What it does need — that the answering party holds the node's
network namespace and is a measured inventory, and that the asking party is CDS
— is what the privileged port plus mutual armTLS provides. The pattern: go over
the network only when you can authenticate what answers; stay on the local
endpoint when what you need is co-location, which attestation cannot prove.

The residual left is neither DNS nor attestation: the socket file lives on a
node path, so a malicious *allowlisted* pod that can `hostPath`-mount that
directory read-write could swap the socket before get-cert connects. That is a
PodSecurity / filesystem-permission hardening (the socket dir must be
unwritable by untrusted pods), not more crypto.

The read-only mount itself is plumbing, not an access boundary: any pod can
acquire it by forging the injected annotation and a sidecar container name, so
every socket in the directory must stay safe with every on-node pod assumed
able to dial it — the binding rests on kernel peer credentials and the RO
mount, never on who holds the mount.

Note this is *not* the same as the socket's own permissions. The non-root
get-cert reaches the socket because the inventory group-owns it
(`workloadclaims.InventorySocketGID`, mode 0660) and the webhook puts the sidecar
in that group — that is reachability for the *file*. The swap vector is about
the *directory*: the installer keeps it root-owned and non-world-writable (mode
0711, see the install script), so an untrusted pod still cannot unlink/replace
the socket. Group-owning the socket for liveness does not open the swap.

---

## Corner 6 — what CDS actually trusts (it can't inspect the running container)

CDS cannot independently observe a pod's running image digests — no component
outside the pod can. So how is the answer trustworthy? The chain, weakest link
named:

- **The evidence proves the requester is a measured TEE**, bound to the CSR key
  and challenge. That is what gates issuance at all; it says nothing about
  images.
- **The sandbox ID comes from the kernel, via a key only a node can serve.**
  get-cert cannot choose it (Corner 1) and cannot forge the token: CDS accepts
  only a signature it can verify under a key fetched from a privileged port in
  a node's own network namespace, at an address in the operator's node CIDRs
  (Corner 5). It can only decline to present a token, which costs it the sandbox
  ID entirely.
- **The ground truth for "what runs" is the inventory** — the admission record —
  and CDS asks it *directly*, at issuance, over a mutually-attested channel.
  There is no requester-supplied list to re-derive or cross-check, because the
  requester supplies none.
- **CDS's own backstop is the allowlist.** Every digest the inventory reports is
  re-checked against the allowlist store, so even a compromised inventory cannot
  smuggle an unallowlisted image past issuance. It *can* report a combination no
  workload entry authorizes, since CDS no longer matches whole sets (Corner 4).
- **The remaining assumption is the honest inventory on an honest node.** The
  key's provenance narrows to a node, not to a process: on node-CVM anything
  that can bind `:1019` in the node's netns — the inventory, or a privileged
  node DaemonSet — can sign for any sandbox that node admitted. Those DaemonSets
  are already root inside the node CVM and can read another pod's memory
  directly, so they are effectively node TCB; that is an assumption, not
  something attestation checks. Fleet-wide, a peer node shares the launch
  measurement, so a hostile node could answer for a node whose traffic it can
  intercept.

"Did get-cert reach the *real* inventory" is not a control-plane-supplied link:
the socket endpoint is compiled (Corner 5). What remains is the node-CVM
socket-file swap — a PodSecurity / filesystem-permission item, not attestation.

---

## Corner 7 — who creates the socket, and why a hostile host can't inject one

A natural challenge: the socket is a filesystem object on the node — what stops
a malicious host from planting its own and answering for the inventory?

**First, who actually creates it.** Not the C8s installer. The nri-image-policy
installer DaemonSet only lays down three things on the node: the plugin
*binary* (into `/opt/nri/plugins`), a *containerd drop-in* that registers it as
a pre-installed NRI plugin, and the *runtime directory*
(`mkdir -p` + `chmod 0711`). The socket itself is created at **runtime by the
plugin**: containerd launches it as a node process and `workloadclaims.ListenUnix`
calls `net.Listen("unix", …)` — that syscall materializes the socket. It
`os.Remove`s the path first, so any pre-existing (stale or planted) socket is
deleted before it binds its own. So: **the inventory creates the socket, not
the installer and not the host.**

**The reframe that answers the challenge.** The socket is not a root of trust —
it is intra-TCB plumbing between two components that are *both already inside*
the measurement boundary (the inventory and get-cert). Its integrity is *inherited*
from that boundary, not established by the socket. Which "host" can subvert it
splits cleanly:

- **The L0 hypervisor — defeated by hardware.** The runtime dir is under `/run`,
  which is **tmpfs (RAM)**, and under SEV-SNP / TDX the guest's RAM is
  hardware-encrypted. The L0 host physically cannot read, write, inject, or swap
  a socket in that memory. The whole node is the CVM and the socket sits in
  the node's encrypted tmpfs. A guest the
  host booted with a swapped plugin would not match the launch measurement, so a
  CDS with `--measurements` set refuses to issue to it.

- **The residual is a co-tenant, not the L0 host** (node-CVM only). The exposure
  is a *malicious allowlisted pod* — inside the node's TCB in the TEE sense, but
  not benign — that can `hostPath`-mount the socket directory **read-write** and
  swap the file. This is a PodSecurity / filesystem-permission problem, the same
  residual as "Why a unix socket". It is
  gated by: the dir is **root-owned `0711`** (untrusted pods cannot write it),
  get-cert's own mount is **read-only**, get-cert dials a **compiled** path the
  control plane cannot redirect, and the chart's `deny-host-namespaces` policy
  denies `hostPath` volumes to tenant namespaces outright. The residual opens
  if that policy is disabled and PodSecurity permits untrusted host-path mounts,
  or an untrusted workload is placed in a trusted namespace exempt from both.
  (One nuance: the mount *source* — the
  inventory's configured socket dir — is operator-supplied, so a malicious
  operator could point it at a rogue dir — but the plugin runs inside the
  node-CVM and is measured, so this reduces to "is the node's TCB intact",
  which the node launch digest attests. The plugin binary's on-disk integrity rests on the same
  node measurement + allowlist + guest lockdown, not on the socket.)

**And a subverted socket is bounded anyway.** A swapped socket can hand get-cert
a token, but not one CDS accepts: the signature must verify under a key CDS
fetched from `:1019` at an address inside the operator's node CIDRs, over
mutually-attested armTLS. Naming a real node's address does not help — that
node's inventory holds the key, and it did not sign this token. The worst a
co-tenant swap achieves is denying the pod its sandbox ID.

The **identity/digests endpoint** needs no equivalent argument: it is not a
filesystem object, it never answers an unauthenticated caller, and reaching it
requires the node's network namespace. It does need to be *reachable* from CDS —
see Enablement.

---

## Corner 8 — exempt namespaces admit on a captured digest, not the name

On the hosted lanes (gke/aks) the provider owns the platform pods in
`kube-system` — kube-proxy, CoreDNS, the CNI, CSI drivers — and their images are
not on the C8s allowlist. Nothing baked into the node measures them either;
unlike node-CVM, whose image carries the RKE2 system floor, these nodes run the
provider's unmeasured OS and containerd. So admission there needs a source of
truth for "the platform images this node runs" that the C8s allowlist does not
supply.

`policy.exempt_namespaces` supplies it **without** re-introducing the
namespace-name key that admission keyed on before it was removed. A namespace
name is API-server metadata the pod's creator chooses, so keying admission on it
let an allowlist-denied image run by being named into `kube-system`. Here the
name is only a **capture selector**: when the plugin first connects to a
containerd that already requires it — the platform pods having come up before
the `required_plugins` gate — it resolves each listed namespace's running images
to their content-store digests and freezes that set, scoped per namespace. From
then on a container in a listed namespace is admitted only if its resolved
digest is in that namespace's frozen set. The key is the digest — a local fact
the plugin reads from the store — not the relayed name.

What this does and does not grant:

- **An unlisted image in a listed namespace is denied**, and audited
  `exempt_snapshot_miss` so drift (a provider rotating a platform image between
  chart upgrades) is alertable from the log. It is **denied, never killed**:
  stopping a running kube-proxy or CoreDNS can cut the node, so enforcement is
  at the next create, not retroactive.
- **A captured digest does not admit in a tenant namespace.** The set is scoped
  to the namespace it was captured in, so this does not widen tenant admission
  the way a namespace-global floor entry would.
- **The exemption only downgrades a denial** (`checkContainer`), so the label
  rules and the allowlist still run and still audit; the exemption event names
  the denial it overturned (`overrides`).

Freezing and regeneration. The captured set is persisted under the plugin's
cache dir and is **loaded, not recaptured, on a plain restart or reboot** — on a
reboot containerd gates every container on this plugin, so the plugin sees an
empty node at connect time and a recapture would freeze nothing. The one event
that recaptures is the installer rewriting the boot config (a chart install or
upgrade), which deletes the snapshot file; the next connect re-freezes from
what is running then. An operator changing the exempt list is such a rewrite.

Scope of trust. This is a hosted-lane mechanism and it does not claim a
node-CVM guarantee: the captured digests come from an unmeasured store on an
unmeasured host, and anything an adversarial control plane had already planted
in a listed namespace before the plugin first connected is captured along with
the genuine platform set. That is strictly narrower than the removed
namespace-name exemption — bounded to one capture window per node and to
concrete digests rather than "any image, forever" — but it is weaker than the
node-CVM floor, which is why `exempt_namespaces` is left empty on `cvmMode=bare-metal`
and the baked floor stands alone there.

---

## Enablement

Always on: the chart wires the NRI inventory socket and the operator flag,
and the plugin NRI-mounts the socket directory into the injected sidecars.
get-cert is fail-closed on an inventory error, so a broken inventory blocks
workload cert issuance — by design.

**Network reachability.** The identity/digests endpoint is a new *inbound* path:
CDS must be able to reach the nodes on
`workloadclaims.DigestsPort` (1019, fixed), and the node bound —
`cds.sandboxInventoryCIDRs` (`c8s install --node-cidr`), or the live node list
when unset — must cover those addresses or CDS refuses every request carrying a
token. The advertised host defaults to the installer DaemonSet's own
`status.hostIP`, written to a `node-ip` file beside the socket;
set `nriImagePolicy.sandboxDigests.advertiseHost` or
`$C8S_SANDBOX_DIGESTS_ADVERTISE_HOST` to override. Route inference is the last
resort and is wrong under the chart's default, where the plugin dials the CDS
NodePort over loopback.

**A failed digests endpoint is not fatal.** The NRI plugin logs and continues:
containerd sets `required_plugins`, so a plugin exit takes container creation
down node-wide, whereas a missing digests endpoint only degrades issuance.

**Unpinned measurements do not disable the flow.** With an empty measurement
allowlist both ends still require a hardware-attested armTLS peer but pin no
measurement — any TEE can answer as the inventory, and any TEE that can reach
the port can read what a node runs. Both log it as UNSAFE outside development;
the allowlist gate still runs. A CDS with no `--armtls-platform` has no armTLS
identity to present, makes no callback, and **refuses** any request carrying a
sandbox token. A `--measurements` entry that is not hex fails CDS startup rather
than silently unpinning the callback; the same typo fails the plugin's
config validation at startup.

**Upgrade ordering.** Because get-cert fails closed on an inventory error, roll
`nri-image-policy` (which creates the socket and serves both surfaces) **before
or with** the operator/webhook that injects `--workload-claims`. If the
webhook starts injecting the flag while an old plugin (no inventory socket, no
NRI-injected socket-directory mount) is still running, every newly admitted
`cw` pod fails cert issuance until the plugin is current: get-cert exits while
the socket directory is absent, so the sidecar crashloops and its next
creation picks up the mount once the node's plugin is. A chart upgrade rolls
the webhook Deployment and the per-node plugin independently, so expect that
crashloop window on not-yet-rolled nodes.

Existing Pods that still declare the old claims `hostPath` must be recreated to
pick up the NRI mount. Pod CREATE/UPDATE and `pods/ephemeralcontainers` updates
reject that volume even when it is unchanged from a previously admitted Pod.
Admission does not evict already-running Pods.

The same ordering covers the secret and volume fetchers, which redeem at the
same endpoint. Volume mounts also require the node's `volumed` DaemonSet and
its Unix socket; see [Volumes](volumes.md) for setup and mount ordering.

## Public hostname and mesh identity

A launch-driven router can use different public and mesh names. For example,
the mesh certificate can name `c8s.local`, while ACME requests a certificate
for `api.confidential.ai` and `candidate.api.confidential.ai`.

The baked router passes `--discovery-public-tls-hostnames-file` to get-cert.
In ACME mode, discovery reports the first hostname from the signed launch
input. It does not replace the mesh SAN or the CDS certificate and evidence.
In CDS mode, discovery reports the mesh SAN. Missing or invalid hostname
files stop startup. An empty file is valid only in CDS mode.

This metadata does not prove certificate issuance. Clients must still check
the live TLS certificate and verify that fresh front-door attestation binds
to that certificate. A bootstrap certificate does not pass the public CA
check merely because discovery reports the correct hostname.

## Audit pointers

| Concern | Where |
|---|---|
| Inventory protocol (both surfaces), sandbox token, peer-cred + cgroup binding | `pkg/workloadclaims/` |
| node-CVM inventory (shallowest-tracked resolution, sandbox/container eviction) | `internal/cmds/nri-image-policy/inventory.go` |
| get-cert challenge → token fetch → `/attest` forward | `internal/cmds/getcert/run.go`, `pkg/attestclient/client.go` |
| get-cert leaf-embed (nonce-free armTLS extension on the CSR) | `pkg/attestclient/armtls.go` (`AttestationExtension`) |
| CDS token verify + inventory callback + allowlist membership gate + leaf stamp | `internal/cmds/cds/attest.go`, `internal/issuer/sign.go` |
| verifier pin | `internal/cmds/verify/` (`--sandbox-id`, `--mesh-ca`) |
