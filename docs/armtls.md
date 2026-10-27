# armTLS

armTLS is the mutual TLS C8s components authenticate each other with. A peer's
certificate carries hardware attestation evidence — a report a CPU key signs
over what the guest booted — so a handshake checks what the peer is, not a name
someone signed for it. Terms left undefined here are in
[glossary.md](glossary.md). Every connection runs one of two paths, never both:
the **evidence path**, where the peer presents a self-issued certificate with
its evidence embedded, and the **chain path**, where it presents a leaf signed
by the mesh CA.

The evidence path carries the API of CDS — the Certificate Distribution Service,
which holds policy and secrets and signs workload certificates — and the
endpoint of each node's admission inventory, the node service that records which
containers were admitted in which pod sandbox. A verifier there re-checks the
peer's evidence against its own measurement pins on every connection. It refuses
a CA-issued certificate, so a CA signature can never stand in for a measurement.

The chain path carries traffic between member pods — pods the node treats as
inside the mesh: injected, gated, and packet-captured — through their mesh
endpoints. It admits a peer on the mesh CA's signature alone and never falls
back to embedded evidence, so a peer it admits proved its measurement **at
issuance**, not at handshake.

## The attestation extension

A TEE can ask its hardware for an attestation report: a structure signed by a
CPU key, carrying the guest's launch measurement and 64 bytes of caller-chosen
REPORTDATA. C8s generates an ECDSA P-256 key in process memory and puts
`SHA-384(PKIX-DER(pubkey) ‖ challenge)` there — the challenge slot is empty
unless an issuance supplies one — so the report states with the silicon vendor's
authority that this measured guest holds this key.

The evidence travels in a non-critical X.509 extension under
`1.3.6.1.4.1.66378.1.1`: the TEE type (`1` = SEV-SNP, `2` = TDX), the report —
raw bytes for SEV-SNP, an evidence envelope elsewhere — a collateral field C8s
leaves empty, since an envelope carries its own, and an optional
`runtimeExtensions` list. The type comes from the evidence, not from the
component's configured platform. `runtimeExtensions` is TDX-only: it lists the
allowlist policy digests the node extended into RTMR[3], one of the TDX runtime
measurement registers a guest can extend after boot, at most 256 per boot, so a
verifier can replay the register. Weighing those digests is an external
verifier's job
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#measured-policy-history)).

A certificate's embedded evidence commits to its key alone, with no challenge:
possession of that key in the handshake and the certificate's validity window
are the freshness bound there. A challenge appears at one moment only, in the
evidence an issuance request carries, and no certificate embeds that evidence —
what CDS copies onto a leaf is the challenge-free extension the CSR carried.
Certificates live 24 hours by default and rotate at half their lifetime. Every
leaf CDS signs also carries `…1.2`, a digest of the evidence it was issued on;
it carries `…1.4`, the [sandbox ID](#sandbox-identity), when the request proved
a sandbox, and `…1.5`, the [matched workload](#matched-workload), when exactly
one entry matched.

## The handshake and pin checks

Both sides of a connection run the same checks in their role. The verifier
derives the REPORTDATA it expects from the peer certificate's public key and
posts the evidence and that expectation to `/verify` on its own attestation-api,
the service that checks hardware evidence for the component next to it. That
answers whether the hardware signature chain is valid, the REPORTDATA matches,
the debug and TCB policy hold, and whether the launch measurement it reports is
one of the verifier's pins. Verification is never in-process, and the answer is
unsigned, so every deployment points at the node's own attestation-api — the
node-local Unix socket, or the node address where no socket is served.

In-cluster armTLS refuses a pin set that names no guest — no launch measurement
and no image pin — before any request is made, because any genuine TEE would
pass it, including one the host runs itself. An outside verifier is the other
context: `c8s verify` without `--measurements` proceeds and prints an UNSAFE
warning instead ([verify.md](verify.md)). On TDX the launch measurement is the
MRTD, which covers the firmware alone, so pins identify guest code only with two
of the guest's runtime measurement registers pinned too: RTMR[1], holding the
kernel, and RTMR[2], holding the command line that carries the dm-verity root
hash (`c8s install --rtmrs`). A measurement covers boot state, so runtime
compromise inside a measured node is out of scope.

## CDS issuance

CDS is the only component that signs leaves. Its mesh CA is a P-384 key
generated in process memory at startup, CN `c8s Mesh CA`, valid for a year and
renewed past half of that under the same key. The key is never a Kubernetes
Secret and never on disk, so a CDS restart mints a fresh CA and every workload
re-bootstraps ([operator.md](operator.md)).

Issuance is challenge, attest, certify. The requester asks CDS for a challenge
(32 bytes, single-use, TTL-bound), generates a key and a CSR, asks its
attestation-api for evidence over `SHA-384(CSR pubkey ‖ challenge)`, and posts
the challenge, that evidence, the CSR and any sandbox token — the inventory's
signed statement of which pod sandbox the requester is in — to `/attest`. CDS
verifies the sandbox token, then the evidence through its own attestation-api,
enforces its measurement and register pins, checks the CSR's SAN and CN policy,
asks the pod's inventory what it is running, and returns the leaf plus the CA
bundle. The challenge is the freshness proof: the REPORTDATA commits to it, so
recorded evidence cannot be replayed into an issuance. Leaves are capped at 24
hours, a leaf carrying a matched workload at 6.

The leaf's name follows from what the request carries. A CSR with DNS or IP SANs
keeps its own common name, as does a CSR carrying only a common name and no
sandbox token. For `get-cert --no-san`, whose CSR must carry no common name, CDS
sets the common name to the lowercase hex SHA-256 of the verified sandbox ID. A
request with none of those names is refused `403 csr_denied`, and so is a
`--no-san` CSR that carries one. Names authorize nothing here: the mesh matches
on the signed extensions below.

`GET /ca` is unauthenticated. Consumers seed trust from the authenticated
issuance response and afterwards accept only a bundle already trusted, a
certificate renewed under a trusted CA's own key, or a CA certificate signed by
one they already trust, so a tampered read injects no root.

## get-cert and the mesh endpoint

A member pod gets two injected containers for this: get-cert (the `c8s-cert`
native sidecar, with a `c8s-cert-wait` init container gating the pod's own
containers on the first certificate) and the mesh endpoint (`c8s-mesh`).
get-cert publishes the pod's leaf, key and CA set as one generation on a
memory-backed volume at `/etc/c8s/certs`, renewing at the earlier of
`--renew-interval` and half the generation's remaining lifetime — its leaf's or
its CA's, whichever expires first. Between renewals `--ca-watch-interval` polls
CDS, so a renewed mesh CA or a stale stamped policy snapshot is picked up early.
The endpoint carries the pod's captured TCP over armTLS, on ports 15001
outbound, 15006 inbound and 15021 for probes.

A member pod's application TCP is redirected into those listeners in both
directions, so it crosses the pod boundary over armTLS. The node's packet rules
leave five kinds of traffic uncaptured and deny everything else in both
directions: resolver queries to the single address trusted policy names (port
53), the probes the mesh endpoint forwards to the pod's own address on port
15021, the sockets of platform roles (the credential clients that reach CDS, and
the endpoint itself), the platform services the measured mesh policy names for
every member pod (see [Cluster metrics](#cluster-metrics)), and the egress the
pod's workload entry declares once the pod matches that entry
([allowlist-entries.md](allowlist-entries.md)). Loopback stays reachable.

### Cluster metrics

A baked node — one booted from the measured C8s node image — runs
kube-state-metrics as a platform add-on, and every non-root socket of a member
pod may open TCP to its Service at `10.53.0.11:8080`, uncaptured, and read `GET
/metrics` there: the measured mesh policy names that one address and port. It
runs in `kube-system`, outside the mesh, from a stock image the node's base
allowlist pins to its exact argv, mounts, and environment, over plain HTTP.

What it exports is Kubernetes object metadata: names, owners, status and
conditions, restart counts, container images, pod IPs and node addresses, and
resource and replica figures, for pods, nodes, namespaces, Services, volumes,
the workload controllers and pod disruption budgets. Its RBAC is list and watch
on those kinds alone, so it reads no Secret and no ConfigMap; it exports no
labels, annotations or environment, and the series describing the host rather
than the workloads are off. Any member pod can read that metadata about every
other pod in the cluster: like the resolver, this is an address and a port the
mesh leaves open, not a payload filter.

### The mesh endpoint profile

A mesh endpoint presents its pod's CDS-issued leaf and authenticates peers on
the chain path alone. It accepts a peer only when the leaf chains to the mesh CA
it holds at the current time, permits the purpose the peer's role needs
(`serverAuth` for a server, `clientAuth` for a client), carries an ECDSA P-256
or P-384 key, and carries exactly one well-formed sandbox-ID extension. Both
roles require the ALPN protocol `c8s-mesh/1`, so no application byte moves on a
peer that does not speak it. Either role may also decide on the identity the
chain path read: the router's route authority, which holds the cluster's
operator-signed route manifest, requires a route's backend to be the workload
that manifest names, stamped under the allowlist digest on the router's own
leaf, or by name alone while that leaf carries no stamp
([operator.md](operator.md#route-manifest)).

### No session resumption

Every armTLS configuration disables session tickets and sets no client session
cache: a resumed handshake would skip the callback where armTLS checks chain and
evidence.

## Sandbox identity

Hardware attestation binds a key to a guest, and the guest here is the whole
node: every pod shares one launch measurement. A CDS-issued leaf narrows that to
one pod run, naming the CRI pod sandbox it was issued to under OID
`1.3.6.1.4.1.66378.1.4`.

The arbiter is that inventory: the part of the admission plugin
(`nri-image-policy`) that recorded which containers were admitted where. It
serves two disjoint surfaces, so what mints identity cannot enumerate sandboxes
and what enumerates cannot mint:

| Surface | Route | Listener | Caller bound by |
|---|---|---|---|
| tokens | `POST /sandbox` | node-local Unix socket | kernel peer credentials |
| identity, digests | `GET /identity`, `GET /digests/{id}` | port 1019, armTLS | the client leaf's measurement |

Port 1019 is compiled in, not configured, and privileged. Answering on it at the
node's address needs host networking or a host port, and the chart's
`deny-host-namespaces` policy withholds both from tenant pods — that, not
measurement, separates the inventory from any other pod on the node.

get-cert asks the inventory for a sandbox token, which binds the sandbox ID, a
digest of the requester's key, the CDS challenge for this issuance, and the IP
of the node serving port 1019. Nothing get-cert sends names its pod, and it
reports no images of its own. The token carries no credential for its signing
key: CDS resolves that key by dialing `/identity` at the named address, which
must be a routable unicast IP literal inside the operator's node bound
(`--sandbox-inventory-cidr`, else the live node list; an empty bound refuses
every token). CDS then verifies the token and asks `/digests/{id}`, where every
image reported must be in the allowlist — the operator policy of workload
entries CDS serves and every node enforces — and an empty answer is refused.

Issuance gates on membership, not on a whole workload entry
([allowlist-and-capabilities.md](allowlist-and-capabilities.md) owns that rule),
so a sandbox ID says *this key belongs to pod X*, not *pod X runs exactly
workload Y*. A request with no token gets a leaf with no sandbox ID;
[getcert-workload-binding.md](getcert-workload-binding.md) walks the binding.

The ID rides the leaf's signed area and is in no hardware report, so the mesh CA
signature authenticates it. No TLS path pins it — the mesh endpoint only
requires it to be well-formed — and on a self-issued certificate it is
peer-chosen and means nothing, which is why `c8s verify --sandbox-id` requires
`--mesh-ca`. The residual trust is a node: anything that can bind port 1019
there can sign for any sandbox that node admitted.

## Matched workload

A leaf additionally names the single workload entry the pod's attested container
inventory matched, when exactly one matches, under `1.3.6.1.4.1.66378.1.5`. The
stamp carries the entry name (at most 63 bytes, in the grammar that
`confidential.ai/cw` and a workload entry also use), the allowlist version, and
the allowlist digest: the SHA-256 of that policy's canonical bytes. Parsing is
strict, so damage never reads as absence.

CDS decides once per issuance, from one inventory answer and one immutable
policy snapshot: it runs the membership gate above, cross-checks the answer's
two views, drops a container by the platform role the node's base allowlist
binds to its launch, and matches the rest. A unique match stamps that name with
the snapshot's version and digest; anything else — a malformed answer, no match
mid-lifecycle, an ambiguous match — issues the unnamed, membership-only leaf,
since an incomplete pod still needs a certificate. The digest pins which policy
decided the match, so a client holding the same bytes detects skew. The router
keeps a route's backend inside its own allowlist by requiring the two stamps to
carry the same digest, checking the name alone while its own leaf carries no
stamp and refusing every workload dial with 502 while its own stamp does not
parse ([operator.md](operator.md#route-manifest)).

A sandbox goes from unnamed to named at the first renewal after its pod is
complete. There is no third state, and losing the match costs the pod its name
at the next issuance, not its containers: the inventory's record is never
pruned, so a pod that ever ran a foreign container issues unnamed from then on,
and the 6-hour cap bounds how long the last named leaf outlives its match.
Revoking a workload entry is a separate mechanism
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)). get-cert polls
faster while its leaf is unnamed, from 2s doubling toward
`--unnamed-renew-interval`; a leaf stamped with any name other than
`--expected-workload` stays on that fast poll instead of settling, which is why
the flag exists.

The stamp has the sandbox ID's posture: CA-vouched, enforceable only where a
chain was verified, so `c8s verify --workload` and `--allowlist` require
`--mesh-ca` too, and a compromised mesh CA can mint any name.
