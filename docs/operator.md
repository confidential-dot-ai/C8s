# Running a cluster

A C8s cluster takes its policy from operator private keys that never enter it.

Guarantee: [No privileged way in](guarantees.md#no-privileged-way-in),
[Routes are what the operator signed](guarantees.md#routes-are-what-the-operator-signed).

The platform operator is the person holding those keys; `c8s install` is the
command they run, `c8s operator` is the controller pod it deploys, and only the
person's keys authorize policy. For a workload, see
[workloads.md](workloads.md).

Kubernetes credentials come from the cluster's own control plane, which on
bare-metal runs outside every TEE and issues the kubeconfig `c8s install` and
`kubectl` use
([launch-configuration.md](launch-configuration.md#a-workers-control-plane));
a measured node releases none.

## What an install deploys

`c8s install` renders the chart embedded in the CLI and runs
`helm upgrade --install`. Two flags have no default and describe the hardware:
`--cvm-mode` (`bare-metal`, `gke`, `aks`) and `--hardware-platform` (`sev-snp`,
`tdx`). All three CVM modes are node-as-CVM: the node is itself the confidential
VM, its pods processes inside it ([overview.md](overview.md)); dotted names
here, such as `router.publicTLS.mode`, are chart values.

| Resource | Role |
|---|---|
| `c8s-operator` Deployment and Service | Controllers and the two admission webhooks |
| `c8s-pod-injector`, `c8s-pod-validator`, `<release>-deny-host-namespaces` | Injection, its enforcement, and the host-namespace refusal |
| `c8s-attestation-api` and `c8s-nri-image-policy-worker` DaemonSets | Node-local evidence and the admission plugin; on `bare-metal` the measured node image carries both, so the chart renders neither |
| `c8s-router` Deployment, Service, and the `c8s-router` namespace | The public front door |
| One ingress NetworkPolicy per installed component | See [Network policies](#network-policies) |
| `c8s-volumed` DaemonSet, the `ConfidentialWorkload` CRD | Volumes with `--volumes` ([volumes.md](volumes.md)); `--install-crds=false` skips the CRD |

Two inputs are policy rather than plumbing. `--cds-address` and `--cds-pin`
name the CDS this cluster trusts and the guest it runs in, and the chart
refuses to render without them. The address is `<host>:<port>`: a DNS name
this cluster's components resolve, or an IPv4 address. `--operator-keys` pins the operator public keys
the router verifies route manifests under; without it the router uses the keys
the pinned CDS serves. CDS takes its own write keys from
`c8s cds config new --operator-keys`. `--force` installs despite a fail-closed
policy that would deny the platform's own pods. A measured node image boots the
chart its own build rendered, configured from the worker document it launches
with ([launch-configuration.md](launch-configuration.md)); `c8s install`
refuses a cluster labelled `confidential.ai/baked=true`.

Images in a registry that needs authentication need a
`kubernetes.io/dockerconfigjson` Secret in the release namespace, named with
`--image-pull-secret <NAME>`; the chart adds it to every component's
`imagePullSecrets`. Digest resolution runs on your machine and uses your local
registry login instead.

`c8s uninstall` deletes the release, then sweeps host state the chart cannot:
the admission plugin's containerd registration, the `ARMTLS-MESH` chains and
ipsets, and idle `c8s volume attach` backstores. Baked components stay. Each is
one set per node, shared by every release, so uninstalling one takes them from
another.

## The `c8s operator` controller

The operator pod serves the pod injector and the pod validator, both
`failurePolicy: Fail` and both release-tracked, so a webhook never outlives the
Service behind it and a pod is rejected rather than admitted uninjected. The
webhook CA is minted at every start of the pod, with its key only in process
memory. Injection happens at pod CREATE; both webhooks also see
`pods/ephemeralcontainers` updates, which is what stops `kubectl debug` reaching
an injected pod's credential volume. A pod admitted while the webhook was
unavailable is never re-admitted, so at startup the pod deletes controller-owned
pods carrying `confidential.ai/cw` with no injected shape, and logs the ones no
controller would recreate. Its controllers create one headless Service
`c8s-<ENTRY>` per workload whose pod template carries `confidential.ai/cw`, and
mirror into `ConfidentialWorkload` status how many of its pods are Ready, read
as holding a certificate: the `c8s-cert-wait` gate exits only once one exists.
The CRD (`cwl`) is that status view and nothing else: injection reads pod
annotations and looks up no CR, and whether a pod's containers may run is the
node's and CDS's decision
([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).

## Injection contract

Every pod created in a namespace the injector's selector admits is injected, so
the excluded set is the whole opt-out: the release namespace, `c8s-router`,
`kube-system`, `kube-public`, `kube-node-lease`, and `webhook.extraExcluded`;
an installed cluster (`node.baked=false`) also excludes `local-path-storage`.
Injection adds the memory-backed `c8s-certs` volume, mounted at `/etc/c8s/certs`
for the platform containers alone, and these containers ahead of the pod's own:

- `c8s-mesh`: the pod's mesh endpoint, carrying its traffic over armTLS
  ([armtls.md](armtls.md)).
- `c8s-cert`: get-cert, which obtains the first leaf before the application
  starts and then renews on the chart default `webhook.getCert.renewInterval`
  (2h); the cadence rule is [armtls.md](armtls.md).
- `c8s-cert-wait`: a run-once gate holding the application containers until the
  first `tls.crt` exists.
- `c8s-secret`, `c8s-volume`: the fetchers, when the pod requests secrets or
  volumes ([secrets.md](secrets.md), [volumes.md](volumes.md)).

Those endpoints form the mesh, the armTLS traffic layer with its own identity
and guarantees; `c8s-mesh` is one pod's end of it ([armtls.md](armtls.md)).

Injection adds the inventory socket's supplemental group; the socket itself is
the node's, bind-mounted read-only into the pod's socket consumers by the
admission plugin as an NRI mount. `confidential.ai/cw` names the workload a pod
belongs to and selects the SAN get-cert requests, `c8s-<ENTRY>.<namespace>.svc`.
One string does all of it: `<ENTRY>` is the annotation's value, the workload
entry CDS matches, an adoption's id, and the Service suffix. A pod without
`confidential.ai/cw` is injected too but requests no SAN; the annotation becomes
mandatory as soon as the pod asks for secrets, volumes, discovery output, or a
renewal interval. `confidential.ai/c8s-san` only refines the SAN of a pod that
already carries it.

The webhook refuses a pod that occupies what injection owns — a reserved
container name, the credential volume or mount under another shape, host network
or namespaces, a pinned-mount annotation
([secrets.md](secrets.md#fixed-sidecar-mounts)) — and the validator rejects a
final shape that is not the injected one.

## CDS runs as one VM

CDS runs as one VM outside the cluster, which `c8s cds config new` writes the
configuration and the pin for. A cluster may also run its CDS as several VMs
that share one mesh CA and one store, where a replica that restarts takes the
cluster's state back from the others ([cds-ha.md](cds-ha.md)). Everything
below is the one-VM deployment. Its state is in that VM: the mesh CA key is
generated inside the process and written nowhere, released secrets live in
process memory, and the allowlist and route manifest live in a store on a
tmpfs. Any restart is a re-bootstrap:

- The replacement process mints a new CA key. Member pods stay bound to the key
  their first issuance recorded, so all of them must be recreated, the router
  included.
- Operator-written workload entries, every stored secret — every encrypted
  volume's key blob included — and the route manifest are gone; only the
  configuration's own workloads are served again, and each node keeps serving
  the policy it last applied
  ([allowlist-and-capabilities.md](allowlist-and-capabilities.md)). For its
  clock-skew window (30 seconds) it also refuses operator tokens, having
  forgotten which were spent.

Recovery re-applies all of it: the operator's workload entries with their
`secrets` grants and mount rules (`c8s allowlist upload` of a saved
`c8s allowlist export`, or `c8s allowlist apply` per entry), the route manifest
(`c8s routes add --new`, which an empty store needs), and every secret from its
escrow file (`c8s secrets put <PATH> --from-file <ESCROW>`). An encrypted
volume opens once its consumer's entry and its key are both back
([volumes.md](volumes.md#keep-the-escrow-file)).

## The router

The router is the cluster's only public entry point, in its own `c8s-router`
namespace. Its pod holds nginx, `cds-attest`, the allowlist-route proxy and the
member shape the chart renders rather than injects. `router.publicTLS.mode`
selects what terminates public TLS:

| Mode | Credential | Attested handshakes |
|---|---|---|
| `cds` (default) | A CDS-issued mesh leaf; the key stays in the pod's TEE | attest-pq and attest-lb |
| `acme` | A multi-SAN WebPKI leaf the in-pod `c8s acme` sidecar obtains over HTTP-01; TEE-held, `bare-metal` only | attest-pq and attest-lb |
| `webpki` | An operator-supplied Secret in `c8s-router`; the key is host-visible | attest-pq only |

The two attested handshakes, attest-pq and attest-lb, are
[routes-evidence.md](routes-evidence.md)'s. The mode is a trust statement:
`cds-attest` commits it into both transcripts and refuses attest-lb unless the
serving key is TEE-held, since a host holding the key could terminate a client's
TLS with the same leaf. For the same reason `c8s allowlist` and `c8s routes`
refuse a front door outside mode `cds`, wanting a direct CDS URL.
In mode `cds` attest-lb binds the mesh identity leaf, which is the leaf nginx
serves; a mesh leaf or CA outside its validity window is a credential failure,
503 `binding_unavailable`. In mode `acme` it binds the leaf
`--serving-cert-file` names and refuses with 503 `serving_leaf_rejected` while
that leaf is outside its validity window or served with a chain that has
expired. In mode `cds`, an expired intermediate in `tls.crt` gets
`serving_leaf_rejected`, and a `tls.crt` chain block that does not parse gets
503 `binding_unavailable` from attest-lb; `/readyz` and attest-pq are
unaffected.

ACME issuance covers the names the sidecar is configured with — `router.san` on
an installed cluster, the launch file's `hostnames` on a baked node — and never
one outside that set. It keeps one certificate for those whose public challenge
path reaches this router, probing each with a one-off token first, so an
unreachable name blocks no other. The certificate is kept while it covers the
reachable names, renewal fires at two thirds of its lifetime, and a covered name
that stops answering is dropped only in the last sixth — so moving a production
hostname needs its challenge path on the new router while HTTPS still reaches
the old one.

### Route manifest

CDS stores one operator-signed `c8s.routes/v1` manifest at `/routes`, in the
same store as the served allowlist, so it shares its lifetime; there is no route
seed. `cds-attest` polls `GET /routes` every `router.routing.pollInterval` (30s)
over armTLS against the same CDS pins, verifies the manifest's write token under
the operator keys, and routes by nothing else. A baked node takes those keys
from the CDS configuration its document pins; elsewhere they are Kubernetes
configuration, so whoever controls that can sign routes of their own —
detectable only by pinning the route digest or the operator keys.

- Until a manifest is applied, application requests get 503; an applied manifest
  keeps routing them however stale it is. Readiness ignores route state, so a
  new pod is Ready before its first fetch. What the attested handshakes
  refuse, and when, is [routes-evidence.md](routes-evidence.md).
- A request whose `Host` is not a manifest host, or whose path matches no route,
  gets 404. The router's own paths are never routed by the manifest.
- A workload backend is dialed as a mesh client: the peer must present a leaf
  chaining to the mesh CA, carrying that route's workload name, and that entry
  must be the same in the allowlist its leaf is stamped under as in the one
  the router's own leaf is stamped under. When the two digests differ the
  router fetches both documents from CDS's allowlist history
  (`/allowlist/objects/sha256/<hex>`, cached by digest) and compares the
  entry. A failed check is 502 `backend_digest_mismatch`: the entry was
  redefined, is missing from either document, or a document cannot be
  fetched. No backend is reached in plaintext. A router whose own leaf carries
  no stamp binds no policy digest and checks the name alone.
- An allowlist write therefore refuses only the backends whose entry it
  removed or redefined, from the router's renewal or the backend's, whichever
  comes first, until both carry the new definition. The slower of their
  `--ca-watch-interval`s, plus half an interval of jitter, plus one issuance
  bounds that; with the watch off it lasts until the next scheduled renewal.
  A backend under an entry the write added is accepted once the router's
  leaf renews under it. A router renewal under another allowlist digest refuses
  pinned requests: bound sessions and requests carrying `X-C8s-Expect-Allowlist`
  get 503 `router_digest_changed`. Other requests are forwarded under the renewed
  digest, subject to the per-backend entry check.
- An allowlist write takes effect on nodes `--allowlist-node-delay` (CDS flag,
  30s) after it is written. CDS issues certificates under it at once, and
  router certificates (`--router-cert-ttl`, 20s) last less than that, so any
  router still serving advertises it before it takes effect. A write replaced
  before it takes effect never does. When its certificate expires the router
  retires every backend pool and dials nothing until it renews.
  Its nginx supervisor checks credentials every five seconds, stops nginx on
  withdrawal, and starts it again when all served credentials are readable.
  Readiness fails while nginx is stopped. An unexpected nginx exit terminates
  the container for kubelet to restart.
- With the front door in `cds` mode the serving certificate is the router's
  mesh certificate, so a client pinning it attests again at every renewal.
- An attested session routes only by the manifest and the router allowlist
  digest its handshake bound. Once either changes the router answers 503 and
  the client attests again
  ([routes-evidence.md](routes-evidence.md#session-binding)).
- A router refuses, until it restarts, any revision below the highest it has
  accepted — one waiting for its `notBefore` included — and the same revision
  with different bytes. A CDS reset lets a lower revision be stored, so write
  above the highest any router accepted.

### Built-in allowlist route

The chart publishes CDS's `/allowlist` API through the router by default
(`router.allowlist.enabled`), as an exact `/allowlist` location and an
`/allowlist/` prefix, so a lookalike path is not exposed. An in-pod proxy holds
CDS to the endpoint and pins the admission plugin bind-mounts for a container
holding the credentials platform role, refusing a flag naming another; on an
install they come from `--cds-pin`. Reads stay unauthenticated at CDS; a
write still needs the body-bound operator token, and the operator private key
never enters the cluster. nginx rate-limits the route per client and in
aggregate. Both bounds are nginx's: CDS limits per source IP and sees the whole
front door as one pod IP, so only nginx's aggregate bound stops front-door
clients draining the bucket operator writes share.

## Existing workload adoption

`c8s install --workload-ref <ENTRY>=<namespace>/<kind>/<name>[:<port>]` adopts a
workload that is already running. After the release is ready the CLI patches
each named pod template with `confidential.ai/cw: <ENTRY>`; the rollout goes
through the webhook, and the operator pod creates the `c8s-<ENTRY>` headless
Service. `--upstream <ENTRY>` builds the first route manifest, routing `/` on
every `router.san` name to that workload's Service and port. With
`--operator-key` (the signing key, not the pinned `--operator-keys` bundle)
install stores it on CDS; without one it goes to `--routes-out`, and the router
answers 503 until stored.

With `--resolve-digests` (the default) install also writes one workload entry
per adopted workload, named `<ENTRY>`, declaring every container of its pod
template with exact mounts. CDS stamps that name on the pod's leaf, which is
what the router requires of a workload backend, with the same entry as in the
allowlist its own leaf is stamped under ([Route manifest](#route-manifest)). When two entries describe
one pod, CDS stamps neither name, and the router answers 502 for that backend
at runtime. A template with other mounts, a `subPath`, or secrets and volumes
gets an any-mounts entry and a warning; for the `--upstream` workload install
refuses, so write that entry yourself
([allowlist-entries.md](allowlist-entries.md)).

## Network policies

The chart ships one ingress policy per component it installs, each admitting
only the ports that pod answers on: 9443, 8081 and 8080 for the operator pod,
`router.nginx.httpsPort` for the router plus the ACME HTTP-01 port `8080` in
mode `acme`, and nothing at all for attestation-api and volumed, which answer
on pod loopback and a node-local socket. None of them carries a `from`, so each
narrows which port answers, not who may connect: the router is public and the
API server's address is not nameable. They are ingress-only — outward reach is
the node's packet ruleset — and additive, so another port is your own
NetworkPolicy.

## Rendering the chart

Rendering shows what a release contains. This example disables the host
image-policy installer, so only image tags are needed; the full shape wants
image digests, the DNS resolver and the cluster CIDRs.

```sh
helm template c8s internal/helmchart/cloud \
  --namespace c8s-system \
  --set cds.address=10.0.0.9:8443 \
  --set-file cds.measurementsConfig=cds-pin.json \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set armtlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false
```

The address is this cluster's CDS and `cds-pin.json` the document
`c8s cds config new` wrote beside its configuration.
