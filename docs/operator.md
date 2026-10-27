# Running a cluster

What a C8s install puts in a cluster, and what the platform operator controls
afterwards. The platform operator is the person holding the cluster's keys;
`c8s install` is the command they run, `c8s operator` is the controller pod it
deploys, and only the person's keys authorize policy. For the install itself see
[QUICKSTART.md](QUICKSTART.md); for a workload, [workloads.md](workloads.md).

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
| `c8s-cds` Deployment, Service (NodePort `30808`), PodDisruptionBudget | CDS, the Certificate Distribution Service: the cluster's trust root |
| `c8s-pod-injector`, `c8s-pod-validator`, `c8s-deny-host-namespaces` | Injection, its enforcement, and the host-namespace refusal |
| `c8s-attestation-api` and `c8s-nri-image-policy-worker` DaemonSets | Node-local evidence and the admission plugin; on `bare-metal` the node image bakes both, and the worker only carries this release's CDS pins to the baked plugin |
| `c8s-router` Deployment, Service, and the `c8s-router` namespace | The public front door |
| One ingress NetworkPolicy per installed component | See [Network policies](#network-policies) |
| `c8s-volumed` DaemonSet, the `ConfidentialWorkload` CRD | Volumes with `--volumes` ([volumes.md](volumes.md)); `--install-crds=false` skips the CRD |

Two inputs are policy rather than plumbing. `--measurements` (or
`--image-policy-file`) pins the guest CDS runs in, and the chart refuses to
render unpinned. `--operator-keys` pins the operator public keys that authorize
allowlist and route writes; without them CDS refuses every write, so a change
needing a new entry needs a reinstall. `--force` proceeds past the two guarded
prompts — no `--operator-keys`, and a fail-closed policy that would deny the
platform's own pods; `--single-node` clears the dedicated-CDS-node selector and
toleration. A measured node image boots the same chart, rendered at build time
and configured from the signed launch file; `c8s install` refuses a cluster
labelled `confidential.ai/baked=true`.

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

| Container | What it is |
|---|---|
| `c8s-mesh` | The pod's mesh endpoint, carrying its traffic over armTLS ([armtls.md](armtls.md)) |
| `c8s-cert` | get-cert: the first leaf before the application starts, then renewal on the chart default `webhook.getCert.renewInterval` (2h); the cadence rule is [armtls.md](armtls.md) |
| `c8s-cert-wait` | A run-once gate holding the application containers until the first `tls.crt` exists |
| `c8s-secret`, `c8s-volume` | The fetchers, when the pod requests secrets or volumes ([secrets.md](secrets.md), [volumes.md](volumes.md)) |

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

## CDS is a singleton

CDS runs as one replica with `strategy: Recreate`, and the default
PodDisruptionBudget (`maxUnavailable: 0`) blocks voluntary disruptions. Its
state is in the pod: the mesh CA key is generated inside the process and written
nowhere, released secrets live in process memory, and the allowlist and route
manifest live in a store on a memory-backed `emptyDir`. Any restart is a
re-bootstrap:

- The replacement pod mints a new CA key. Member pods stay bound to the key
  their first issuance recorded, so all of them must be recreated, the router
  included.
- Operator-written workload entries, every stored secret — every encrypted
  volume's key blob included — and the route manifest are gone; only the CDS
  seed is applied again, and each node keeps serving the policy it last
  applied ([allowlist-and-capabilities.md](allowlist-and-capabilities.md)).
  For `cds.jwtClockSkew` seconds (30) it also refuses operator tokens, having
  forgotten which were spent.

Persistence is refused rather than offered: `cds.persistence.enabled=true`
mounts a PVC, and the chart fails the render outside `audit` mode, because CDS's
own workload entry admits its store only on memory or encrypted storage, and no
PVC observes as either.

## Authenticated launch configuration

A measured node runs one image for both roles and takes its configuration from a
disk labelled `opkeydata` holding exactly `pubkey`, `launch.yaml`, and
`launch.yaml.sig`. The strict `c8s-launch/v1` document fixes the role (`server`
or `agent`), the cluster id, node addresses, RKE2 join tokens, the trusted role
keys, the image pins, the TLS SAN, and optionally an initial allowlist, registry
mirrors, and the server's `router` block, which carries the public hostnames,
ACME settings, and request body cap an image built before the cluster cannot
know. Non-empty `hostnames` puts the baked front door in ACME mode at boot,
while the chart value `router.publicTLS.mode` stays `cds`.

The signature covers the exact file bytes, and the launch key's public half
binds into the node's evidence: the measured initrd extends TDX RTMR[3], while
an SNP launcher sets `HOSTDATA` to `SHA-256(pubkey)`. At boot, staging
authenticates those bytes before parsing them and checks the image measurement
and the role-key relationship against fresh self-attestation. Missing, unsigned,
or inconsistent input leaves RKE2 and the role's services down; any change means
a relaunch with newly signed bytes.

`c8s node launch-config new` writes one cluster's bundle: separate server and
agent launch keys, fresh join tokens, a signed document per node, and the client
policies pinning the server and listing every identity CDS admits. The server
launch key is also the operator key for
[`c8s get-kubeconfig`](#trust-gate-c8s-get-kubeconfig) and for signed CDS
writes. Use distinct keys per cluster: evidence names the key and the image, not
the cluster, so two clusters sharing both are indistinguishable to a client
pinning them. The join tokens in the document are RKE2 enrollment credentials,
not C8s identity: the mesh wraps neither port `9345` nor `6443`, so a token
holder with network access can enroll with no C8s evidence.

## Operator credentials

### Trust gate: `c8s get-kubeconfig`

`c8s get-kubeconfig` obtains a kubeconfig from a measured node and enforces the
node's full measured identity before any credential moves. The
`--image-manifest` shape selects the platform and pins the whole guest image:
MRTD, RTMR[1] and RTMR[2] on TDX, one of the per-vCPU launch measurements on
SEV-SNP. The operator-key binding is pinned with it, as the RTMR[3] chain (the
key's seed, each digest-pinned `--workload-image`, then optionally a replaying
prefix of the policies the node measured) or as SEV-SNP `HOSTDATA` equal to
`SHA-256(operator pubkey)`. A fresh nonce-bound report comes from the
credential-release service on port `8443`, which authenticates the operator
token first. The gate proves that a genuine guest of that platform booted the
pinned image and was launched to trust this operator key — and nothing the flags
do not name.

The released certificate is `CN=operator, O=c8s:node-operators`.
`--role log-reader` asks for `CN=log-reader, O=c8s:log-readers` instead: get,
list and watch on pods, their logs, namespaces and events, nothing more. The
role travels inside the token-bound request body, so neither it nor the CSR can
be swapped, and a log-reader holder cannot release another. The node image binds
both groups to baked ClusterRoles, and the measured unit fixes the group names;
a cluster running `c8s cred-release` itself needs equivalent bindings, or
`--cert-org` and `--log-cert-org` naming groups it already binds.

### Bounded operator

The released credential is deliberately not `cluster-admin`, and the node's
guards exist to hold against its holder. The baked ClusterRole is an enumerated
allowlist with no wildcards and no path to those guards: no `bind`, `escalate`
or `impersonate`, no cluster-scoped RBAC, admission or webhook writes, no
`*/proxy`, and no PersistentVolume, StorageClass, CRD or Node writes. A baked
admission policy re-checks the same exclusions for every principal in a `c8s:`
group, whatever RBAC says, and refuses any write in the privileged namespaces
(`kube-system`, `c8s-system`, and `c8s-router`), where a pod or an edited
DaemonSet is root on the node. It also refuses a Service that would take over a
platform address a member pod's packet filter passes by IP: `spec.externalIPs`,
and a ClusterIP in `10.53.0.0/24`, where the platform pins the resolver and the
baked cluster-metrics exit
([armtls.md](armtls.md#cluster-metrics)). The credential-release service keeps
its listener closed until those guards are live, match their copies on the
read-only root, and pass server-side dry-runs of the deny paths; exec, attach,
port-forward and ephemeral containers are denied for every credential
([node-exec-mode.md](node-exec-mode.md)).

Revocation is a launch-time decision: deleting a binding cuts access until the
next boot only, because the manifests sit on the read-only root and RKE2's state
lives on the encrypted scratch disk, which no reboot survives. To revoke
durably, relaunch with a rotated server launch key and new documents.

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
from its signed launch configuration; elsewhere they are Kubernetes
configuration, so whoever controls that can sign routes of their own —
detectable only by pinning the route digest or the operator keys.

- Until a manifest is applied, application requests get 503; an applied manifest
  keeps routing them however stale it is. Readiness ignores route state, so a
  new pod is Ready before its first fetch. What the attested handshakes
  refuse, and when, is [routes-evidence.md](routes-evidence.md).
- A request whose `Host` is not a manifest host, or whose path matches no route,
  gets 404. The router's own paths are never routed by the manifest.
- A workload backend is dialed as a mesh client: the peer must present a leaf
  chaining to the mesh CA, carrying that route's workload name, stamped under
  the same allowlist digest as the router's own leaf. A failed handshake is
  502 — `backend_digest_mismatch` when the two digests differ — and no backend
  is reached in plaintext. A router whose own leaf carries no stamp binds no
  policy digest and checks the name alone.
- The router and its backends renew on their own schedules, so after an
  allowlist write a workload route refuses requests until both carry the new
  digest: 502 `backend_digest_mismatch` while a backend lags, 503
  `router_digest_changed` while the router's own pools still hold its previous
  digest. The slower of their `--ca-watch-interval`s, plus half an interval of
  jitter, plus one issuance bounds that; with the watch off it lasts until the
  next scheduled renewal.
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
install they come from `--measurements`. Reads stay unauthenticated at CDS; a
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
what the router requires of a workload backend, under the same allowlist digest
as its own leaf ([Route manifest](#route-manifest)). When two entries describe
one pod, CDS stamps neither name, and the router answers 502 for that backend
at runtime. A template with other mounts, a `subPath`, or secrets and volumes
gets an any-mounts entry and a warning; for the `--upstream` workload install
refuses, so write that entry yourself
([allowlist-entries.md](allowlist-entries.md)).

## Network policies

The chart ships one ingress policy per component it installs, each admitting
only the ports that pod answers on: `cds.port` for CDS, 9443, 8081 and 8080 for
the operator pod, `router.nginx.httpsPort` for the router plus the ACME HTTP-01
port `8080` in mode `acme`, and nothing at all for attestation-api and volumed,
which answer on pod loopback and a node-local socket. None of them carries a
`from`, so each narrows which port answers, not who may connect: the router is
public, the API server's address is not nameable, and the CDS NodePort arrives
off-cluster. They are ingress-only — outward reach is the node's packet ruleset
— and additive, so another port is your own NetworkPolicy.

## Rendering the chart

Rendering shows what a release contains. This example disables the host
image-policy installer, so only image tags are needed; the full shape wants
image digests, the DNS resolver and the cluster CIDRs.

```sh
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set cds.measurements[0]=abababababababababababababababababababababababababababababababababababababababababababababababab \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set armtlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false
```

The measurement is a placeholder; a real install passes the node image's own.
