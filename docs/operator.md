# C8s operator and Helm chart

The C8s operator installs the Kubernetes-facing C8s components. It hosts
status-mirror controllers, serves the pod-injection admission webhook, and
ships an embedded Helm chart for installing the operator, CRDs, RBAC, webhook
resources, attestation-api DaemonSet, and CDS (the Certificate
Distribution Service trust root).

## Overview

The operator tree is built around these pieces:

- `cmd/c8s operator` runs the controller-runtime manager, the
  `ConfidentialWorkload` status-mirror controller, and the pod-injection
  admission webhook.
- `cmd/c8s install` extracts the embedded chart from `internal/helmchart`
  and shells out to `helm upgrade --install`.
- `internal/helmchart/c8s` installs the operator Deployment and Service, the
  CRDs, RBAC, webhook configuration, attestation-api DaemonSet, and CDS.
- `internal/webhook` injects get-cert containers into opted-in pods so each
  workload can fetch and renew a leaf certificate through CDS.

The operator does not inject the armTLS mesh sidecar. Pod-to-pod mTLS remains
the responsibility of node-level `armtls-mesh`, deployed as a DaemonSet by
the chart or as systemd services by the measured node image. The chart-managed
mesh excludes the namespaces in `armtlsMesh.iptablesSync.excludeSourceNamespaces`
(default `kube-system`) as local traffic sources, so on kind/kubeadm-style
clusters where the API server runs as a `kube-system` pod, in-cluster webhook
callers do not get captured by the pod-to-pod mesh path. The release namespace
is deliberately not excluded: router's egress to workload pod IPs must be
intercepted to get attested mTLS, and the control plane's own traffic dials
Service VIPs, which the mesh never intercepts. The exclusion is one-sided: it
removes those pods as PREROUTING sources but keeps their IPs in the destination
ipset, so a workload that connects to a `kube-system` pod by pod IP — bypassing
the Service VIP — will still be DNATed into the mesh and fail mTLS against a
peer with no armtls sidecar. In-cluster Service-VIP traffic to those namespaces
is unaffected because kube-proxy DNATs the VIP before the mesh chain matches.

Confidential-workload pods (label `confidential.ai/cw`) get a stricter
inbound posture from the always-on cw guard: the mesh drops FORWARD-path
traffic to their pod IPs, so Service-VIP dials and excluded-namespace sources
are blocked instead of reaching the workload in plaintext.
`armtlsMesh.cwInboundEnforcement.passthrough` (default `udp:53,tcp:53`) is the
reply allowlist that keeps DNS working; an empty list is strict drop-all. It
admits replies only on the stock ephemeral window (32768-60999), which costs a
cw pod its DNS if the pod moves `net.ipv4.ip_local_port_range` *and* the
dataplane breaks the reply's conntrack tuple — see the
`ARMTLSMeshCWInboundDrops` alert description for the triage path.
Only mesh-delivered traffic and node-local host processes
(kubelet probes) reach cw pods.

## Ownership model

Installing the C8s chart is a platform-admin operation, not a fully
self-service application-team workflow.

The install creates or updates cluster-scoped resources such as CRDs, RBAC,
the operator Deployment, the webhook Service and configuration, and the
attestation-api DaemonSet. Enabling injection also requires platform-owned
prerequisites:

- the chart-managed CDS Service reachable from workload pods;
- allowlist storage and a measurement allowlist for any workload allowed to
  mutate the allowlist;
- a CDS public-bundle PVC for CA continuity;
- nodes with the expected TEE device access for attestation-api;

After the platform installs those pieces, workload opt-in is self-service:
application teams annotate their pod templates with `confidential.ai/cw`.

## Code layout

The main source directories are:

| Path | Purpose |
|---|---|
| `cmd/c8s/` | User-facing operator and install CLI commands. |
| `internal/controller/` | controller-runtime manager, webhook bootstrap, and status mirror setup. |
| `internal/webhook/` | Pod mutation logic, get-cert args, cert volume permissions, and unit tests. |
| `internal/helmchart/c8s/` | Embedded Helm chart templates and defaults. |
| `internal/helmchart/chart_test.go` | Helm render tests for the supported chart-managed CVM-only shape. |
| `cmd/get-cert/` | Certificate bootstrap and renewal helper, including private-key file mode handling. |

## Default install behavior

The supported chart shape is chart-managed and CVM-only. The chart does not
support a non-CVM install shape or a bring-your-own CDS endpoint shape.

`c8s install` (including `--cvm-mode=bare-metal`) is for chart-managed clusters.
The [measured node image](../node-guest-image/README.md) runs CDS, the armTLS
mesh, router and operator as Kubernetes workloads rendered from this chart
at **image build time**. Their pinned container images are baked into the
image too. RKE2 applies the manifests at boot; no guest Helm installation is
needed. The local attester, signed-launch verification and NRI enforcement
remain host services needed before those workloads can start. `c8s install`
refuses a cluster whose `c8s-system` namespace carries `confidential.ai/baked=true`.

Core Pods mount public signed identity inputs read-only from `/run/c8s-node`;
they never mount the private launch directory. The measurement covers the
initial manifests and images, while Kubernetes API changes remain subject to
the existing trusted-cluster-administrator boundary. Changing core versions
requires rebuilding and relaunching with updated signed image pins. The
current schema does not support rolling upgrades across different measured
images; CDS's ephemeral CA also requires certificate re-bootstrap when it
restarts.

### Authenticated launch configuration

A measured node uses one image for both `server` and `agent`. Each boot
requires an ISO labelled `opkeydata` containing exactly the launch inputs
`pubkey`, `launch.yaml`, and `launch.yaml.sig`. The private signing key stays
with the operator. `pubkey` is bound to the guest by the platform: the measured
initrd extends TDX RTMR[3], while an SNP launcher must set HOST_DATA to
`SHA-256(pubkey)` over the exact PEM file bytes.

The strict `c8s-launch/v1` document selects the role, cluster identity, node
addresses, RKE2 join credentials, trusted role keys, image pins and TLS SAN.
It accepts an optional `workloads` string containing a complete
`c8s.allowlist/v1` JSON document, and an optional `registryMirrors` map from
a registry host to one `http://<IPv4>[:port]` endpoint, at most 8 (for
example `ghcr.io: http://10.43.0.5:5000`). Staging writes the map as
`/etc/rancher/rke2/registries.yaml`, so containerd pulls through the mirror
first and from the registry itself as the last resort. The mirror is plain
http and gets no registry credentials: the host can see which blobs a node
pulls, and a private image falls back to its registry unless the mirror holds
its own credentials. This is acceptable because image references stay
digest-pinned and containerd checks every blob against its digest, so a
mirror can withhold an image but cannot change what a node runs. It does not
accept Helm values, arbitrary service arguments or component toggles. The
measured image runs volumed as a host service, so encrypted volumes
([docs/volumes.md](volumes.md)) open on every node without an install. Its
router always publishes the applied route manifest
([Route manifest](#route-manifest)).

Use **distinct launch keys for server and agent roles, and new keys for
each cluster**. `clusterID` is a descriptive RFC1123 label; the distinct
launch keys establish cluster separation during peer verification. Keep one
server key and one or more agent keys. An agent document must omit
`rke2.serverToken` entirely, including an empty field; it receives only the
agent token. Server and agent tokens must differ and contain 64 lowercase
hexadecimal characters each.

`c8s node launch-config new` creates everything one cluster needs: a server
launch key, an agent launch key, fresh join tokens, a signed `launch.yaml`
per node and the client policy that pins the server. Give it the trusted
`manifest.json` published with the exact node image, the server's guest IPv4
address that every node can reach, and the agent names. On SNP, also pass
the VM's vCPU count, which selects the launch digest. `--registry-mirror
ghcr.io=http://10.43.0.5:5000` (repeatable, once per registry) sets
`registryMirrors`; agents inherit it from the server document.

```sh
c8s node launch-config new --out demo --cluster-id demo \
  --image-manifest manifest.json \
  --server-address 10.0.0.10 \
  --agent demo-agent-1 --agent demo-agent-2
# SNP: add --vcpus 8 (the VM shape's launch digest); TDX has one per image.

xorriso -as mkisofs -V opkeydata -o demo/server.iso demo/server
xorriso -as mkisofs -V opkeydata -o demo/demo-agent-1.iso demo/demo-agent-1
```

`c8s launch-config` remains available as a compatibility command for existing
launch scripts; both paths use the same implementation.

The bundle directory is created new and never reused:

| Path | Purpose |
|---|---|
| `demo/server.key` | server launch key; also the operator key for `c8s get-kubeconfig --operator-key` and signed CDS writes (not written with `--operator-key`) |
| `demo/agent.key` | the agent launch key every agent boots with |
| `demo/server.json` | `C8S_MEASUREMENTS_CONFIG` for clients of this cluster |
| `demo/peers.json` | every launch identity CDS admits and serves; `c8s cds verify --served-policy-file` |
| `demo/server/` | `pubkey`, `launch.yaml`, `launch.yaml.sig`: the server's opkeydata |
| `demo/<agent>/` | the same three files for each agent |

To keep an operator key that clients already pin across clusters, pass it
with `--operator-key op.key` (an ECDSA P-256 key) instead of letting the
command generate one. It becomes the server launch key and stays where it is:
the bundle has no `server.key`, so use `op.key` wherever this guide says
`demo/server.key`. Add `--operator-pubkey op.pub` (the file
`c8s keys new --pub-out` wrote) to refuse a key that does not match it byte
for byte: on SNP, HOST_DATA hashes those bytes. The agent key is always
generated.

Node evidence and client pins name the server key and the image, not the
cluster. Clusters that share an operator key and an image therefore look the
same to a client that pins them, and a host can boot one cluster's server with
the other's signed server document. Use a distinct key where that matters.

An agent can be added to a running cluster without touching the server:
`c8s node launch-config add-agent --bundle demo --name demo-agent-3` derives
its document from the server's (same cluster, image, agent token and keys,
never the server token) and signs it with the agent key. A server created
without `--server-address` autodetects its own; `add-agent` then needs
`--server-address`.

The generated document is the strict schema below; edit it only when a field
the command does not expose is needed, then re-sign with
`c8s keys sign-launch --key demo/server.key --force demo/server/launch.yaml`.

Attach the corresponding ISO to each VM along with its required scratch
disk, booting the **same image and supported VM shape** for both roles.
The image is built separately for TDX and SNP; their image digests and
measurements are different. SNP's launch digest also depends on vCPU count.
Every `image.measurement` is 96 lowercase hexadecimal characters. TDX
requires exactly `image.rtmrs[1]` and `[2]`, each also 96 characters; MRTD alone
pins firmware, not the guest kernel and verity root. Do not put RTMR[0] or
RTMR[3] in the image pins: RTMR[3] is checked against each role's launch key.

For a server, `server.address` may be omitted: staging uses `node.ip`, or
selects the primary IPv4 address if that is also omitted. An agent must
always carry its server's reachable IPv4 address. `node.ip` is optional
(`0.0.0.0` means autodetect); `node.externalIP` is an optional explicit unicast
IPv4 address. `node.name` must be unique within the cluster. `tlsSAN` defaults
to `c8s.local` and must be a lowercase DNS hostname. Arbitrary routes and CORS
overrides are not launch settings in this image.

A server document may carry an optional `router` block. It sets the router's
public hostnames and request body limit at boot, because the image cannot know
them at build time. An agent document must not carry it.

```yaml
router:
  hostnames: ["candidate.api.confidential.ai"]
  acmeEmail: "ops@example.com"
  acmeDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"
  maxRequestBodyBytes: 67108864
```

- `hostnames` are lowercase DNS names. When set, the in-guest `c8s acme`
  sidecar gets one Let's Encrypt certificate for them over HTTP-01 on port 80
  (front-door mode `acme`). When empty, nginx serves the CDS-issued mesh leaf
  (front-door mode `cds`) and the sidecar stands by. The mode selects the
  certificate through `router/tls.conf`, which nginx includes.
- `acmeEmail` and `acmeDirectoryURL` are optional and need `hostnames`. Use a
  staging directory for tests.
- `maxRequestBodyBytes` is the largest application request body, in bytes, the
  public listener accepts; a larger one gets nginx's 413. It is optional, must
  be positive and defaults to 1048576 (1 MiB). nginx streams the body to the
  routing listener rather than holding it, so a large limit costs no router
  disk. It reaches nginx through `router/request-body.conf`. Protocol
  endpoints keep their own limits: 16 KiB for the attestation handshakes,
  8 MiB for a tunnel record and 1 MiB for the built-in allowlist route.

The block names no backend: a baked router routes by the route manifest, as
any router does (see [Route manifest](#route-manifest)). A document that
still carries `router.upstream` is refused; write its route with `c8s routes`.

`c8s node launch-config new` writes the block from `--router-hostname`
(repeatable), `--acme-email`, `--acme-directory-url` and
`--router-max-request-body-bytes`.
The block is part of the signed bytes. Boot preparation publishes it as files
in `/run/c8s-node/router/`, which the router pod reads at start. To change it,
re-sign the document and relaunch the server.

For KubeVirt, the same three files can be supplied as a Secret-backed ISO:

```sh
kubectl -n YOUR_NAMESPACE create secret generic demo-server-launch \
  --from-file=pubkey=demo/server/pubkey \
  --from-file=launch.yaml=demo/server/launch.yaml \
  --from-file=launch.yaml.sig=demo/server/launch.yaml.sig
```

Reference that Secret in the VM's volume with
`secret: {secretName: demo-server-launch, volumeLabel: opkeydata}` and attach
it as a read-only virtio disk. Repeat with the agent's files and a separate
Secret. On SNP, the launcher must additionally commit the corresponding
public-key hash as HOST_DATA; attaching the disk alone is insufficient.

`c8s keys sign-launch` signs the exact file bytes with ECDSA P-256/SHA-256
and writes an ASN.1 DER signature encoded as one base64 line to
`<file>.sig`. It does not overwrite an existing signature unless `--force`
is passed. Any later edit requires a new signature. At boot, `rke2-role.service` calls
`c8s launch-config stage`, which authenticates those bytes before parsing,
checks the complete software measurement and role-key relationship against
verified self-attestation, then publishes the role marker last. Missing,
unsigned or inconsistent input leaves RKE2 and role-dependent services down.
Changing role or launch configuration requires a relaunch with a newly
signed bundle and the corresponding role's hardware-bound public key.

The verified files live in root-only `/run/confos/launch`. `peers.json`
contains the software/key tuples for this cluster's server and permitted
agents; `cds.json` contains only its server. Their shared measurement-file
schema carries `approver_key` as the exact PEM string alongside each entry's
image measurement and TDX RTMR tuple. This lets peers accept both roles while
CDS clients require the authorized server despite identical software images.
The schema belongs to attestation-go's `refvalues` package: `approver_key`
maps to `remote.ImagePin.Anchor`. `remote.EnforceImages` checks the image and
calls `runtimemeasure.VerifyBinding` for that same pin, so an image cannot
borrow another entry's authorized key. C8s passes these complete pins through
`remote.Policy.Images`; legacy flags that cannot carry anchors are refused
where they would weaken enforcement.
Boot preparation copies the public identity policies to `/run/c8s-node`;
core Pods mount that directory read-only without access to the private launch
directory. The operator forwards the full server policy to injected workload
helpers, which use the in-cluster CDS Service URL. NRI uses the same server
policy from private staging and reaches CDS through the signed server
address and NodePort. Join tokens and private keys never enter the public
policy directory.

Join tokens remain secret RKE2 enrollment credentials. The armTLS mesh protects
selected pod traffic; it does not wrap the RKE2 supervisor on port `9345` or the
Kubernetes API on port `6443`. A token holder with network access can attempt
RKE2 enrollment without a C8s armTLS identity, including from a non-confidential
pod. The server token carries server-enrollment authority; the separate agent
token only permits agent enrollment. Neither token supplies the launch signing
key or satisfies the image-and-role-key attestation policy. See
[RKE2 token management](https://docs.rke2.io/security/token).

Signed launch media authenticates configuration but does not encrypt it. An
infrastructure operator able to read the launch ISO or outer-cluster Secret can
read its join tokens; root-only staging protects them inside the guest. The
current 64-hex tokens use RKE2's short-token format, which does not pin the
cluster CA during initial enrollment. The signed server address alone does not
authenticate that CA. See [RKE2 token formats](https://docs.rke2.io/security/token#token-format).

### Chart-managed defaults

- The chart renders webhook, attestation-api, and CDS together.
- The webhook is wired to the chart-managed CDS Service.
- CDS verifies evidence and signs workload CSRs in one process.
- allowlist admin uses operator-signed JWTs through CDS; the chart does not render a
  CDS allowlist password or attestation-api API key into Kubernetes
  Secrets.
- Sandbox identity needs the node addresses CDS may dial for a pod's admission
  inventory. CDS derives them **live from the cluster's node objects** — one
  host route per node InternalIP, kept current as nodes are added, replaced,
  or removed — over read-only node access the chart grants its ServiceAccount.
  A host route per node rather than a covering range, because on a CNI that
  assigns pod IPs from the node subnet (AWS VPC CNI, Azure CNI) any range
  covering the nodes covers the pods too, and the bound would be absent while
  looking configured. `c8s install` preflights the same derivation and fails
  rather than proceeding if it cannot determine them or a node address sits
  inside a pod range; such an address is excluded from the bound at runtime
  too, and CDS logs it.

  On a cluster whose node network is separate from the pod network, pass
  `--node-cidr <range>` instead: CDS then uses the static range and the chart
  grants no node access. (docs/armtls.md, "Sandbox identity".)

- `image.tag` or `image.digest`, `attestationApi.image.tag` or
  `attestationApi.image.digest`, and `cds.image.tag` or
  `cds.image.digest` are required; the CLI passes its build version when
  running `c8s install`. Unstamped local builds report version `dev`, and the
  install CLI maps that to the `main` branch tag because CI does not publish
  `dev` (CI publishes `main` and `latest` for every image on the default
  branch).

This means a default platform install creates the operator, CRDs, RBAC,
webhook, attestation-api, and CDS. It does not mutate
application workloads until those workloads opt in with
`confidential.ai/cw`.

Install with the CLI. Adopt a running workload as a CW and route the front
door to it with `--upstream` (see [Existing workload adoption](#existing-workload-adoption)
and [Route manifest](#route-manifest)). The ref's port is the port the
workload listens on; its injected endpoint holds the mesh leaf the router
verifies:

```bash
c8s install \
  --workload-ref vllm=vllm/deployment/serving:8443 \
  --upstream vllm --operator-keys operator.pub \
  --operator-key operator.key --measurements CDS_DIGEST
```

### Existing workload adoption

If vLLM is already deployed, `install` can adopt the router as one CW and the
serving engine as another, giving each its own confidential workload identity
without any GitOps overlay wiring:

```bash
c8s install \
  --workload-ref vllm-router=vllm/deployment/vllm-deployment-router:8443 \
  --workload-ref vllm-engine=vllm/deployment/<serving-engine-deployment> \
  --upstream vllm-router
```

The ref syntax is `<cw-id>=<namespace>/<kind>/<name>[:<port>]`, where kind is any
resource exposing a pod template at `spec.template` (`deployment`,
`statefulset`, `daemonset`, or an operator CRD such as `<kind>.<group>`); the
optional `:<port>` is the port the workload listens on, needed on the ref
`--upstream` selects. After Helm reports the C8s release ready, the CLI patches
each workload pod template with `confidential.ai/cw: <id>`. Those rollouts go
through the webhook, and the workload-service reconciler creates the `c8s-<id>`
headless Services. `--upstream vllm-router` routes `/` on every `router.san`
DNS name to `c8s-vllm-router.vllm.svc.cluster.local:8443` (its `<cw-id>` must
be one of the adopted refs, carrying a `:<port>`); see
[Route manifest](#route-manifest).

With `--resolve-digests=true`, install writes one
`nriImagePolicy.bootstrapAllowlist.workloads` entry per adopted workload, named
after its cw id and declaring every container of its pod template in its own
role (init containers and native sidecars as `initContainers`) under any
command, args and env. Containers with the same image and mounts are declared
once; the same image under different mounts is declared once per mount set.
Image admission then allows the rollout, and CDS stamps the cw id on the
workload's certificate, which the router requires of a workload backend.

Mounts in that entry are exact: each container may mount the injected cert
volume and its own memory-backed `emptyDir` volumes, nothing else. When the
template does any of the following, install writes the entry admitting any
mounts and warns. CDS still names the pod after the entry, so a route that
`c8s routes add` writes to it later trusts those mounts. For the `--upstream`
workload, install refuses instead; write that entry yourself with
`c8s allowlist`:

- mounts any other volume. A `hostPath` puts host-controlled content under the
  app; an exact rule cannot admit a ConfigMap, Secret, PVC or disk `emptyDir`.
- mounts a `subPath` or `subPathExpr` of any volume, which the node observes
  as a data mount.
- requests C8s secrets or encrypted volumes.
- sets `confidential.ai/c8s-cert-dir` to a path that is not absolute.

Install also refuses an adopted workload whose pod another entry of the seed
it renders describes, under any command line: another adoption with the same
images and mounts, a `-f` entry, or the entry the chart seeds for a component,
CDS or, with the router enabled, router nginx. CDS cannot tell which entry
names such a pod, so it stamps neither. With
`--resolve-digests=false`, install writes no entry, and you add one named
after the cw id.

`c8s install --install-crds=false` passes Helm's `--skip-crds`; CRDs are
advisory and not required for pod injection. That path also disables the
CRD-backed status mirror controller; if CRDs are absent at runtime, the
operator skips that controller rather than failing startup.

The default `deny-host-namespaces` policy rejects host namespaces outside
trusted platform namespaces.

## Uninstall

`c8s uninstall` reverses `c8s install`. It runs `helm uninstall` to remove the
release (operator, CDS, attestation-api, armtls-mesh, router, the
webhook configurations and admission policies). Both webhook configurations are
release-tracked, so they are deleted with the release — a `failurePolicy: Fail`
webhook cannot outlive the operator Service and block pod creation
cluster-wide.

It then **sweeps the host-side artifacts** that chart hooks cannot guarantee
were removed: chart-installed NRI policy, armtls-mesh netfilter state, the
managed RKE2 containerd-prep template, and `c8s volume attach` LIO disks.
Baked node-image components are preserved.
The host paths are read from the release's computed values *before* deletion,
so install-time `-f` overrides are honored. `--host-sweep=false` skips this cleanup.

The sweep removes:

- the NRI image-policy containerd registration (drop-in or managed config
  block), binary, config, and state directories. It skips these on the C8s
  node image, detected via the baked-only `nri-node-ip.service`: that stack is
  the image's to keep, not the release's to delete;
- the `ARMTLS-MESH` chains and base-chain jumps in `iptables` and `ip6tables`,
  and the `ARMTLS-MESH-*` ipsets. The mesh's own preStop deliberately keeps the
  fail-closed guard, so this state survives healthy uninstall. A stale
  `OUTPUT` redirect blackholes host-originated pod traffic for non-root users;
- on RKE2, the sentinel-marked containerd template written by containerd-prep
  and its lock file, skipped on the baked node image by the same rule;
- the LIO loopback disks `c8s volume attach` built, torn down the way
  `c8s volume detach` does. Only a `fileio_0` backstore whose unit serial is
  `c8s-vol-<name>` and the loopback target attach derives from it are touched.
  A disk is left in place and named in the sweep log when it or one of its
  partitions has a holder (an open dm-crypt mapping), is mounted in any
  process's mount namespace, or is active swap; run
  `c8s volume detach <name>` once it is released. A process holding the raw
  device open with no mount or holder is not detected, as `detach` does not
  detect it either. A disk whose use cannot be read, or an idle disk that
  will not tear down, stays and fails the sweep.

  To stay admissible under the release's allowlist, the sweep replays the
  script the release's chart pinned, so this step applies only to releases
  installed from a chart that carries it. For an older release the uninstall
  prints a notice: run `c8s volume detach <name>` on each node for every
  attached volume, or, once the release is gone, run
  `c8s uninstall --host-sweep-only`, which runs this CLI's own sweep.

The swept paths are cluster-global, so running two C8s releases in one
cluster is unsupported: uninstalling either strips the other's host state.

Guardrails:

- Uninstall refuses while pods hold encrypted volumes. Delete those workloads
  first; `--force` bypasses the guard and may leave device mappings behind.
- `--host-sweep-only` runs only the host sweep, for a cluster whose release a
  bare `helm uninstall` already removed but whose nodes still carry artifacts;
  it uses the chart defaults and the distro detected from the cluster.
- `--delete-crds` and `--delete-namespace` are **off by default** and
  destructive: the former deletes the `ConfidentialWorkload` CRD and every
  `ConfidentialWorkload` object with it; the latter deletes the release
  namespace and everything left in it.

Requires the `helm` and `kubectl` CLIs on `PATH`. See
[`docs/install-flows.md`](install-flows.md#uninstall-flow) for the uninstall
sequence and host sweep.

## Chart-managed CDS

The supported deployment is chart-managed CDS running inside the intended CVM
trust boundary.

The chart installs a CDS Deployment, Service, ServiceAccount, and either an
`emptyDir` allowlist DB (a PVC when `cds.persistence.enabled=true`, which
the chart accepts only in `audit` mode). The
operator injects pods with the chart-managed CDS Service URL. Allowlist
writes (`POST`, `PUT`, `DELETE /allowlist`) are authorized by an operator key:
the caller presents a short-lived token signed by an operator EC private key
whose public half is pinned in `cds.operatorKeys`. The token algorithm must
match the key's curve: ES256 for P-256, ES384 for P-384, ES512 for P-521; CDS
rejects any other pairing. The `c8s allowlist` CLI mints
that token (see the README, "Managing the image allowlist"). Without
`cds.operatorKeys` set, allowlist writes are rejected while reads keep serving.

Operator clients construct signed requests through `operatorauth.NewRequest`,
which binds the token to the actual HTTP method, parsed URL path (including
any base URL prefix), and an owned copy of the body.

CA-bundle refresh traffic uses the chart-managed cluster Service. Trust for
those flows comes from authenticated certificate issuance and CA continuity
checks.

The chart does not render a CA private key into
a Kubernetes Secret. CDS generates its mesh CA key inside the process, keeps it
in memory, and persists only the public CA bundle in the configured
public-bundle PVC.

Minimal allowlist-write values (pin operator public keys):

```yaml
cds:
  operatorKeys: |
    -----BEGIN PUBLIC KEY-----
    ...operator EC public key...
    -----END PUBLIC KEY-----
```

Prefer `c8s install --operator-keys operator.pub`, which reads the file and
sets this value for you. The router also verifies route manifests under these
keys. In a GitOps flow, `c8s render-values --operator-keys
operator.pub` embeds the content into the emitted values.

The value is the PEM **content**, never a file path — a path from the machine
that rendered the values is meaningless in-cluster, and the chart fails the
render when the value doesn't look like PEM.

### Operational warning: CDS is a singleton

CDS runs as a single replica with the in-memory mesh CA key, and **any
restart is a full re-bootstrap event**: the replacement pod generates a
fresh CA whose public key is not signed by anything armtls-mesh already
trusts. `pkg/armtls/cdsclient`'s continuity check then refuses the new CA on
the next `/ca` poll, CDS keeps signing leaves with the new key, no workload
trusts them, and the mesh degrades as old leaves expire. Recovery is to
restart every workload so its get-cert init container re-runs the CDS
provisioning flow.

The router discovery endpoints (`/.well-known/mesh-ca.pem`,
`/.well-known/cds-cert.pem`, `/v1/discovery`) track the new CA without a
router restart: the c8s-cert sidecar polls CDS's `/ca` every
`router.certProvisioning.caWatchInterval` (default 1m; values below 1s are
rejected, `"0"` disables) over the same
armTLS-verified channel it obtains certificates on, and re-issues its leaf —
rewriting the served CA bundle and discovery document — as soon as CDS holds
a CA the served bundle is missing. External clients that pinned the old CA
must still re-fetch it from the discovery endpoint.

An allowlist write has a similar effect on a router that requests workload
claims: its leaf stamps the policy snapshot it was issued under, and strict
clients reject a leaf naming a superseded policy. The same watch tick also
polls CDS's `/allowlist` and re-issues the leaf when the served policy moves.
CDS answers 304 while nothing changed, so an idle poll is cheap. Strict
clients recover without a router restart within one poll interval, plus up to
half an interval of jitter, plus one issuance.

An allowlist write does not interrupt workload routes whose entry it leaves
unchanged. The router reads the current allowlist from CDS on every route
poll (`--routes-poll-interval`). It forwards to a workload backend when the
entry named in the backend leaf's stamp is in the current allowlist with the
same canonical content as in the document the leaf was stamped under. It
fetches that document from CDS's allowlist history
(`GET /allowlist/objects/sha256/<digest>`) and caches the last 16 by digest.
A write that removes or redefines an entry cuts that entry's backends off at
the router's next route poll: their pooled connections retire and new
connections get 502 `backend_entry_changed` until the backend re-issues under
the current allowlist (one `--ca-watch-interval`, plus half an interval of
jitter, plus one issuance). The check fails closed: a stamped document CDS
can no longer serve, as after a CDS reset, is refused the same way until the
backend re-issues.

CDS renews its mesh CA certificate at half its configured lifetime under the
same process-lifetime key. Workloads pick up the current certificate on their
next `/ca` refresh, and the continuity check accepts its signature under the
trusted key. A CDS restart replaces the key and requires re-bootstrap.

With CDS a singleton:

- run CDS with `replicas: 1` and `strategy: Recreate` (default in
  this chart);
- guard the CDS Deployment with a PodDisruptionBudget that blocks
  voluntary disruptions;
- treat any CDS restart as a planned maintenance event with workload
  churn;
- watch the `key_id` in CDS's mesh CA log lines: a renewal moves the
  `fingerprint` and keeps the `key_id`, so a new `key_id` is a new key and
  every workload needs re-provisioning.

### Operator-added allowlist entries across restarts

For the measured node image, CDS stores its database at `/mnt/c8s-data/cds/allowlist.db`
in the Pod's `emptyDir`. A container restart preserves that directory; Pod
recreation or a VM reboot loses it. The baked component seed and optional
signed `workloads` document initialize the new store; reapply any later
operator changes. The CA signing key is in process memory and changes on
any CDS process restart, so plan for certificate re-bootstrap even when the
database survives. This image does not expose a persistent-volume switch in
launch configuration.

For chart-managed CDS:

Pod recreation also resets the **served allowlist**. CDS seeds its store
from the install seed once, at startup, then serves whatever an operator writes
with `c8s allowlist add` or `apply`. Without `cds.operatorKeys` nothing can
write, so an upgrade that changes a component's shape needs a reinstall; set
the keys when you install (see "Known limitations" in
[`allowlist-and-capabilities.md`](allowlist-and-capabilities.md)). With `cds.persistence.enabled=false`
(the default), that store is a memory-backed `emptyDir` capped by
`cds.persistence.memorySizeLimit` (64Mi) and counted toward
`cds.resources.limits.memory`: it survives a container restart,
but drain, upgrade or scale-down can recreate the Pod and lose every
operator-added entry. CDS logs a warning at startup when persistence is off.
Re-apply the entries after the store is recreated. The chart refuses
`cds.persistence.enabled=true` outside `audit` mode: CDS's component entry
admits its store only on memory or encrypted storage, and no PVC observes as
either (see [`allowlist-and-capabilities.md`](allowlist-and-capabilities.md)). The chart-seeded component entries are
unaffected — they are re-seeded and, unlike dynamic entries, are also admitted
from the plugin's base allowlist. Recreating the store also resets the
allowlist version counter, and
every enforcer ignores a served version at or below the one it last applied
(`docs/allowlist-and-capabilities.md`, "Refresh and anti-rollback"): a plugin
that had applied version N stays on that policy until the restarted
CDS counts past N again, or the plugin itself restarts.

### Route manifest

CDS stores one signed route manifest (`c8s.routes/v1`) at `/routes`, in the
same database as the allowlist, so it shares the allowlist's lifetime. There
is no route seed: after CDS starts with an empty database, write the manifest
again. CDS logs a warning at startup when it holds none.

The router routes only by this manifest. Its `cds-attest` sidecar polls
`GET /routes` from the chart-managed CDS every `router.routing.pollInterval`
(default 30s). It verifies CDS against the same pins as the allowlist route.
It verifies the manifest against the operator keys: the node's launch
configuration on a baked node, else `cds.operatorKeys` (`c8s install
--operator-keys`), else the verified CDS's `GET /operator-keys`. That last
source needs a CDS pin or, on a development cluster only,
`router.routing.allowUnpinnedCDS=true`; `c8s install` refuses otherwise (see
[Route by the manifest](#route-by-the-manifest)). nginx sends every request
that no protocol endpoint claims to the sidecar's
loopback routing listener (`router.routing.port`, default 8802). Requests
decrypted from the attested tunnel route by the same manifest. Routing
follows these rules:

- Until the router applies a manifest, application requests get 503 and
  attested sessions are refused with `routes_unavailable`. Readiness does not
  wait for a manifest, so `c8s install --wait` completes first. An upgrade
  rollout that also resets a non-persistent CDS
  (`cds.persistence.enabled: false`) therefore leaves the front door
  answering 503: new router pods become Ready before their first fetch, and
  the old pods are gone. Persist CDS, or run `c8s routes put` after the
  upgrade.
- A request whose `Host` is not a manifest host, or whose path matches no
  route, gets 404. The router's own paths (`/allowlist`, `/.well-known/c8s/`,
  `/.well-known/acme-challenge/`, the discovery and certificate paths,
  `/readyz`, `/healthz`) are never routed by the manifest.
- A workload backend (`workload`) is reached as a mesh client of the member
  behind it: `cds-attest` presents the router's mesh certificate and requires
  a peer certificate chaining to the mesh CA whose matched workload name
  equals `workload`, and whose stamped entry is unchanged in the allowlist
  CDS serves now. A failed handshake gets 502, `backend_entry_changed` when
  the entry was removed or redefined or its stamped document cannot be
  fetched; no backend is reached in plaintext.
- An attested session routes only by the manifest its handshake bound, and a
  request on it only while the entry its route names is unchanged from the
  allowlist on the router leaf the handshake bound. After a route change, or
  an allowlist change that removes or redefines that entry, the router
  answers with 503 `route_digest_changed` or `route_entry_changed`. Other allowlist writes, and the router's renewal
  under them, do not refuse the session. It ends an attest-pq
  session. An attest-lb connection stays open and every request on it gets
  the same 503 until the client reconnects or attests again on it. No
  traffic moves to the new routes unattested. See
  [Route evidence](routes-evidence.md#server).
- Each router replica holds at most 65536 attest-lb bindings, and one
  client address prefix at most 512 of them. At either limit, new attest-lb
  handshakes from that client get 503 `sessions_busy`. A binding idle for
  2 minutes lapses and refuses its connection with 503 `binding_expired`
  until the client attests again.
- `router.routing.readTimeout` bounds nginx's wait between reads, and
  `router.routing.backendTimeout` (default 1h) how long a routed request, or
  a WebSocket, may go with no data moving; a tunnelled request gets that long
  in total for its backend call. `router.routing.tunnelBudget` (default 75%
  of the cds-attest memory limit, or 32Gi) bounds the bytes the tunnelled
  requests in flight in each router replica may buffer.
- `router.routing.maxRequestBodyBytes` (default 1048576) is the largest
  application request body nginx accepts; a larger one gets 413. nginx
  streams the body to the routing listener rather than spooling it. A baked
  node ignores this value and takes `router.maxRequestBodyBytes` from the
  signed launch file (see [Authenticated launch configuration](#authenticated-launch-configuration)).

`c8s install --upstream <cw-id>` writes the first manifest for an adopted
workload: every DNS name in `router.san` (default
`<release>-router.<namespace>.svc`; install warns about and skips wildcard,
IP and numeric-final-label entries) routes prefix `/` to `c8s-<id>.<ns>.svc.cluster.local:<port>`, with `workload: <id>`.
`--routes-max-age` sets `maxAgeSeconds` of a new manifest (default 24h): how
long the router admits new attested sessions without a successful fetch.
Application routing goes on past it. With `--operator-key`
(or `C8S_OPERATOR_KEY`), install signs it once the release is ready and stores
it on CDS through a port-forward pinned by `--measurements` (with `--rtmrs`
on TDX) or `--image-policy-file`. When CDS already stores a manifest, install verifies it
against `--operator-keys` and adds or replaces the `/` route of each host at the
next revision, keeping the stored `maxAgeSeconds` (install warns when that
overrides `--routes-max-age`). Without a key, install writes a new manifest to
`--routes-out` (default `routes.json`, which install overwrites only when you
pass the flag) and prints the `c8s routes add` commands that add the route to
whatever CDS stores. It does the same when it cannot store the manifest after
the release changed the cluster: the port-forward fails, CDS is unreachable or
fails verification, the served allowlist cannot be read or does not name the
pod, or CDS refuses the write, including with 412 when another write landed
after install read the stored manifest. It also prints `c8s routes put` of the file
when it sent no write and did not see that CDS stores a manifest, since storing
the file drops a stored manifest's other routes. When the revision is refused,
the printed `add` commands leave `--revision` out. The revision is the later of the stored one
plus one and the current Unix time in seconds; `--routes-revision` sets it.
`--operator-key`, `--routes-out`, `--routes-max-age` and `--routes-revision`
require `--upstream`; `C8S_OPERATOR_KEY` does not.

#### Migrate from `router.upstream` and `router.routes`

`router.upstream.*`, `router.routes[]` and `router.nginx.resolver` are gone.
The chart fails a render that still sets any of them
(`kind=removed_router_routes`). Write each route into the manifest with `c8s routes add`
instead, and move `router.upstream.readTimeout` to `router.routing.readTimeout`.
`router.routing.tunnelSlots` is gone too: the tunnel is bounded by the byte
budget `router.routing.tunnelBudget`, and the schema refuses a values file
that still sets `tunnelSlots`.
`c8s render-values` has no `--upstream` or `--workload-ref`. Expect these
changes:

- **Backends are reached over the mesh.** The plaintext route to an adopted
  workload's headless Service has no replacement: the router dials the pod,
  whose injected endpoint holds the mesh leaf and forwards to the port the
  route names. Give its `--workload-ref` the port the workload listens on.
  A `protocol: http` route has no replacement either, and per-route CORS
  opt-out is gone: `router.cors` covers every manifest route.
- **The backend's certificate must name its workload.** CDS stamps the matched
  allowlist entry's name on a workload's certificate only when exactly one
  entry describes its running containers. Entries written per image digest
  describe no multi-container pod, so `c8s install` now writes one entry per
  adoption, named after the cw id. A persistent CDS keeps a stored entry by
  name over the seed, so after an image bump the stored `<cw-id>` entry is
  stale, and a per-digest entry left from an older install makes the match
  ambiguous; either way CDS names the pod nothing and the router answers 502.
  When install wrote the `<cw-id>` entry (`--resolve-digests=true`) and has
  `--operator-key`, it reads the served allowlist and refuses to store the
  route until exactly the `<cw-id>` entry describes the pod's main containers
  and native sidecars. The refusal names the stale or conflicting entry.
  Without a key, install prints the `c8s allowlist list` command to check by
  hand. Update or delete those entries with
  `c8s allowlist apply` or `c8s allowlist delete`.
- **Routing is per host.** Before, nginx routed every `Host` to its one
  backend. Now only manifest hosts route: a client that reaches the router by
  IP, through a port-forward (`Host: 127.0.0.1`), or by a load balancer name
  missing from the manifest gets 404. A manifest host must be a DNS name, so an
  IP-only deployment cannot route application requests.
- **CDS state is now routing state.** The default chart does not persist the
  CDS database (`cds.persistence.enabled: false`). After a CDS restart the
  manifest is gone. The router keeps routing by the one it applied, but
  refuses new attested sessions (`routes_stale`) once `maxAgeSeconds` pass
  without a successful fetch. After the router also restarts, application
  requests get 503 until an operator stores the manifest again
  (`c8s routes put`). An upgrade that resets CDS hits this at once: new router
  pods become Ready before their first fetch, and the old pods are gone.
  Persist CDS, or run `c8s routes put` after the upgrade. Re-running
  `c8s install --upstream` after such a reset starts a fresh manifest with
  only the `/` route, so add routes added earlier with `c8s routes add`
  again. An install
  without operator keys can never store one, so its router routes nothing.
- **A CDS reset does not reset the routers.** A router refuses any revision
  lower than the one it applied, and the same revision with other bytes, until
  it restarts. `c8s install --upstream`, `c8s routes add` and `c8s routes rm`
  write at least the current Unix time in seconds, which outranks what the
  routers hold unless one applied a revision written explicitly, by a
  faster clock, or in a burst of writes. CDS then accepts the new manifest,
  but such a router keeps routing by its old one. After a reset, write above
  the highest revision any router accepted, applied or staged: `--revision` on `add` and `rm`,
  `--routes-revision` on install, or a `put` of a file with that revision.
- **Operator keys are control-plane configuration off baked nodes.** Without
  a launch configuration, the router trusts `cds.operatorKeys`, mounted from
  the chart, or else the keys CDS serves; both are Kubernetes configuration.
  Whoever controls the Kubernetes
  configuration can substitute a key and sign routes to a backend of their
  choice. A client detects that only by pinning the route digest or the
  operator keys; see [Route evidence](routes-evidence.md). Route on baked
  nodes when the control plane is not trusted.

`GET /routes` is unauthenticated and returns
`{"manifest": "<base64 of the manifest bytes>", "token": "<write token>"}`.
`PUT /routes` takes the manifest bytes and is authorized exactly like an
allowlist write, against the same `cds.operatorKeys`. An optional `If-Match`
header carries the lower-case hex route digest of the manifest the writer
read; CDS then stores the write only if the stored manifest still has that
digest. CDS stores the bytes and the write token verbatim. CDS answers:

| Request | Status |
|---|---|
| `GET`, a manifest is stored | 200 with the JSON above |
| `GET`, no manifest is stored | 404 |
| `PUT`, the write is stored | 204 |
| `PUT`, the write token does not verify against `cds.operatorKeys`, or `cds.operatorKeys` is empty | 401 |
| `PUT`, CDS has no mesh CA to check `ca` against | 500 |
| `PUT`, the body exceeds 1 MiB | 400 |
| `PUT`, the manifest fails validation, or a `ca` holds the CDS mesh CA | 422 |
| `PUT`, the revision is not greater than the stored one | 409 |
| `PUT`, the write token was already spent | 409, plain text `operator token already used` |
| `PUT`, CDS verifies the write token but cannot record it as spent; nothing is stored, so retry with a fresh token | 503 |
| `PUT`, `If-Match` differs from the stored manifest's route digest, or no manifest is stored | 412 |

The `c8s routes` CLI takes the `c8s allowlist` connection and credential
flags. Point `--url` at CDS itself, with no path, because the router does not
relay `/routes`. A port-forward works; pin the CDS launch digest with
`--measurements`. On a baked node, CDS listens on NodePort 30808 of the
server: use `--url https://SERVER_ADDRESS:30808`, pinned with
`--image-policy-file` set to the bundle's `server.json`.

To show the stored route manifest and add a route:

```sh
c8s routes show --url https://127.0.0.1:8443 --measurements CDS_DIGEST \
    --operator-keys operator.pub
c8s routes add --url https://127.0.0.1:8443 --measurements CDS_DIGEST \
    --operator-key operator.key --operator-keys operator.pub \
    --host app.example --path / --address vllm.ai.svc.cluster.local:8443 --workload vllm --new
```

- `CDS_DIGEST`: the CDS launch digest.
- `operator.pub`, `operator.key`: the operator key pair whose public half is in
  `cds.operatorKeys`.

| Subcommand | Effect |
|---|---|
| `show [--raw] [-o json] [--operator-keys FILE]` | Prints revision, `notBefore`, `maxAgeSeconds`, route digest and routes; `--raw` prints the manifest bytes and `-o json` the stored envelope. `--operator-keys` verifies the stored token's signature and bindings. |
| `digest FILE` | Validates a manifest file and prints its route digest, the hex SHA-256 of its bytes. |
| `put FILE [--dry-run]` | Validates the file locally, then signs and stores its bytes verbatim. |
| `add --operator-keys FILE --host H --path P [--match prefix\|exact] --address A (--workload W \| --server-name N --ca FILE) [--new] [--revision N] [--dry-run]` | Adds the route, or replaces the one with the same path and match, and stores the next revision. With no stored manifest it refuses, since a CDS reset looks the same; with `--new` it writes a new one with `--max-age` (default 24h, at least 1s). Over a stored manifest it warns that `--max-age` is ignored. |
| `rm --operator-keys FILE --host H --path P [--match M] [--revision N] [--dry-run]` | Removes the route, and the host when it has no route left, and stores the next revision. |

`add` and `rm` re-sign the stored routes, so they require `--operator-keys`
and refuse a stored manifest that does not verify against it. They set
`notBefore` to now, or keep a later stored one, and keep the stored
`maxAgeSeconds`. The next revision is the later of the stored one plus one and
the current Unix time in seconds, or `--revision N`, which must be above the
stored one. When a manifest is stored, `add` and `rm` send its digest as
`If-Match`, so a 412 means another write landed first: re-run the command.
`add` on an empty store is not compare-and-swap: a `put` that lands between
the 404 and the write is replaced. Both writers hold the operator key.
`--dry-run` still fetches the stored manifest from CDS.

An edit re-signs every stored route at a new revision, not only the one it
changes. Before signing, `add` and `rm` print each route the new revision
carries to stderr. After a CDS reset, check that list: the stored manifest may
be older than the one routers hold, and an edit would re-authorize the routes
you had removed since. Once the router applies the manifest, it keeps the
highest revision it accepted, applied or staged, even across a CDS reset. The
default revision, the current Unix time, outranks it unless a router accepted a
revision ahead of your clock; then pass `--revision` above that revision.

`GET /routes` serves the write token. The CDS that spent it answers a replay
with 409, but any reader can replay it as a `PUT /routes` on another CDS that
trusts the same operator key, until its `exp` plus the CDS `--jwt-clock-skew`
allowance (`cds.jwtClockSkew`, 30 seconds by default). `c8s routes` mints 60-second
tokens; CDS accepts at most 5 minutes between `iat` and `exp` from any tool.
The token names no CDS: a replay succeeds on any CDS that trusts the same
operator key and stores a lower revision, or none. Use a separate operator key
for each cluster.

After an operator key rotation, the stored manifest still carries the token of
the old key, so `add` and `rm` refuse it unless `--operator-keys` holds the
old public key. To recover, do one of the following:

- Keep the old public key in `--operator-keys` for the next `add` or `rm`,
  which re-signs the manifest under the new key.
- Review the bytes from `c8s routes show --raw`, raise `revision`, and store
  the file with `put`.

The route digest `show` and `digest` print is the value
`c8s verify --route-digest` takes. The router binds the digest of the
manifest it applied into its attest-pq and attest-lb evidence. With
`router.routePublication.enabled: true` (default `false`; requires
`router.attest.enabled`), the router also serves that signed manifest at
`/.well-known/c8s/routes` for `c8s verify --operator-keys`. Leave route
publication off when the hosts, backend addresses and workload names in the
manifest are not public, and have clients pin `--route-digest` instead. A baked
node image always publishes: `c8s node-image render` sets the value in the
measured image, so keep names that must stay private out of a baked node's
manifest. See [Route evidence](routes-evidence.md).

### Route by the manifest

`cds-attest --cds-url` polls `GET /routes` from CDS over armTLS, verifies the
signed manifest, and routes by it. It routes the requests it decrypts from
the tunnel and, with `--routing-port`, plain requests on a loopback listener.
The chart sets these flags from `router.routing` and the CDS pins.

| Flag | Default | Effect |
|---|---|---|
| `--cds-url` | none | CDS origin to poll. Required, with `--attestation-api-url`. |
| `--cds-measurements`, `--cds-rtmrs`, `--image-policy-file` | none | CDS pins. Without `--cds-measurements` or `--image-policy-file`, `cds-attest` logs a warning and accepts any armTLS-attested CDS. Unsafe outside development: any TEE on the pod network can pose as CDS and serve the manifest. |
| `--operator-keys-file` | none | PEM operator public keys a manifest must verify under, when the launch configuration carries none. |
| `--allow-unpinned-cds` | `false` | Development only. Route with no CDS pin and the operator keys from that CDS. Without it, `cds-attest` refuses to start in that case. |
| `--routes-poll-interval` | `30s` | Time between polls. Keep it under half of `maxAgeSeconds`. |
| `--routing-port` | `0` | Port of the loopback routing listener. `0` disables it. |
| `--routing-host` | `127.0.0.1` | Host of the routing listener. Must be a loopback IP. |
| `--backend-timeout` | `1h` | On the routing listener, how long a request, or an upgraded connection such as a WebSocket, may go with no data moving either way. A tunnelled request, whose response is buffered whole, gets this long in total for its backend call. Must be positive. |
| `--tunnel-io-timeout` | `30s` | How long a tunnel upload, or the download of its sealed response, may make no progress. Must be positive. |
| `--tunnel-budget` | 75% of the container memory limit, else `32Gi` | Bytes the tunnelled requests in flight in one replica may buffer, as a quantity such as `64Gi`. Each request reserves three copies of its record and four of the largest response (32 MiB); one client (by `X-Real-IP`) holds at most a quarter. Must cover one full-size request, 152 MiB. Set by `router.routing.tunnelBudget`. |
| `--reserved-paths` | the router's own endpoints | Paths no manifest route can match. Each entry must be a normalized path. |
| `--attest-endpoints` | `true` | `false` serves only the routing listener and probes. Requires `--routing-port`. `true` requires the three `--mesh-identity-*` files, whose leaf the attestation endpoints bind to; they must name `/etc/c8s/certs/tls.crt`, `tls.key` and `ca.crt`, the credential the router reaches backends with. |
| `--publish-routes` | `false` | Serves the applied signed manifest at `/.well-known/c8s/routes`. Requires `--cds-url` and `--attest-endpoints=true`. Set by `router.routePublication.enabled`. |

`cds-attest` takes the operator keys from the node's launch configuration,
`/run/c8s-node/operator-pubkey`, when that file exists at startup. Otherwise it
takes them from `--operator-keys-file`. A keys file that exists but holds no
readable key stops `cds-attest` at startup, and so does a set
`--operator-keys-file` that is absent. With neither, it
takes them from CDS's `GET /operator-keys` and logs a warning: that list is
control-plane configuration, and the router does not stop a substituted key.
Keys from an unpinned CDS stop `cds-attest` at startup, unless
`--allow-unpinned-cds` is set: any attested TEE answering as CDS would then
choose both the manifest and its keys.

The chart pins CDS from `cds.measurements` or `cds.measurementsConfig`. It
passes `--operator-keys-file` from the launch configuration on a baked node,
so a node image without the keys stops `cds-attest`, else from
`cds.operatorKeys`. With neither a CDS pin nor `cds.operatorKeys`,
the render fails with `kind=unpinned_route_source` and `c8s install` refuses
before it starts. Fix it with `--measurements` (or `--image-policy-file`) or
`--operator-keys`. On a development cluster only, set
`router.routing.allowUnpinnedCDS=true` in a `-f` file; the chart then passes
`--allow-unpinned-cds`.

Until it applies a manifest, `cds-attest` answers routed requests with 503
and refuses attest-pq and attest-lb handshakes with 503 `routes_unavailable`.
When `maxAgeSeconds` passes without a successful poll, it refuses them with
503 `routes_stale` and keeps routing, by the stale manifest, both established
sessions and the routing listener. A manifest whose `notBefore` is in the
future counts as a successful poll. `cds-attest` applies it at the first poll
at or after `notBefore` and keeps no timer, so while CDS is unreachable the
applied revision keeps serving. CDS serves only the staged manifest, so a
replica that starts before its `notBefore` (a restart, rollout or scale-up)
has nothing to apply: until `notBefore` it refuses handshakes with
`routes_unavailable` and answers routed requests with 503, while `/readyz`
stays 200. Keep the `notBefore` window short, and avoid restarts and
scale-ups inside it. The handshake gates on a fresh applied manifest and
binds its route digest into the evidence.

`/readyz` ignores route state: it answers 200 before the first apply and
while the manifest is stale. To spot a router that routes nothing, watch for
the `route manifest poll failed` log and for handshakes refused with
`routes_unavailable` or `routes_stale`; a router that routes has logged
`route manifest applied`.

After its signing key leaves the operator key set, every poll fails to verify
the stored manifest: `cds-attest` keeps routing by the applied one and goes
stale within `maxAgeSeconds`. After removing an operator key, write a new
revision under a remaining key.

A tunnelled request routes by the sealed request's `Host` header only. One
with no `Host` header, or more than one, gets 400 inside the tunnel and is
never routed by the outer request's host.
Upgrade `c8s-verify-js` to a version that seals `Host` in every tunnel
request before you upgrade the router; earlier versions seal it only when
the caller passes it.

Backends receive `X-Real-IP`, `X-Forwarded-For` and `X-Forwarded-Proto` as
nginx set them on the outer request. They are metadata the host can forge,
not client identity.

`maxAgeSeconds` counts from the last successful poll, not from when the
manifest was signed. The accepted revision lives in memory only: after a
restart, `cds-attest` accepts any validly signed revision, including an older
one. Once it accepts a revision with a future `notBefore`, it refuses every
lower revision, including the applied one, and keeps the staged revision. To
withdraw a staged revision, publish a higher one; restoring the previous
manifest is refused.

Each `cds-attest` replica admits a tunnelled request only while
`--tunnel-budget` covers every copy it may buffer: three of its record and
four of the largest response, 32 MiB, so 128 MiB to 152 MiB. One client, by
`X-Real-IP`, holds at most a quarter of the budget. Others get 503
`tunnel_busy`. At 32 GiB that is about 250 requests per replica and 64 per
client. Clients behind one NAT share a quarter, and so do all clients behind
a node when the Service SNATs them (`externalTrafficPolicy: Cluster`). A
request holds its reservation from reading the sealed request until the
client has read the sealed response: through the backend call, up to
`--backend-timeout`, and then for as long as the client keeps reading. One
that names no live session gets 401 before its body is read. Anyone can open
a session, so the per-client quarter is what bounds one client.

A tunnel request body over 8 MiB gets 413, and a response over 32 MiB gets
a sealed 502; the routing listener streams
responses without a cap. No timeout assumes a client speed: an upload or
download loses its budget only once it makes no progress for
`--tunnel-io-timeout`. `cds-attest` writes a sealed response in 16 KiB
pieces and restarts that timeout after each, so a client that keeps reading
gets the whole response however slowly it reads. On the routing listener,
`--backend-timeout` restarts in the same way whenever data moves either way,
also on an upgraded connection, which has no fixed lifetime.

The chart's nginx settings apply wherever `router.attest.enabled` is set.
nginx reads each request body whole before proxying it, so a slow upload
holds nginx memory rather than budget; keep `proxy_request_buffering` on for
`/.well-known/c8s/`. Replies stream once they outgrow `proxy_buffers`, so a
slow download of a large reply holds its budget for as long as the client
keeps reading. Its timeouts restart on progress too: `client_body_timeout`
and `send_timeout` (nginx's 60s default) count from the last read from or
write to the client, and `proxy_read_timeout`
(`router.routing.backendTimeout` plus 30s) from the last read from the
sidecar. The handshake endpoints admit bodies up to 16 KiB.
`/.well-known/c8s/tunnel` admits bodies up to 8 MiB and drops an upload that
sends nothing for 10s. Bodies past 16 KiB spill to a tmpfs of
`router.nginx.tunnelBodySpace` (default 8Gi), charged to nginx's memory, so
a memory limit on nginx must exceed it. An upload that does not fit gets
500. One client address has at most
`router.nginx.tunnelConnectionsPerClient` (default 64) tunnel requests open,
so filling the tmpfs takes 16 addresses at the defaults; past that cap, and
for a body over 8 MiB, nginx answers with its own HTML 503 or 413 page
before the sidecar's JSON errors can apply. Each nginx worker accepts 16384
connections.

## Attestation-api

The attestation-api DaemonSet binds pod loopback and is served to on-node
consumers by its attest-proxy sidecar over a Unix socket in
`nriImagePolicy.hostPaths.runtimeDir`; no Service renders.

Two operational notes:

- **Upgrading from a release that rendered the attestation-api Service
  deletes it.** Already-running cw pods keep their old
  `--attestation-api-url`, and their get-cert renewals fail once the Service
  is gone — roll cw-annotated workload pods after the upgrade so the webhook
  re-injects the socket URL. New pods are unaffected.
- **A wedged attestation-api does not self-restart.** Its health signal is
  the attest-proxy's exec probe, so a hung (not crashed) API process shows as
  a NotReady `c8s-attestation-api` pod with a crash-looping attest-proxy
  container; delete the pod to restart the pair.

## Verifying attestation after install

`c8s verify` (and `c8s cds verify`, shorthand for `c8s verify --kind cds`) fetches
a component's TEE attestation evidence — AMD SEV-SNP or Intel TDX — and verifies it
against the hardware signature chain plus a pinned launch measurement. Use it to
confirm CDS — or the router — is a genuine TEE running the expected code
after install.

It verifies **in-process** with `attestation-go` — the Go port of the same
attestation-rs engine the cluster runs. That engine auto-detects the platform and
AMD product, including Zen4c (Siena/Bergamo) which stock `go-sev-guest` cannot
classify. The only requirement on the machine running `c8s verify` is outbound
HTTPS to AMD KDS (`kdsintf.amd.com`) when a bare report's VCEK is not already
cached; no container runtime is needed. `attestation-go` caches endorsement
certificates under `os.UserCacheDir()/c8s/kds`, with `c8s` choosing that directory.
Set `C8S_KDS_CACHE_DIR` to override it, or set it to an empty value to disable
caching. Certificate verification still runs for every report; revocation data
is never served from this disk cache. Cache failures do not block a successful fetch.

```bash
# CDS's armTLS endpoint answers unattested clients:
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &

c8s cds verify https://localhost:8443 --measurements <sha384-launch-digest>

# JSON + exit codes for CI:
c8s cds verify https://localhost:8443 --measurements-file digests.txt -o json
```

PKI/SAN mismatch when dialing localhost or a pod IP is fine — `verify` trusts
the attestation embedded in the serving cert, not the certificate chain.

On a cluster created with `c8s launch-config new`, `--image-policy-file` alone
cannot pass: it pins the CDS server's identity, but the served-set check
against `/measurements` is exact, and CDS admits the agents' launch keys
beside the server's. The bundle carries both policies — pin the target with
`server.json` and name the served set with `peers.json`:

```bash
c8s cds verify https://$SERVER:30808 --image-policy-file demo/server.json \
  --served-policy-file demo/peers.json --operator-keys demo/server/pubkey
```

Both policy files must name the same TEE family, and every target pin in
`server.json` must appear in `peers.json`, including its image measurements
and launch-key anchor. Inconsistent files produce a usage error before
connecting to the target.
For `kind=cds`, a target policy with multiple launch-key anchors produces a
warning: any identity it admits, including an agent, can pass as CDS.

The launch digest(s) to pin are the same values discussed under measurement
pinning (the node CVM digest). They
are enforced client-side against the report's launch measurement; with no
`--measurements` the command still runs but prints an UNSAFE warning — any
genuine TEE is accepted.

On TDX, `--measurements` pins MRTD, which covers only the TDVF firmware: the
guest kernel and rootfs live in RTMR[1] and RTMR[2], and a verdict pinned on
MRTD alone warns that they are unmeasured by that policy. To pin the whole
image, pass `--image-manifest <file>` — a build-artifact manifest published
with the guest image build, carrying `mrtd`, `rtmr1` and `rtmr2` (96
lowercase hex chars each, each named once) under its `tdx` object, as a
confos manifest publishes them; a flat top-level tuple is also accepted.
The manifest ships as a `manifest.json` layer in the image's oras artifact
(the tag the CDI ref carries without its `-cdi` suffix), so it can be
fetched with `crane blob` for the exact build a node booted. The
three registers are loaded atomically from that one provenanced manifest and
all three are compared exactly, the same rule `c8s get-kubeconfig` applies to
the same manifest — MRTD is deliberately not merged into the `--measurements`
allowlist, since an allowlist is satisfied by any member and a launch digest
from a different build would then pass alongside this manifest's
RTMR[1]/RTMR[2].

For that reason `--image-manifest` **replaces** the allowlist rather than
combining with it: passing it together with `--measurements` or
`--measurements-file` is a usage error (exit 1). The manifest already pins
MRTD to exactly one value, so an allowlist beside it can only restate that
digest or contradict it — and a contradiction builds a policy no guest can
ever satisfy, failing every run with an `MRTD mismatch` that reads like an
attestation failure rather than the typo it is. Pin this image and drop
`--measurements`/`--measurements-file`; or, to accept several firmware
images, drop `--image-manifest` and give up its RTMR[1]/RTMR[2] kernel and
rootfs pins with it.

`--rtmr 3=<sha384-hex>` can additionally pin the runtime register — the ordered
operator-key/workload extend chain ([`runtimemeasure`](https://github.com/confidential-dot-ai/attestation-go/tree/main/runtimemeasure)) — which is a
deployment property, not a cluster identity, and therefore requires
`--image-manifest`: the untrusted host picks the guest image, so it can boot
anything and reproduce that chain. (`--expected-rtmr3` is the former spelling of
the same pin and still works, but `--rtmr` now covers every register: 1 and 2
conflict with `--image-manifest` because they *are* the image, while 3
requires it.) `--operator-pkey <file>` is the same pin
without the arithmetic: point it at the operator **public** key PEM (the
verbatim bytes the guest initrd hashed, as written by `openssl ec -pubout`)
and `verify` derives the bare operator-key seed,
`SHA-384(0x00*48 ‖ SHA-384(pubkey))`, itself. The two are mutually exclusive
— one register, one expected value — and `--operator-pkey` carries the same
`--image-manifest` requirement. Note its scope: it pins the seed, optionally
followed by the node's measured allowlist policies, but not per-workload
extends; `c8s get-kubeconfig` is the command that folds `--workload-image`
extends into the expected register. Supplying any of these flags against
SEV-SNP evidence is a policy error, not an ignored option: SNP has no runtime
measurement registers.

A TDX verdict pinned on MRTD alone is **rejected**, not warned about, when no
operator-pinned CA anchor (`--mesh-ca`) stands beside the measurements: the
measurement pins are then the entire trust anchor, so an incomplete image
policy leaves nothing behind the verdict. A chain checked against a CA the
responder committed into its own transcript (attest-pq) does not downgrade
this — that anchor is responder-chosen.

Certificate-sourced evidence must also carry an authenticated certificate
body. A self-signed leaf authenticates its own body under the attested key; a
CA-issued one does not, and `x509` parsing verifies no signature — so a
CA-issued leaf is accepted only when its chain verifies against `--mesh-ca`,
including on a `--mode discovery` target whose live door presents the attested
certificate byte-identically. `c8s cds ca` writes that anchor. What the live
handshake decides is the front-door check below.

Exit codes are a CI contract: `0` verified, `1` usage error, `2`
verification/policy failed (e.g. wrong measurement), `3` evidence unavailable
(unreachable/unparseable), `4` partially verified — the evidence verified, but
a property it presents is not proven. The partial cases today: a non-empty
policy history that neither `--pin-policy` nor `--trust-operator` checked (see
[Check a node's policy history](#check-a-nodes-policy-history)), the
front door's live TLS handshake presenting a serving certificate the discovery
evidence does not attest (a WebPKI front door, whatever the document's
`public_tls.mode` declares — the verdict keys on the handshake observed on the
verifier's own connection at verify time, not the host-served declaration;
what is proven is the router pod's TEE residency and measurement, not the TLS
endpoint clients reach), a discovery target fetched over a non-TLS connection
(no live handshake observed — the declared `public_tls.mode` is then the only
mode signal, a host-served claim nothing authenticates), and attest-pq or
saved-bundle evidence without `--mesh-ca` (the mesh chain anchors to a CA the
responder committed into its own transcript, so which deployment the endpoint
belongs to is not proven). JSON renders these as
`verified: false, partial: true` with a `not_proven` list, so a gate checking
`verified` fails closed while scripts can still tell partial from failure.

`--mode attest-pq` and `--mode attest-lb` evidence also binds the router's
route digest, so these modes require exactly one route check:
`--route-digest HEX` pins the digest `c8s routes show` prints (repeat it
while a route change rolls out), and
`--operator-keys FILE` verifies the manifest the router publishes, optionally
against a `--routes-floor REV:HEX` rollback floor. Without either they are a
usage error (exit 1). [Route evidence](routes-evidence.md) has the transcript
layouts and the checks.

Caveats the output surfaces:

- **Freshness.** Verifying an armTLS serving cert binds REPORTDATA to the
  certificate key, not a per-request nonce, so it proves "this key was born in a
  TEE with this measurement" but not "freshly now" (`fresh: false`).

### Check a node's policy history

A node that measures its allowlist policies (Helm value
`nriImagePolicy.measurePolicies`, see
[Measured policy history](allowlist-and-capabilities.md#measured-policy-history))
reports RTMR[3] as the seed followed by each policy it enforced since boot.
Its router's attest-pq and attest-lb bundles list those digests as
`measured_policies`, and its TDX armTLS certificates and discovery document
carry them as runtime extensions. With `--operator-pkey`, or an
`--image-policy-file` whose matching image pins an `approver_key`, `verify`
replays that list against RTMR[3] and reports the longest prefix that matches
as `history:` (`measured_policies` in JSON). Only the anchor of an image the
evidence matches on its own counts: another image's `approver_key` proves
nothing about a guest that booted an unanchored one. Without such an anchor, a
listed history is not replayed and the verdict warns. A non-empty replayed history leaves the verdict
partial until `--pin-policy` or `--trust-operator` checks it: the replay proves
which policies the node enforced, not that they are acceptable. Choose how to
accept the history:

| Flag | Accepts | Failure |
|---|---|---|
| `--pin-policy sha256:<hex>` (repeatable) | Only these digests, for every history entry and for the policy the leaf was issued under | `policy_history_not_pinned` |
| `--trust-operator --trust-operator-keys <pem>` | Every history entry, and the policy the leaf was issued under, whose document carries a valid operator signature under these keys | `policy_history_unsigned` |

Both flags require `--operator-pkey` or an `--image-policy-file` image pinning an
`approver_key`, and exclude each other. Both fail with
`policy_history_absent` when nothing replays: a node that does not measure
proves nothing about the policies it enforced. Both also fail when the leaf's
matched-workload stamp is unreadable; that stamp is CA-vouched, so without
`--mesh-ca` the verdict stays partial. A leaf with no stamp, which CDS issues
when the pod matches no single allowlist entry, leaves the verdict partial: it
is indistinguishable from a leaf issued to a pod that presented no sandbox
token, so the policy it was issued under is not checked (`leaf_stamped` is
`false` in JSON for an absent or unreadable stamp, and absent when the evidence
carries no leaf).

The history runs from boot up to the evidence's quote. Evidence that this
check's nonce does not bind (a certificate, a discovery document or a saved
file) cannot show a policy the operator pushed since, so both flags leave such
a verdict partial: use `--mode attest-pq` or `attest-lb` to check the node's
current history. With `--operator-pkey`, a list of more than 256 entries, or
one with an entry that is not a canonical `sha256:<hex>` digest, fails the
verdict.

`--trust-operator` fetches each document from
`<target>/allowlist/objects/sha256/<hex>`, checks it hashes to its digest
(`allowlist_digest_mismatch` otherwise), and checks its stored write token
against `--trust-operator-keys` with `operatorauth.VerifyStored`.
`--operator-keys` does not feed it, and `--trust-operator-keys` alone is
rejected. Only a document uploaded whole with a signed `PUT /allowlist`
carries a token: a per-workload edit yields an unsigned policy, which fails
`--trust-operator` until a signed upload of the same document stores a token
for its digest. The documents authenticate
themselves against the replayed digests, so any router replica may serve
them. Each fetch, here and with `--fetch-allowlists`, has its own `--timeout`, and all of them together get four times
`--timeout`; a fetch that times out or cannot
connect exits 3, as for unavailable evidence.

To review the documents before pinning them, add `--fetch-allowlists DIR`
(also requires `--operator-pkey` or an anchored `--image-policy-file` image): `verify` saves each one as
`DIR/<hex>.json`, and a failed fetch or write fails the verdict with
`allowlist_fetch_failed`.

```sh
c8s verify https://app.example.com --mode attest-lb \
  --image-manifest image.json --operator-pkey operator.pub \
  --trust-operator --trust-operator-keys operator-keys.pem
```

### Complete measured identity policies

Image policy files preserve each image measurement, its TDX RTMR tuple and
optional `approver_key` as one policy entry. The key is the exact PEM string;
attestation-go's `refvalues` package maps it to `remote.ImagePin.Anchor`.
`remote.EnforceImagesWithRuntimeLog` checks the image and its launch-key
binding for that same entry. On TDX the binding may be the key's seed followed
by a prefix of the peer's measured policies that replays
([Measured policy history](allowlist-and-capabilities.md#measured-policy-history)).
An image cannot borrow another entry's authorized key.
C8s passes these entries through `remote.Policy.Images` to its attestation
clients and injected workload helpers. Each verifier enforces the complete
entry, including its launch-key binding when present. The measured policies
after the seed are accepted as far as they replay, not judged: see "What
armTLS guarantees" in [armTLS](armtls.md).

### Image policy inputs

A complete image policy is a JSON document containing each trusted image's
launch digest, TDX registers where applicable, and optional launch-key anchor.
File and inline inputs use the same JSON format:

| Input | Contents |
|---|---|
| `--image-policy-file policy.json` | Path to a complete JSON image policy. |
| `--image-policy-json '{...}'` | The JSON document itself; supported by workload helpers such as `get-cert` and `get-secret` when they run outside an injected pod. |
| `--measurements-file digests.txt` | Text file containing one launch digest per line; no per-image register or key bindings. Supported by `verify`, `allowlist`, and `secrets`. |

The enforcer bind-mounts the node's own policy at `/run/c8s/cds-pins.json`
and the CDS endpoint it admits at `/run/c8s/cds-address` for every container
holding the credentials role — the injected `get-cert`, `get-secret` and
`get-volume`, and the router's `get-cert` and `allowlist-proxy`, which the
chart renders — and each of them reads both from there: while those mounts are
present they are the one source, and a policy, a pin or a `--cds-url` passed as
an argument is refused rather than silently ignored. On a baked node the pins
and the address come from the signed launch configuration; on an install they
come from the chart. The address is the one destination the pod's packet rules
admit for the credential role: the staged server address on a baked node, the
node's own address and `cds.service.nodePort` on an install.

Choose one complete policy source. A complete policy cannot be combined with
independent digest or register inputs such as `--measurements`,
`--measurements-file`, or `--rtmrs` (including the `--cds-` variants where
provided). These independent inputs remain available for policies expressed as
a digest list and a shared register set.

`c8s install` and `c8s render-values` accept image policies only when every
image has identical RTMR pins and no `approver_key`. The Helm NRI installer
configures CDS trust through a digest list and one shared register set, so
these commands reject policies whose per-image register or launch-key
constraints would be lost. Direct Helm installs with `cds.measurementsConfig`
must also supply equivalent `cds.measurements` and `cds.rtmrs`; the chart
rejects missing or mismatched pins while its NRI installer is enabled.
Operator-key-bound policies require the baked node launch flow, which manages
NRI separately with `nriImagePolicy.enabled=false`. CDS, mesh, and workload
helpers that receive a complete image policy enforce its per-image tuples
directly.

### Trust gate: `c8s get-kubeconfig`

`c8s get-kubeconfig` obtains an operator kubeconfig (or, with `--role
log-reader`, a logs-only one) from a measured node CVM.
Before any credential flows it enforces the node's **full measured identity**,
both on the armTLS connection and on a fresh nonce-bound attestation report:

- **platform** — the `--image-manifest` shape selects it (a TDX tuple or SNP
  `snp_variants`); a node of any other platform is refused up front;
- **guest image (TDX)** — MRTD, RTMR[1] and RTMR[2] must match the tuple from
  `--image-manifest` (required), an explicitly selected, provenanced
  build-artifact manifest carrying all three fields under its `tdx` object. A
  generic artifact-hash `manifest.json` is not an image pin and is rejected;
- **RTMR[3] chain (TDX)** — the register must equal the operator-key seed
  (`runtimemeasure.Seed` over the exact pubkey PEM bytes)
  extended, in order, by each digest-pinned `--workload-image` ref (tags are
  rejected). With no `--workload-image` the register must equal the bare seed.
  A node that measures allowlist policies extends them after that chain and
  sends their list with the fresh report, or in cred-release's armTLS
  certificate; the register may then also carry the longest prefix of that
  list that replays (see
  [Measured policy history](allowlist-and-capabilities.md#measured-policy-history)).
  That trailing part is a prefix check, not an exact chain: policy and
  workload extends share one event encoding, so `--workload-image` excludes
  an unpinned workload only while the measured image journals policies
  alone, which the image pin above enforces;
- **guest image + operator key (SEV-SNP)** — the report's MEASUREMENT must be
  one of the per-SMP launch digests pinned by `snp_variants` (one image has
  one digest per vCPU count), and HOSTDATA must equal `SHA-256(operator
  pubkey)`. SNP has no runtime-extend register, so `--workload-image` is a
  usage error there rather than a silently ignored flag;
- **certificate body** — the credential-release serving cert must sit inside
  its validity window (NotBefore with a bounded 5-minute skew, NotAfter with
  none) and, being self-signed, verify its own signature with its attested
  key.

By default the client sends a signed, 32-byte nonce to `POST /attest` on the
credential-release service at port **8443**. That service authenticates the
operator token before asking its configured local attester for evidence.
The client verifies the returned report in-process before generating the
credential CSR. The fresh report is still required: the TLS certificate's
key-bound quote may have been created before later workload measurements.
The raw attester remains on guest loopback; external bootstrap only needs
the credential service and the Kubernetes API on port **6443**.

```sh
c8s get-kubeconfig --node "$SERVER_IP" \
  --operator-key demo/server.key --image-manifest manifest.json \
  --out demo/kubeconfig --release-wait 5m
```

For SSH tunnels or non-default ports, supply `--release-url` and
`--apiserver-url` instead of `--node`. Release URLs must use HTTPS, and
signed requests never follow redirects. `--release-wait` retries refused
connections while the service starts; attestation and authorization failures
stop the flow. An explicit `--attest-url` retains the separate nonce check
for older images with a reachable attestation API. There is no automatic
fallback: images without the authenticated `/attest` endpoint need a rebuild
to use the default flow.

With `--attest-url`, the measured-policy list comes from cred-release's
certificate, which the node reissues only at half its armTLS lifetime. After
the node measures a new policy, the gate fails until that reissue. To avoid
the wait, omit `--attest-url`: the default flow takes the list from the
`/attest` response, read after the quote.

The released kubeconfig's client certificate is
`CN=operator, O=c8s:node-operators`, with a one-hour default (and baked
node-image) TTL. The node image's baked `cred-release-rbac` RKE2 AddOn binds
that group to the baked `c8s-node-operator` ClusterRole through ordinary
RBAC. That role is deliberately not `cluster-admin`: the operator manages
tenant workloads, namespaces, namespaced RBAC, ConfidentialWorkloads and
network policy cluster-wide, and reads everything else, but holds no
wildcard and nothing that reaches the guards or the host. See "Bounded
operator" below.

`--role log-reader` asks cred-release for `CN=log-reader, O=c8s:log-readers`
instead, with a 24-hour default TTL. The baked `log-reader-rbac` AddOn binds
that group to the `c8s-log-reader` ClusterRole: get/list/watch on pods and
`pods/log`, namespaces and events, and nothing else (no ConfigMaps or
Secrets, no exec). The role travels in the token-bound request body, so the
same operator key authorizes both and neither the CSR nor the role can be
swapped in transit; an unknown role is refused, never downgraded. Use it to
hand `kubectl logs` access to someone who should not hold the operator role:

```bash
c8s get-kubeconfig --node "$GUEST_IP" --operator-key operator.key \
  --image-manifest image-manifest.json --role log-reader --out logs.kubeconfig
```

The holder cannot renew the file; only the operator key can release another.
`kubectl exec`, `attach`, `port-forward` and ephemeral containers are denied
in admission for every credential by the baked `confos-pod-exec` policy
(the kubelet's debugging handlers stay on for logs and have no logs-only
switch).

RKE2 reconciles AddOns asynchronously, so `cred-release.service` keeps its
listener closed until `psa-ready.sh` sees both bindings plus the baked
`confos-psa-level`, `confos-operator-scope` and `confos-pod-exec` policies
and bindings, and proves the operator-scope deny path with a server-side
dry-run as a synthetic principal carrying the operator group. The gate also
compares every live guard object against a reference copy of its manifest
that mkosi.sync stages under `/usr/lib/confai/guards` on the read-only
verity root: `server/manifests` sits on the writable scratch overlay
because RKE2 stages its bundled charts there, so a shadowed or edited AddOn
is caught by the comparison and keeps the listener closed. Root inside the
guest can still edit live objects after the gate has passed; what it cannot
do is change the reference the gate checks against without changing the
image measurement. The gate then uses a temporary,
namespace-create-only synthetic principal for two server-side dry-runs: a
Restricted namespace must be admitted and a privileged namespace must be
denied by that exact policy and validation. A released credential is therefore
both authorized and behind a live Restricted namespace floor the moment it is
issued.
`system:masters` is deliberately avoided because it bypasses authorization
and admission webhooks and cannot be revoked through RBAC. The default group
is only meaningful where such a binding exists: on a cluster that is not the
C8s node image, create an equivalent `ClusterRoleBinding` or pass `--cert-org`
for a group that cluster already authorizes.

#### Bounded operator

The guards (`confos-psa-level`, `confos-pod-exec`, `confos-operator-scope`,
the two RBAC bindings) exist to hold against the credential holder, so no
released credential may be able to disable them. Two independent layers
enforce that:

- **RBAC.** `c8s-node-operator` is an enumerated allowlist with no `*` in any
  group, resource or verb. It grants no `bind`, `escalate` or `impersonate`,
  no cluster-scoped RBAC writes, no admission-policy or webhook writes, no
  `nodes/proxy`, `pods/proxy` or `services/proxy` (the kubelet-proxy
  subresources reach the kubelet's exec endpoint without a `pods/exec`
  admission check), no exec, attach, port-forward or ephemeral containers,
  no `serviceaccounts/token`, no `podsecurityexemptions` grant, no
  PersistentVolume, StorageClass, HelmChart, CustomResourceDefinition, Node,
  APIService or CSR-approval writes. Namespaced Roles and RoleBindings are
  allowed, and the apiserver's
  escalation check keeps them within the operator's own permissions.
- **Admission.** `confos-operator-scope` re-checks the same exclusions for
  every principal in a `c8s:` group, whatever RBAC says: no write at all in
  the privileged namespaces (`kube-system` and `local-path-storage`, which
  are PodSecurity-exempt, and `c8s-system`, labelled privileged for the
  baked operator), where a pod, an edited DaemonSet, a HelmChart or a
  service-account token secret is root on the node; and none of the
  cluster-scoped resources listed above. Its match condition selects the
  `c8s:` groups before any validation runs, so system components and the
  in-guest `rke2.yaml` are unaffected.

The role therefore cannot lower a namespace below restricted, cannot exec,
cannot write where PodSecurity does not apply, cannot mount the host through
a PersistentVolume or a `nodePath` StorageClass, and cannot edit or delete
any guard or binding. A credential leaked or over-shared is bounded by the
same rules. Root-equivalent access to the guest exists only through the
in-guest `rke2.yaml`, which never leaves the node.

Every other bound still applies: who can obtain the credential (the
attestation gate above), the TTL, and the verity root and per-boot
ephemeral writable state of the guest.

Revocation is a launch-time decision. Deleting or editing the live
ClusterRoleBinding cuts access immediately, but only until the next boot: the
manifest is baked into the read-only root and everything RKE2 writes, the
cluster state included, lives on the scratch disk, which is re-encrypted with
a fresh random key every boot. `.skip` markers and `config.yaml.d` drop-ins
are lost with it, so there is no in-guest switch that survives a restart, by
design. To revoke durably, relaunch with a rotated server launch key and
updated signed documents and peer key sets. Every boot requires valid
`opkeydata`; omitting it prevents the node from starting. A certificate already
issued remains usable against its original live cluster until expiry or an
RBAC change.

What the gate proves: a genuine guest of the manifest's platform booted
exactly the pinned image, was launched to trust exactly this operator key,
and (on TDX) ran exactly the expected measured workloads. What it does not prove: anything about images or keys the
manifest and flags do not name, or the provenance of the manifest file itself
— select it deliberately from the trusted image build. An RTMR[3]-only gate
would prove much less: the untrusted host stages the operator public key, so
it can boot **any** image and reproduce the bare operator-key register — the
image tuple is the identity anchor, and RTMR[3] then binds the key and
workload set to it.

## Injection contract

The webhook only reads pod metadata. A `ConfidentialWorkload` CR is not
required for injection. The single webhook entry (`pods.c8s.confidential.ai`)
excludes the release namespace and the router's via its namespaceSelector, so
the chart's own pods never hit the webhook during bootstrap; router's get-cert
containers are rendered directly into its pod template by the chart instead of
injected.

Opt a pod template in with:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

`confidential.ai/cw` is required. The certificate SAN is derived from it: an
id that names the operator-managed headless Service gets that Service's
in-cluster DNS name (`c8s-<id>.<namespace>.svc`, which CDS's default
`--dns-san-pattern` signs); an id that cannot name a Service (dots, length
over 59) is used as the SAN verbatim and must match a CDS pattern itself.
A workload adopted into C8s whose clients already dial an existing Service
name can set `confidential.ai/c8s-san` to that name instead; the annotation
value is used as the requested SAN verbatim and must match a CDS pattern.
Injection does not require a CR lookup.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume into the pod's mesh endpoint and credential sidecars at
  `/etc/c8s/certs`;
- prepends a `c8s-cert` native sidecar (init container with
  `restartPolicy: Always`) that fetches the first cert before application
  containers start and then renews `tls.crt` every
  `webhook.getCert.renewInterval`;
- prepends a `c8s-cert-wait` run-once init container after it that gates the
  application containers on the initial cert (see below);
- stamps `confidential.ai/c8s-injected=true` to make reinvocation a no-op.

The sidecar runs:

```bash
get-cert \
  --attestation-api-url=<release-attestation-api-url> \
  --san=<derived from confidential.ai/cw, e.g. c8s-api.default.svc> \
  --cert-path=/etc/c8s/certs/tls.crt \
  --key-path=/etc/c8s/certs/tls.key \
  --ca-path=/etc/c8s/certs/ca.crt \
  --renew-interval=<webhook.getCert.renewInterval> \
  --continue-on-initial-error
```

get-cert writes the leaf, key and CA together under `generations/` and
atomically replaces the `current` symlink. Readers resolve `current` once and
read all three files from that directory for a consistent generation.
The stable `tls.key`, `ca.crt` and `tls.crt` hard links are replaced in that
order and can span generations during renewal. On a sidecar restart, a valid
stored generation remains available until its replacement is published;
every certificate request generates a fresh key. After a withdrawal the pod
stays bound to the CA key its `issuer` record names and re-issues under it;
only a pod whose `issuer` record cannot be read publishes nothing until it is
recreated.

In renewal mode, `--ca-watch-interval` defaults to one minute. It compares
CDS `/ca` with `--ca-path` and renews when the CA certificate changes under
the pod's bound issuer key; it also watches the stamped allowlist policy unless
`--no-workload-claims`. Replacing the CDS CA key requires pod recreation.

`tls.crt` is the full chain (leaf first, mesh CA after); `ca.crt` is the mesh
CA alone, world-readable, for applications that take the trust anchor as a
separate file (`mysqld --ssl-ca`, clients doing `VERIFY_CA` against peers on
the mesh). The directory and the three file names are the injector's: a pod
carrying `confidential.ai/c8s-cert-volume`, `confidential.ai/c8s-cert-dir`,
`confidential.ai/c8s-cert-file`, `confidential.ai/c8s-key-file` or
`confidential.ai/c8s-ca-file` is refused.

`tls.key` is written `0640` owned by the get-cert user (UID/GID 65532, the pod's
`fsGroup`). An image whose entrypoint starts as root and then drops to a
service user (`gosu`, `su`) loses supplementary groups and can no longer read
it; either run the container as UID 65532, or have the entrypoint copy the
key into a directory the service user owns before dropping privileges.
The `c8s-cert-wait` init container (`/c8s probe-file --wait /etc/c8s/certs/tls.crt`)
gates the application containers on the initial cert being written: it blocks
until the cert exists, then exits, and normal init-completion ordering holds the
workload until then — fail-closed. Renewals publish a new generation;
application-level TLS reload is the workload's responsibility.

Platform-owned workloads can specialize the same webhook behavior with typed
C8s annotations for the renewal interval, discovery output, and get-cert
UID/GID. (router, living in the
webhook-excluded `c8s-router` namespace, renders the whole member shape —
endpoint, get-cert containers and the credential paths above — from the
chart's templates instead.) The webhook rejects an
incomplete discovery annotation set during pod admission instead of admitting
a pod that cannot serve its configured discovery path. The sidecars mount at fixed
destinations, which the allowlist pins; see
[Fixed sidecar mounts](secrets.md#fixed-sidecar-mounts).

## router public TLS modes

`router.publicTLS.mode` selects which credential terminates public TLS at the
front door:

- `cds` (default) — get-cert provisions a mesh-CA-issued serving leaf into a
  pod-local volume; the key stays inside the pod's TEE.
- `webpki` — nginx serves an operator-supplied `publicTLS` Secret; the key is
  host-visible. The Secret lives in the `c8s-router` namespace, the one the
  router pod runs in.
- `acme` — the `c8s acme` sidecar keeps one multi-SAN WebPKI certificate for
  the validated router SAN list via ACME HTTP-01: nginx's :80 server proxies
  `/.well-known/acme-challenge/` to the sidecar's loopback challenge listener
  and 301s everything else to https. The CA's validation fetch arrives on that
  port, so the mode needs :80 reachable from the internet, not just from the
  cluster. The chain lives in one Memory-medium emptyDir and the serving key
  with the ACME account state in another, so the front door mounts both while
  the attestation sidecar — which runs as the same identity and only needs the
  leaf it binds — mounts the chain alone. Both are TEE-held under a
  confidential runtime (which this mode requires), lost with the pod and
  re-issued on recreation (point the sidecar at an ACME staging directory in
  tests to stay clear of the CA's duplicate-certificate limits). Renewal fires
  at 2/3 lifetime; nginx's own entrypoint re-reads the files it serves and
  reloads on each install. On start the sidecar writes a self-signed
  placeholder so nginx, whose config names the cert files, can start before
  the first issuance.

The mode is a trust statement, not plumbing: the attestation sidecar commits
it into the attest-pq and attest-lb report_data transcripts and echoes it as
`front_door_mode`, and attest-lb — the transport binding to the exact serving
leaf — is served only for the TEE-held-key modes, `cds` and `acme`; `webpki`
is attest-pq-only.

When `cds-attest --measured-policies-file` names the node's measured-policy
journal, both bundles also carry `measured_policies`: the policy digests the
node extended into RTMR[3], read after the quote and outside any transcript.
The chart passes the journal under `nriImagePolicy.hostPaths.runtimeDir`
wherever the router mounts the attestation-api socket; an absent journal
omits the list. With an operator-key anchor, `c8s verify` replays it against
RTMR[3] (see
[Check a node's policy history](#check-a-nodes-policy-history) and
[Measured policy history](allowlist-and-capabilities.md#measured-policy-history)).

CDS, cred-release, the mesh, `launch-config stage` and get-cert take the
journal from `--measured-policies-file`. It defaults to
`/run/nri-image-policy/measured-policies`, except for get-cert, whose default
is the sidecar mount, `/run/c8s/workload-claims/measured-policies`. An empty
value lists none. The chart passes CDS and the mesh the journal under
`nriImagePolicy.hostPaths.runtimeDir` wherever it mounts the attestation-api
socket. A producer logs once, naming
the path, when the journal is missing. The plugin's digests endpoint reads the
journal in its runtime directory.

To roll out policy measurement, upgrade in this order:

1. CDS and every verifier: cred-release, the mesh, router discovery and
   `c8s get-kubeconfig`. An older verifier rejects a node that measures
   policies.
2. The clients that send the list: get-cert and the CDS client. An older CDS
   rejects an `/attest` request carrying `runtime_extensions` with 422 (`invalid_request`).
3. The node's policy measurer.

At boot the measurer and its readers start in any order: the journal records
each policy before extending it, and every reader reads it after its report.

On a baked node image (`node.baked=true`, set by `c8s node-image render`), the
signed launch file selects the mode at boot. Mode `acme` applies when its
`router.hostnames` is not empty, else mode `cds`. See "Authenticated launch
configuration".

### Verify a saved attest-lb receipt

A client can verify an `attest-lb` response after the fact. Keep the 32-byte
challenge it sent and the serving certificate it observed on the HTTPS
connection that fetched the receipt; a certificate fetched over another
connection proves nothing about that receipt.

```bash
c8s verify --mode attest-lb --from-file receipt.json \
  --attestation-nonce "$NONCE" --observed-serving-cert serving-leaf.pem \
  --route-digest "$ROUTE_DIGEST" --measurements "$MEASUREMENT" -o json
```

`NONCE` is the challenge as unpadded base64url; `MEASUREMENT` is the pinned
launch digest; `ROUTE_DIGEST` is the route digest the receipt must bind (a
saved receipt takes `--route-digest` only). The verdict checks the challenge, the serving certificate, the
mesh identity proof and the hardware report, and reports `serving_leaf_sha256`
in the same form as the receipt so the client can match the two. It is never
`fresh`: the caller chose the nonce, so the verdict says what that connection
was, not what the front door serves now.

## Router front door

### Built-in allowlist route

The chart publishes CDS's complete `/allowlist` API through router by default.
It renders exact `/allowlist` and `/allowlist/` prefix locations backed by the
release's chart-managed CDS Service, so lookalike paths such as `/allowlisted`
are not exposed. The router-to-CDS hop verifies CDS's armTLS attestation using
`cds.measurements`; `c8s install --measurements` populates that pin in node-CVM
mode. An empty pin still verifies that the peer is a TEE but accepts any launch
measurement, which is unsafe outside development.

Before nginx collapses requests onto the loopback proxy connection, it
rate-limits the route while it still has the public client address. Mutation
methods are limited per client (`router.allowlist.rateLimit.requestsPerSecond`/
`burst`, default 1 r/s, burst 5) and in aggregate across all clients
(`totalRequestsPerSecond`/`totalBurst`, default 8 r/s, burst 15). The
aggregate bound matters because CDS rate-limits per source IP and sees every
front-door request as the one router pod IP: without it, many distinct public
clients each inside their per-client budget could drain the single CDS bucket
that signed operator writes share. The chart requires the per-client values
not to exceed the totals and the totals to stay below `cds.rateLimit`/
`rateBurst`. Reads (GET/HEAD) are limited per client under
`router.allowlist.readRateLimit` (default 20 r/s, burst 40) so unauthenticated
read pressure on CDS — which also serves attestation issuance and node
allowlist fetches — stays bounded; CORS preflights are exempt. If a flood
saturates the front-door buckets, signed writes still work over a direct CDS
URL or port-forward, which CDS accounts under the caller's own source IP.
LoadBalancer and NodePort Services default to `externalTrafficPolicy: Local`
while this route or the attestation endpoints (`router.attest.enabled`) are on,
so nginx receives the public source address their per-client keys need;
`router.service.externalTrafficPolicy` overrides (Local delivers traffic only
through nodes that run the router pod).

The attestation sidecar bounds what one client may hold as well as how fast it
may ask: 512 concurrent sessions per client address (an IPv6 client is one
/64), inside a pool of 8192. A pool that is full gives up the idlest session,
and only from a client above the share the pool divides between its holders
and the caller, never below 8 entries, so a client holding a handful is not
drained by one holding thousands. Once every holder is down to that floor —
which takes 1024 client addresses holding sessions — a new session is refused
with 503 until one expires.

The proxy preserves the request method, original URI and query, body, and
`Authorization` header. Reads remain unauthenticated at CDS. Writes still
require the short-lived, body-bound operator token generated by
`c8s allowlist --operator-key`; the operator private key is never mounted in
router or CDS.
Use the router URL with `c8s allowlist --url` and pin router's launch digest
with `--measurements` only when `router.publicTLS.mode` is `cds`. In the other
modes the public certificate is not yet bound to the discovery attestation and
the CLI refuses that front door. Use a direct CDS armTLS URL (or a CDS
port-forward) and pin the CDS launch digest instead.

Set `router.allowlist.enabled=false` to remove this route. No route manifest
path under `/allowlist` is routed either way. Application requests route by the
[route manifest](#route-manifest).

## Certificate file permissions

`get-cert` writes private keys with mode `0640` (owner read/write, group read)
in setgid directories and `0600` (owner read/write) elsewhere, on every write.
The webhook sets `fsGroup: 65532` on injected pods that do not already
define an `fsGroup`. This lets application containers running
as a different non-root UID read `tls.key` through the shared group.

Relevant values:

```yaml
webhook:
  certVolume:
    fsGroup: 65532
  getCert:
    renewInterval: 2h
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
```

Set `webhook.certVolume.fsGroup` to `-1` to disable pod `fsGroup` mutation.
The webhook preserves an existing pod `fsGroup`.

For workloads that require UID 0, set
`webhook.getCert.runAsUser=0`, `webhook.getCert.runAsGroup=0`, and
`webhook.getCert.runAsNonRoot=false`. The install CLI exposes those as
`--webhook-get-cert-run-as-user`, `--webhook-get-cert-run-as-group`, and
`--webhook-get-cert-run-as-non-root=false`. The renewal interval is exposed as
`--webhook-get-cert-renew-interval`.

The injected get-cert containers also use a locked-down security context:

- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsNonRoot: true` by default
- drops all Linux capabilities
- `seccompProfile: RuntimeDefault`

## Network policies

The chart ships default-deny ingress for every component it runs. Each pod
accepts only the ports it declares and nothing else on the pod network reaches
it:

| Policy | Selects | Accepts |
|---|---|---|
| `c8s-attestation-api` | attestation-api | nothing (it binds pod loopback) |
| `c8s-cds-ingress` | cds | `cds.port` (armTLS; also the NodePort route) |
| `c8s-operator-ingress` | operator | 9443 webhook, 8081 probes, 8080 metrics |
| `c8s-volumed-ingress` | volumed | nothing (it serves a node-local Unix socket) |
| `c8s-router-ingress` | router (in `c8s-router`) | `router.nginx.httpsPort`, plus the :80 HTTP-01/redirect server in `publicTLS.mode=acme` |

They are ingress-only. NetworkPolicies union, and what bounds a member pod's
reach is its own packet ruleset.

**None of them restricts the source of a connection** — no rule carries a
`from`, so each one narrows which port answers, not who may connect. router is
the public front door and stays reachable from off-cluster; the API server that
dials the admission webhook has no address a selector could name; get-cert runs
beside every adopted workload in every namespace; and the CDS NodePort route
arrives off-cluster too. `c8s-volumed-ingress`, which has no `ingress:` rules at
all, is the only one that refuses everything.

**Opening another port.** Policies are additive, so apply your own
`NetworkPolicy` selecting the same pods — there is nothing to disable first:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cds-extra-port
  namespace: c8s-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: c8s-operator
      app.kubernetes.io/instance: c8s
      app.kubernetes.io/component: cds
  policyTypes: [Ingress]
  ingress:
    - ports:
        - protocol: TCP
          port: 9000
```

These are inert on a cluster whose CNI does not enforce NetworkPolicy.

## Validation

Run the full Go suite:

```bash
go test ./...
```

Run the chart tests only:

```bash
go test ./internal/helmchart
```

Validate the chart with `helm template` (use it, not `helm lint`: lint's
standalone YAML parse chokes on the nri-image-policy installer's embedded
host-config heredoc, while `helm template` — the path CI and the chart tests
use — renders it correctly).

The chart ships no default image tag, so a bare `helm template` must set one.
`c8s install` injects this for you; `main` here is the same fallback tag it
uses for a non-release build. The simplest validation disables the image-policy
component, so only image tags are required (no digests). Disabling it renders
only because the chart's default `attestationApi.cvmMode=bare-metal` bakes its own
policy plugin and so is exempt from the `require_host_image_policy` guard; other
modes (gke/aks) must keep nri-image-policy enabled and digest-pinned, as in the
full-shape render below. Both renders pin neither CDS nor the operator keys,
so they set `router.routing.allowUnpinnedCDS`; a real install pins one instead.

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set router.routing.allowUnpinnedCDS=true \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set armtlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false >/dev/null && echo OK
```

To render the full default shape (image policy enabled), the chart requires the
nri-image-policy installer image and the CDS image to be digest-pinned, and
`nriImagePolicy.mesh.resolver` to name the cluster DNS service address. Set
`nriImagePolicy.mesh.clusterRanges` to the pod and Service CIDRs. The CDS
node selector defaults to `role: cds`; override it if your CDS node uses a
different label. `c8s install` fills these digests from the registry by default
(via `crane`); for a manual render the values below are placeholders:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set router.routing.allowUnpinnedCDS=true \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set armtlsMesh.image.tag=main \
  --set nriImagePolicy.image.tag=main \
  --set nriImagePolicy.mesh.resolver=10.96.0.10 \
  --set 'nriImagePolicy.mesh.clusterRanges={10.244.0.0/16,10.96.0.0/12}' \
  --set nriImagePolicy.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 >/dev/null && echo OK
```

Append `--set-file cds.operatorKeys=operator.pub` to either command to render
the operator-keys ConfigMap and the CDS `--operator-keys` flag that gate
allowlist writes.

The rendered manifests should include:

- a CDS Deployment, Service, and ServiceAccount;
- no CDS admin-password Secret and no attestation-api API-key Secret;
- `confidential.ai/trust-root-mode: inMemory` annotations on the chart-managed
  CDS resources.
