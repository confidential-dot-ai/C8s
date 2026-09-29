# c8s operator and Helm chart

The c8s operator installs the Kubernetes-facing c8s components. It hosts
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

The operator does not inject the RA-TLS mesh sidecar. Pod-to-pod mTLS remains
the responsibility of node-level `ratls-mesh`, deployed as a DaemonSet by
the chart or as systemd services by the measured node image. The chart-managed
mesh excludes `kube-system` and its own release namespace as local traffic
sources, so c8s control-plane agents (and, on kind/kubeadm-style clusters where
the API server runs as a `kube-system` pod, in-cluster webhook callers) do not
get captured by the pod-to-pod mesh path. The exclusion is one-sided: it
removes those pods as PREROUTING sources but keeps their IPs in the destination
ipset, so a workload that connects to a `kube-system` or release-namespace pod
by pod IP — bypassing the Service VIP — will still be DNATed into the mesh and
fail mTLS against a peer with no ratls sidecar. In-cluster Service-VIP traffic
to those namespaces is unaffected because kube-proxy DNATs the VIP before the
mesh chain matches.

Confidential-workload pods (label `confidential.ai/cw`) get a stricter
inbound posture from the always-on cw guard: the mesh drops FORWARD-path
traffic to their pod IPs, so Service-VIP dials and excluded-namespace sources
are blocked instead of reaching the workload in plaintext.
`ratlsMesh.cwInboundEnforcement.passthrough` (default `udp:53,tcp:53`) is the
reply allowlist that keeps DNS working; an empty list is strict drop-all. It
admits replies only on the stock ephemeral window (32768-60999), which costs a
cw pod its DNS if the pod moves `net.ipv4.ip_local_port_range` *and* the
dataplane breaks the reply's conntrack tuple — see the
`RATLSMeshCWInboundDrops` alert description for the triage path.
Only mesh-delivered traffic and node-local host processes
(kubelet probes) reach cw pods.

## Ownership model

Installing the c8s chart is a platform-admin operation, not a fully
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
The [measured node image](../node-guest-image/README.md) runs CDS, the RA-TLS
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

The strict `c8s-launch/v2` document selects the role, cluster identity, node
addresses, trusted role keys, image pins and TLS SAN. It contains no RKE2
credentials and rejects the entire `rke2` field, including empty values.
It accepts an optional `workloads` string containing a complete
`c8s.allowlist/v1` JSON document. It does not accept Helm values, arbitrary
service arguments or component toggles; volume support remains disabled.

Use **distinct launch keys for server and agent roles, and new keys for
each cluster**. `clusterID` is a descriptive RFC1123 label; the distinct
launch keys establish cluster separation during peer verification. Keep one
server key and one or more agent keys. The server generates its separate
agent credential inside the guest; RKE2 generates the privileged server token.
Neither credential is present on the host launch disk. Existing v1 bundles
must remove the `rke2` field, set `schemaVersion: c8s-launch/v2`, and be signed
again before use with this image.

`c8s node launch-config new` creates everything one cluster needs: a server
launch key, an agent launch key, a signed `launch.yaml`
per node and the client policy that pins the server. Give it the trusted
`manifest.json` published with the exact node image, the server's guest IPv4
address that every node can reach, and the agent names. On SNP, also pass
the VM's vCPU count, which selects the launch digest.

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
| `demo/server.key` | server launch key; also the operator key for `c8s get-kubeconfig --operator-key` and signed CDS writes |
| `demo/agent.key` | the agent launch key every agent boots with |
| `demo/server.json` | `C8S_MEASUREMENTS_CONFIG` for clients of this cluster |
| `demo/server/` | `pubkey`, `launch.yaml`, `launch.yaml.sig`: the server's opkeydata |
| `demo/<agent>/` | the same three files for each agent |

An agent can be added to a running cluster without touching the server:
`c8s node launch-config add-agent --bundle demo --name demo-agent-3` derives
its document from the server's (same cluster, image and keys) and signs it
with the agent key. A server created
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
to `c8s.local` and must be a lowercase DNS hostname. The built-in front door
serves a CDS-issued certificate; arbitrary routes, public WebPKI configuration
and CORS overrides are not launch settings in this image.

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
agents; `cds.json` contains only its server. On a server with authorized
agents, `agents.json` contains only those agent identities. Their shared
measurement-file
schema carries `approver_key` as the exact PEM string alongside each entry's
image measurement and TDX RTMR tuple. This lets peers accept both roles while
CDS clients require the authorized server despite identical software images.
The schema belongs to attestation-go's `refvalues` package: `approver_key`
maps to `remote.ImagePin.Anchor`. `remote.EnforceImages` checks the image and
calls `runtimemeasure.VerifyBinding` for that same pin, so an image cannot
borrow another entry's authorized key. c8s passes these complete pins through
`remote.Policy.Images`; legacy flags that cannot carry anchors are refused
where they would weaken enforcement.
Boot preparation copies the public identity policies to `/run/c8s-node`;
core Pods mount that directory read-only without access to the private launch
directory. The operator forwards the full server policy to injected workload
helpers, which use the in-cluster CDS Service URL. NRI uses the same server
policy from private staging and reaches CDS through the signed server
address and NodePort. Private keys never enter the public policy directory,
and no RKE2 credential exists on launch media at all.

On servers with an authorized agent policy, `c8s-join-release.service`
listens on TCP `8444`. An agent's `c8s-join.service` authenticates that server
with the pinned image and designated server key; the server checks the
agent's pinned image and an explicitly authorized agent key. Both endpoints
prove possession of their attested TLS keys. This works with TDX and SNP,
using the same image and platform tuple throughout each cluster. Only the
agent credential with its RKE2 CA pin is released, and the agent stages it
in root-only `/run/confos/rke2-agent-token` before RKE2 may start. A server
without authorized agents does not start the release listener.

The released agent credential remains a secret RKE2 enrollment credential
once inside the guest. The RA-TLS mesh protects selected pod traffic; it does
not wrap the RKE2 supervisor on port `9345` or the Kubernetes API on port
`6443`. RKE2 generates the privileged server token itself, so no server-
enrollment credential ever leaves the server guest. See
[RKE2 token management](https://docs.rke2.io/security/token).

Enrollment waits indefinitely while the server is unavailable: the unit
restarts on failure with a five-second backoff. Until it succeeds, RKE2
agent startup remains blocked; enrollment does not depend on CDS, the mesh,
Kubernetes or kubelet. Nodes in different datacenters need agent-to-server
TCP `8444`, RKE2 TCP `9345` and `6443`, and routed guest connectivity for
the mesh and CNI. There is no NAT traversal or control-plane failover.

The server's generated agent credential survives launch staging and service
restarts within the same boot. All guest runtime state, including RKE2's
server credential and CA, resets on a full VM reboot. Relaunch agents after
a server reboot so they enroll against the new ephemeral cluster.

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
  grants no node access. (docs/ratls.md, "Sandbox identity".)

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

Install with the CLI. Adopt a running workload as a CW and front it behind
router with `--upstream` (see [Existing workload adoption](#existing-workload-adoption)
and [router upstream](#router-upstream)):

```bash
c8s install \
  --workload-ref vllm=vllm/deployment/serving:8000 \
  --upstream vllm
```

### Existing workload adoption

If vLLM is already deployed, `install` can adopt the router as one CW and the
serving engine as another, giving each its own confidential workload identity
without any GitOps overlay wiring:

```bash
c8s install \
  --workload-ref vllm-router=vllm/deployment/vllm-deployment-router:8000 \
  --workload-ref vllm-engine=vllm/deployment/<serving-engine-deployment> \
  --upstream vllm-router
```

The ref syntax is `<cw-id>=<namespace>/<kind>/<name>[:<port>]`, where kind is any
resource exposing a pod template at `spec.template` (`deployment`,
`statefulset`, `daemonset`, or an operator CRD such as `<kind>.<group>`); the
optional `:<port>` is the router upstream port, needed on the ref `--upstream`
selects. After Helm reports the c8s release ready, the CLI patches each workload
pod template with `confidential.ai/cw: <id>`. Those rollouts go through the
webhook, and the workload-service reconciler creates the `c8s-<id>` headless
Services. `--upstream vllm-router` points router at
`c8s-vllm-router.vllm.svc.cluster.local:8000` (its `<cw-id>` must be one of the
adopted refs, carrying a `:<port>`). With `--resolve-digests=true`, install resolves adopted workload
images into `nriImagePolicy.bootstrapAllowlist.workloads` entries admitting them
under any command and args, so image admission (the node NRI plugin) allows
those rollouts.

`c8s install --install-crds=false` passes Helm's `--skip-crds`; CRDs are
advisory and not required for pod injection. That path also disables the
CRD-backed status mirror controller; if CRDs are absent at runtime, the
operator skips that controller rather than failing startup.

The default `deny-host-namespaces` policy rejects host namespaces outside
trusted platform namespaces.

## Uninstall

`c8s uninstall` reverses `c8s install`. It runs `helm uninstall` to remove the
release (operator, CDS, attestation-api, ratls-mesh, router, the
webhook configuration and admission policies). The
`MutatingWebhookConfiguration` is release-tracked, so it is deleted with the
release — a `failurePolicy: Fail` webhook cannot outlive the operator Service
and block pod creation cluster-wide.

It then **sweeps the host-side artifacts** that chart hooks cannot guarantee
were removed: chart-installed NRI policy, ratls-mesh netfilter state, and the
managed RKE2 containerd-prep template. Baked node-image components are preserved.
The host paths are read from the release's computed values *before* deletion,
so install-time `-f` overrides are honored. `--host-sweep=false` skips this cleanup.

The sweep removes:

- the NRI image-policy containerd registration (drop-in or managed config
  block), binary, config, and state directories. It skips these on the c8s
  node image, detected via the baked-only `nri-node-ip.service`: that stack is
  the image's to keep, not the release's to delete;
- the `RATLS-MESH` chains and base-chain jumps in `iptables` and `ip6tables`,
  and the `RATLS-MESH-*` ipsets. The mesh's own preStop deliberately keeps the
  fail-closed guard, so this state survives healthy uninstall. A stale
  `OUTPUT` redirect blackholes host-originated pod traffic for non-root users;
- on RKE2, the sentinel-marked containerd template written by containerd-prep
  and its lock file, skipped on the baked node image by the same rule.

The swept paths are cluster-global, so running two c8s releases in one
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
`emptyDir` allowlist DB or a PVC when `cds.persistence.enabled=true`. The
operator injects pods with the chart-managed CDS Service URL. Allowlist
writes (`POST`, `PUT`, `DELETE /allowlist`) are authorized by an operator key:
the caller presents a short-lived token signed by an operator EC private key
whose public half is pinned in `cds.operatorKeys`. The `c8s allowlist` CLI mints
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
sets this value for you. In a GitOps flow, `c8s render-values --operator-keys
operator.pub` embeds the content into the emitted values.

The value is the PEM **content**, never a file path — a path from the machine
that rendered the values is meaningless in-cluster, and the chart fails the
render when the value doesn't look like PEM.

### Operational warning: CDS is a singleton

CDS runs as a single replica with the in-memory mesh CA key, and **any
restart is a full re-bootstrap event**: the replacement pod generates a
fresh CA whose public key is not signed by anything ratls-mesh already
trusts. `pkg/ratls/cdsclient`'s continuity check then refuses the new CA on
the next `/ca` poll, CDS keeps signing leaves with the new key, no workload
trusts them, and the mesh degrades as old leaves expire. Recovery is to
restart every workload so its get-cert init container re-runs the CDS
provisioning flow.

The router discovery endpoints (`/.well-known/mesh-ca.pem`,
`/.well-known/cds-cert.pem`, `/v1/discovery`) track the new CA without a
router restart: the c8s-cert sidecar polls CDS's `/ca` every
`router.certProvisioning.caWatchInterval` (default 1m) over the same
RA-TLS-verified channel it obtains certificates on, and re-issues its leaf —
rewriting the served CA bundle and discovery document — as soon as CDS holds
a CA the served bundle is missing. External clients that pinned the old CA
must still re-fetch it from the discovery endpoint.

There is **no scheduled in-process CA rotation today** — no cds flag or
loop drives it, so every CA fingerprint change is a restart-shaped
re-bootstrap. (An unwired rotator exists at `internal/issuer.CARotator`:
it signs a successor CA with the still-live current CA's key, so the
continuity check would accept it and workloads would pick it up on their
next `/ca` refresh, without re-bootstrap. Wiring it into `c8s cds` is
future work.)

With CDS a singleton:

- run CDS with `replicas: 1` and `strategy: Recreate` (default in
  this chart);
- guard the CDS Deployment with a PodDisruptionBudget that blocks
  voluntary disruptions;
- treat any CDS restart as a planned maintenance event with workload
  churn;
- watch CDS startup logs for the active CA fingerprint — any fingerprint
  change means a restart happened and workload re-provisioning is needed.

### Operator-added allowlist entries across restarts

For the measured node image, CDS stores its database at `/data/allowlist.db`
in the Pod's `emptyDir`. A container restart preserves that directory; Pod
recreation or a VM reboot loses it. The baked component seed and optional
signed `workloads` document initialize the new store; reapply any later
operator changes. The CA signing key is in process memory and changes on
any CDS process restart, so plan for certificate re-bootstrap even when the
database survives. This image does not expose a persistent-volume switch in
launch configuration.

For chart-managed CDS:

Pod recreation also resets the **served allowlist**. CDS seeds its store
from the install seed at startup, then serves whatever an operator writes
with `c8s allowlist add` or `apply`. With `cds.persistence.enabled=false`
(the default), that store is an `emptyDir`: it survives a container restart,
but drain, upgrade or scale-down can recreate the Pod and lose every
operator-added entry. CDS logs a warning at startup when persistence is off.
To keep dynamic entries across Pod recreation set
`cds.persistence.enabled=true` (an RWO PVC); otherwise re-apply the entries
after the store is recreated. The chart-seeded component entries are
unaffected — they are re-seeded and, unlike dynamic entries, are also admitted
from the plugin's base allowlist. Recreating the store also resets the
allowlist version counter, and
every enforcer ignores a served version at or below the one it last applied
(`docs/allowlist-and-capabilities.md`, "Refresh and anti-rollback"): a plugin
that had applied version N stays on that policy until the restarted
CDS counts past N again, or the plugin itself restarts.

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
# CDS's RA-TLS endpoint answers unattested clients:
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &

c8s cds verify https://localhost:8443 --measurements <sha384-launch-digest>

# JSON + exit codes for CI:
c8s cds verify https://localhost:8443 --measurements-file digests.txt -o json
```

PKI/SAN mismatch when dialing localhost or a pod IP is fine — `verify` trusts
the attestation embedded in the serving cert, not the certificate chain.

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
`--image-manifest` requirement. Note its scope: it pins the **bare** seed,
i.e. a node with no per-workload RTMR[3] extends on top. That is what every
node reports today; `c8s get-kubeconfig` is the command that also folds
`--workload-image` extends into the expected register. Supplying any of these
flags against SEV-SNP evidence is a policy error, not an ignored option: SNP
has no runtime measurement registers.

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
or when a live TLS handshake proves the peer holds the attested key. For
`--mode discovery` on an https target that handshake doubles as the front-door
check below: a CA-issued discovery certificate the live door presents
byte-identically is authenticated by possession. A door serving some other
certificate — or a fetch with no handshake to observe (a non-https target) —
still requires `--mesh-ca` (the document publishes `cds_tls.mesh_ca_url`).

Exit codes are a CI contract: `0` verified, `1` usage error, `2`
verification/policy failed (e.g. wrong measurement), `3` evidence unavailable
(unreachable/unparseable), `4` partially verified — the evidence verified, but
a property it presents is not proven. The three partial cases today: the
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

Caveats the output surfaces:

- **Freshness.** Verifying an RA-TLS serving cert binds REPORTDATA to the
  certificate key, not a per-request nonce, so it proves "this key was born in a
  TEE with this measurement" but not "freshly now" (`fresh: false`).

### Complete measured identity policies

Image policy files preserve each image measurement, its TDX RTMR tuple and
optional `approver_key` as one policy entry. The key is the exact PEM string;
attestation-go's `refvalues` package maps it to `remote.ImagePin.Anchor`.
`remote.EnforceImages` checks the image and calls `runtimemeasure.VerifyBinding`
for that same entry. An image cannot borrow another entry's authorized key.
c8s passes these entries through `remote.Policy.Images` to its attestation
clients and injected workload helpers. Each verifier enforces the complete
entry, including its launch-key binding when present.

### Image policy inputs

A complete image policy is a JSON document containing each trusted image's
launch digest, TDX registers where applicable, and optional launch-key anchor.
File and inline inputs use the same JSON format:

| Input | Contents |
|---|---|
| `--image-policy-file policy.json` | Path to a complete JSON image policy. |
| `--image-policy-json '{...}'` | The JSON document itself; supported by workload helpers such as `get-cert` and `get-secret`. |
| `--measurements-file digests.txt` | Text file containing one launch digest per line; no per-image register or key bindings. Supported by `verify`, `allowlist`, and `secrets`. |

Choose one complete policy source. A complete policy cannot be combined with
independent digest or register inputs such as `--measurements`,
`--measurements-file`, or `--rtmrs` (including the `--cds-` variants where
provided). These independent inputs remain available for policies expressed as
a digest list and a shared register set. Mesh peers and CDS can use separate
files; `--cds-image-policy-file` selects the CDS-only policy for `ratls-mesh`.

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
both on the RA-TLS connection and on a fresh nonce-bound attestation report:

- **platform** — the `--image-manifest` shape selects it (a TDX tuple or SNP
  `snp_variants`); a node of any other platform is refused up front;
- **guest image (TDX)** — MRTD, RTMR[1] and RTMR[2] must match the tuple from
  `--image-manifest` (required), an explicitly selected, provenanced
  build-artifact manifest carrying all three fields under its `tdx` object. A
  generic artifact-hash `manifest.json` is not an image pin and is rejected;
- **RTMR[3] chain (TDX)** — the register must equal the operator-key seed
  (`runtimemeasure.Seed` over the exact pubkey PEM bytes)
  extended, in order, by each digest-pinned `--workload-image` ref (tags are
  rejected). With no `--workload-image` the register must equal the bare seed;
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
c8s node image, create an equivalent `ClusterRoleBinding` or pass `--cert-org`
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
excludes the release namespace via its namespaceSelector, so the chart's own
pods never hit the webhook during bootstrap; router's get-cert containers are
rendered directly into its pod template by the chart instead of injected.

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
A workload adopted into c8s whose clients already dial an existing Service
name can set `confidential.ai/c8s-san` to that name instead; the annotation
value is used as the requested SAN verbatim and must match a CDS pattern.
Injection does not require a CR lookup.

For opted-in pods, the webhook:

- adds an in-memory `emptyDir` volume named `c8s-certs`;
- mounts that volume read-only into application containers at
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
  --cds-url=https://<release>-cds.<namespace>.svc:8443 \
  --attestation-api-url=<release-attestation-api-url> \
  --san=<derived from confidential.ai/cw, e.g. c8s-api.default.svc> \
  --out=/etc/c8s/certs/tls.crt \
  --key-out=/etc/c8s/certs/tls.key \
  --ca-out=/etc/c8s/certs/ca.crt \
  --renew-interval=<webhook.getCert.renewInterval> \
  --reload-nginx=<from annotation> \
  --continue-on-initial-error
```

`--key-out` is idempotent: on a kubelet restart of the sidecar it reuses the
key that's already on disk, so the previously-issued cert chain stays valid.
`tls.crt` is the full chain (leaf first, mesh CA after); `ca.crt` is the mesh
CA alone, world-readable, for applications that take the trust anchor as a
separate file (`mysqld --ssl-ca`, clients doing `VERIFY_CA` against peers on
the mesh). File names are overridable per pod with `confidential.ai/c8s-cert-file`,
`confidential.ai/c8s-key-file`, and `confidential.ai/c8s-ca-file`.

`tls.key` is written `0640` owned by the get-cert user (UID/GID 65532, the pod's
`fsGroup`). An image whose entrypoint starts as root and then drops to a
service user (`gosu`, `su`) loses supplementary groups and can no longer read
it; either run the container as UID 65532, or have the entrypoint copy the
key into a directory the service user owns before dropping privileges.
The `c8s-cert-wait` init container (`/c8s probe-file --wait /etc/c8s/certs/tls.crt`)
gates the application containers on the initial cert being written: it blocks
until the cert exists, then exits, and normal init-completion ordering holds the
workload until then — fail-closed. Renewals rewrite the file on disk;
application-level TLS reload remains the workload's responsibility unless the
pod opts into one of the c8s reload annotations.

Platform-owned workloads can specialize the same webhook behavior with typed
c8s annotations for the cert volume, cert/key filenames, renewal interval,
nginx reload, Secret watch paths, discovery output, and get-cert UID/GID.
(router, living in the webhook-excluded release namespace, renders equivalent
get-cert containers directly from the chart's templates instead.) The
webhook rejects incomplete reload-watch or discovery annotation sets during pod
admission instead of admitting a pod that cannot serve its configured
certificate/discovery path.

## router public TLS modes

`router.publicTLS.mode` selects which credential terminates public TLS at the
front door:

- `cds` (default) — get-cert provisions a mesh-CA-issued serving leaf into a
  pod-local volume; the key stays inside the pod's TEE.
- `webpki` — nginx serves an operator-supplied `publicTLS` Secret; the key is
  host-visible.
- `acme` — the `c8s acme` sidecar keeps one multi-SAN WebPKI certificate for
  the validated router SAN list via ACME HTTP-01: nginx's :80 server proxies
  `/.well-known/acme-challenge/` to the sidecar's loopback challenge listener
  and 301s everything else to https. The CA's validation fetch arrives on that
  port, so the mode needs :80 reachable from the internet, not just from the
  cluster. Key, chain, and ACME account state live
  in a Memory-medium emptyDir — TEE-held under a confidential runtime (which
  this mode requires), lost with the pod and re-issued on recreation (point
  the sidecar at an ACME staging directory in tests to stay clear of the CA's
  duplicate-certificate limits). Renewal fires at 2/3 lifetime; each install
  SIGHUPs nginx. On start the sidecar writes a self-signed placeholder so
  nginx, whose config names the cert files, can start before the first
  issuance.

The mode is a trust statement, not plumbing: the attestation sidecar commits
it into the attest-pq and attest-lb report_data transcripts and echoes it as
`front_door_mode`, and attest-lb — the transport binding to the exact serving
leaf — is served only for the TEE-held-key modes, `cds` and `acme`; `webpki`
is attest-pq-only.

## router upstream

### Built-in allowlist route

The chart publishes CDS's complete `/allowlist` API through router by default.
It renders exact `/allowlist` and `/allowlist/` prefix locations backed by the
release's chart-managed CDS Service, so lookalike paths such as `/allowlisted`
are not exposed. The router-to-CDS hop verifies CDS's RA-TLS attestation using
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
while this route or the attestation sidecar (`router.attest.enabled`) renders,
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
the CLI refuses that front door. Use a direct CDS RA-TLS URL (or a CDS
port-forward) and pin the CDS launch digest instead.

Set `router.allowlist.enabled=false` to remove this route. For compatibility,
an explicit `router.routes` entry whose path is `/allowlist` or `/allowlist/`
takes precedence and suppresses the built-in route.

router proxies its catch-all route to one upstream, `router.upstream.address`,
an opaque `host:port` the chart never interprets. For a workload run as the
operator-managed headless Service (annotated `confidential.ai/cw`, see
[Injection contract](#injection-contract)), that upstream must be the headless
Service's own DNS name and container port,
`c8s-<id>.<namespace>.svc.cluster.local:<port>`. Headless DNS resolves
to pod IPs, which the node mesh intercepts to wrap the hop in attested mTLS; a
regular Service VIP it cannot intercept, so dialing one leaves the hop in
plaintext. Dialing the pod IP also bypasses the Service's port remapping, which
is why the explicit container port is required.

`c8s install --upstream <cw-id>` builds that string for you from an adopted
workload: `<cw-id>` must be one of your `--workload-ref` ids and that ref must
carry a `:<port>`, and install sets `router.upstream.address` to
`c8s-<id>.<ns>.svc.cluster.local:<port>` (the ref's namespace and port). The
chart recognizes that headless-Service address shape as mesh-wrapped and admits
the plaintext http hop; any other address must be app-TLS (see below):

```bash
c8s install --namespace c8s-system \
  --workload-ref infer=vllm/deployment/serving:8000 --wait \
  --upstream infer
# router.upstream.address = c8s-infer.vllm.svc.cluster.local:8000
```

Without `--upstream`, `router.upstream.address` is used as-is: an upstream that
is not a c8s-managed workload (an existing Service, an external address). The
chart cannot verify a manual address resolves to pod IPs the mesh intercepts,
so it must be `protocol: https` with `tls.verify: true`: an upstream that
terminates and authenticates TLS itself (app-TLS). There is no
plaintext-to-unattested escape hatch and no default upstream.

Leaving the upstream unset is legal: router installs and serves its cert,
discovery, and any explicit routes with **no catch-all** `location /` until one
is wired. This is the install-then-attach flow: `c8s install` stands up the
front door, and the operator attaches the workload later (`--upstream`, or a
verified-https `router.upstream.address` via `-f`). An unmatched request gets
nginx's default 404 until then.

The chart rejects, at render time, with stable `kind=` markers (the same the
chart tests assert on):

- `router_unsecured_upstream`: a `router.upstream.address` that is not a
  `c8s-<id>.<ns>.svc.cluster.local` headless-Service address is a plaintext http
  backend, or https without `tls.verify=true`. Only a verified-https (app-TLS)
  manual address is admitted; there is no acknowledgment to override this. To
  reach a confidential workload, adopt it with `--workload-ref` and pass
  `--upstream`: pointing a manual address at a Service VIP fronting cw pods is
  unmeshed, and the always-on cw guard drops it, so the hop fails closed rather
  than running plaintext.
- `workload_https_upstream`: the address is a `c8s-<id>` headless Service (a
  mesh-wrapped upstream) with `router.upstream.protocol=https`. That hop is
  plaintext at the app layer (the mesh wraps it in attested mTLS), so an https
  protocol could only fail at runtime; use http for a mesh-wrapped upstream.

The same secured-backend rule applies to every `router.routes[].backend`: it
must use `protocol: https` with `tls.verify: true` (app-TLS). A plaintext http
or unverified-https route backend fails the render (`router_unsecured_route`);
there is no acknowledgment to override it. Routes have no default backend, so
this only affects routes you configure. A confidential workload is reached via
`router.upstream` (the `--upstream` flow), not a route.

The mesh guarantee holds only when `--upstream` names a real cw workload: the
CLI checks the id is one of the adopted refs, but cannot confirm `c8s-<id>`
fronts attested cw pods. A wrong id derives a headless Service that resolves to
nothing (router has no backend) rather than a plaintext leak; the runtime
boundary that a peer is a genuine cw pod is the mesh's always-on cw inbound
guard, not this render guard.

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
| `c8s-cds-ingress` | cds | `cds.port` (RA-TLS; also the NodePort route) |
| `c8s-operator-ingress` | operator | 9443 webhook, 8081 probes, 8080 metrics |
| `c8s-volumed-ingress` | volumed | nothing (it serves a node-local Unix socket) |
| `c8s-router-ingress` | router | `router.nginx.httpsPort`, plus the :80 HTTP-01/redirect server in `publicTLS.mode=acme` |

They are ingress-only. `ratls-mesh-tcp-only-egress` already selects every pod in
the namespace and allows all TCP, and NetworkPolicies union, so an egress rule
on one component would be allowed by that policy regardless.

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
full-shape render below.

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.enabled=false >/dev/null && echo OK
```

To render the full default shape (image policy enabled), the chart requires the
nri-image-policy installer image and the CDS image to be digest-pinned. The CDS
node selector defaults to `role: cds`; override it if your CDS node uses a
different label. `c8s install` fills these digests from the registry by default
(via `crane`); for a manual render the values below are placeholders:

```bash
helm template c8s internal/helmchart/c8s \
  --namespace c8s-system \
  --set image.tag=main \
  --set attestationApi.image.tag=main \
  --set cds.image.tag=main \
  --set ratlsMesh.image.tag=main \
  --set nriImagePolicy.image.tag=main \
  --set nriImagePolicy.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 >/dev/null && echo OK
```

Append `--set-file cds.operatorKeys=operator.pub` to either command to render
the operator-keys ConfigMap and the CDS `--operator-keys` flag that gate
allowlist writes.

The rendered manifests should include:

- a CDS Deployment, Service, and ServiceAccount;
- the operator arg `--cds-url=https://c8s-cds.c8s-system.svc:8443`;
- no CDS admin-password Secret and no attestation-api API-key Secret;
- `confidential.ai/trust-root-mode: inMemory` annotations on the chart-managed
  CDS resources.
