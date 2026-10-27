# Overview

C8s runs Kubernetes workloads inside confidential VMs, so a tenant's weights,
prompts, and responses stay in Trusted Execution Environment (TEE) memory on
hardware the tenant does not own.

Guarantee: all six — [guarantees.md](guarantees.md).

Three things carry that:

- Every node is a confidential VM (CVM): a VM whose memory the CPU encrypts and
  whose launch state the hardware measures.
- Only images an operator put on the allowlist may run in it.
- A member pod — a pod the node admitted into the mesh — has its TCP captured
  and carried over armTLS, mutual TLS whose certificates carry hardware
  evidence. A few named destinations stay uncaptured; [armtls.md](armtls.md)
  lists them.

From outside the cluster a client can check the launch measurement of the
component it dials, and — against an allowlist it holds itself — the policy
digest stamped into that component's certificate. What each check proves, and
when, is [armtls.md](armtls.md) and [verify.md](verify.md).

## Trust boundary and adversary

The trust boundary is the TEE. Inside it: the measured node software, the pods
it admits, and CDS, the Certificate Distribution Service — one pod that holds
the cluster's policy and signs every workload certificate.

Outside it: the host and its hypervisor, the Kubernetes control plane, the pod
network, and the public internet. All of those are the adversary, and the host
can run genuine TEEs of its own. That is why a verifier states the measurements
it will accept — its pins — rather than trusting that a TEE answered at all.

Trusted without proof: the CPU vendor, and whatever measured code you choose to
pin.

Out of scope: availability, side channels, and physical attacks on the hardware.

A node is one trust domain. Its pods share its TEE, so whoever breaks the node
holds every pod on it. Tenants that do not trust each other belong on separate
nodes.

## Node-as-CVM

The node is the confidential VM, and its pods are ordinary Linux processes
inside it. There is no per-pod VM. So a pod is protected from the host, and the
enforcement that decides what may run sits in the node CVM rather than in the
API server — below the layer the adversary controls.

## What runs where

- **CDS** is a single pod in the release namespace (`c8s-system` by default). It
  verifies evidence, signs each pod's leaf — the short-lived certificate issued
  for one pod run — with a mesh CA it generates in its own memory, and holds the
  served allowlist, the secret store, and the route manifest. CDS writes nothing
  to Kubernetes: operator-added entries, secrets, the route manifest, and the
  mesh CA live only in its memory, so a restart re-bootstraps from its CDS
  seed — [operator.md](operator.md).
- The **admission plugin** `nri-image-policy` is a host process containerd
  launches, not a pod. It admits or denies every container and installs each
  member pod's packet rules —
  [allowlist-and-capabilities.md](allowlist-and-capabilities.md).
- The **admission inventory** is the same process, answering pods on a
  node-local Unix socket and CDS's sandbox callback on a privileged port. It
  records every container a pod has run, signs tokens naming the sandbox a
  caller is in, and answers that callback —
  [armtls.md](armtls.md#sandbox-identity).
- **`attestation-api`** produces and checks this node's hardware evidence over a
  node-local socket.
- On a measured node, **`c8s-runc`** replaces the low-level runtime: it
  enforces the privilege floor and refuses exec into a running container —
  [node-exec-mode.md](node-exec-mode.md).
- The **`c8s operator`** pod runs the controllers and the two admission
  webhooks, `pod-injector` and `pod-validator`, that give a pod its C8s shape.
  The **router** pod in `c8s-router` is the front door for application traffic —
  [operator.md](operator.md).
- Every member pod carries its own mesh endpoint (`c8s-mesh`) and get-cert
  (`c8s-cert`), plus `c8s-secret` or `c8s-volume` when it asks for a secret or a
  volume.
- **volumed** is the node agent that opens an entitled pod's encrypted volumes —
  [volumes.md](volumes.md).
- On the measured node image, **kube-state-metrics** runs in `kube-system`
  outside the mesh, and the measured mesh policy lets every member pod reach its
  Service uncaptured — [armtls.md](armtls.md#cluster-metrics).

```text
  outside the TEE
    operator machine: c8s install, allowlist, secrets, routes, keys
    relying party:    c8s verify, or a browser client using the
                      router's attestation endpoints
  --------------------------- trust boundary ---------------------------
   node CVM (AMD SEV-SNP or Intel TDX), measured at launch
   +-----------------------------------------------------------------+
   | containerd + nri-image-policy ---> admission inventory          |
   | attestation-api (node-local)       [volumed: encrypted volumes] |
   | c8s-runc (privilege floor; measured node image only)            |
   |                                                                 |
   | c8s-system  c8s operator + webhooks | CDS                       |
   | c8s-router  router: public TLS, manifest routing                |
   | your pod    app + c8s-mesh + c8s-cert [+ c8s-secret, c8s-volume]|
   +-----------------------------------------------------------------+
  ---------------------------------------------------------------------
   host, hypervisor, and Kubernetes control plane: the adversary
```

## CVM modes and hardware platforms

`c8s install` requires two orthogonal choices. `--cvm-mode` is the deployment
shape; all three are node-as-CVM, and this table is the one place they differ.

| | `bare-metal` | `gke` | `aks` |
|---|---|---|---|
| The node is | the C8s measured node image | a GKE confidential VM | an AKS confidential VM |
| Node services | baked into the image (a chart DaemonSet writes the release's CDS pins into the baked config) | deployed by the chart | deployed by the chart |
| Base allowlist | a baked file, measured with the image | chart values | chart values |
| Privilege floor | `c8s-runc`, measured | none | none |
| Exec, attach, port-forward | denied by a baked policy | the ordinary path | the ordinary path |
| Evidence | the CPU TEE directly | the CPU TEE directly | the Azure vTPM (`az-snp`, `az-tdx`) |
| volumed | `volumed.service` | chart DaemonSet, `--volumes` | chart DaemonSet, `--volumes` |
| Launch configuration | signed `launch.yaml` | none | none |

Node services are `attestation-api` and the admission plugin; the base
allowlist is the set of entries each plugin holds itself
([allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap)); the
privilege floor and the exec denial are
[node-exec-mode.md](node-exec-mode.md); the launch configuration fixes a
measured node's role, identity, and image pins
([operator.md](operator.md#authenticated-launch-configuration), with every
field in [launch-configuration.md](launch-configuration.md)).

Only the measured node image carries the baked policy that refuses host
privilege. On the chart lanes the plugin's own configuration comes from chart
values, which the cluster administrator can also write, so what holds host
namespaces off there is the chart's `<release>-deny-host-namespaces` cluster
policy —
[allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege).

`--hardware-platform` is the CPU TEE: `sev-snp` or `tdx`. Under `aks` it selects
which vTPM report shape to ask for rather than a guest device. On TDX, pinning
the launch measurement alone covers the firmware; pinning the guest needs the
image manifest published with the node image — [verify.md](verify.md),
[measurements.md](measurements.md).

How the node image is built is `../node-guest-image/README.md`.

## The life of a confidential pod

1. The operator publishes a workload entry: the image digests the pod may run,
   with their command, arguments, mounts, and environment, plus any secret
   grants and egress entries — [allowlist-entries.md](allowlist-entries.md).
2. The pod is created. `pod-injector` injects the mesh endpoint, get-cert, and a
   wait gate, and `pod-validator` rejects any pod in scope whose final shape is
   not that one — [operator.md](operator.md).
3. Before any of the pod's containers starts, the node installs its packet
   rules. It then checks every container at create, validation, and start
   against the base and served allowlists, and under the default fail-closed
   enforcement it also stops a running container that a newly applied allowlist
   no longer admits. On the measured node image it refuses a container that
   holds host privilege outside the node's own components —
   [allowlist-and-capabilities.md](allowlist-and-capabilities.md).
4. `c8s-cert` generates a key in pod memory and asks CDS for a challenge, a
   single-use nonce, authenticating CDS against its pins. It then redeems a
   token from the admission inventory, which binds that key and challenge to the
   pod's sandbox —
   [getcert-workload-binding.md](getcert-workload-binding.md).
5. CDS checks the evidence, its measurement policy, the token, and that every
   image the inventory reports is allowlisted. It then signs a short-lived leaf
   naming this pod run and, when exactly one entry matches, that entry —
   [armtls.md](armtls.md#matched-workload).
6. The mesh endpoint adopts the leaf and carries the pod's captured TCP over
   armTLS. Without credentials or rules it carries no application traffic; its
   health port still answers the node's probes —
   [armtls.md](armtls.md#the-mesh-endpoint-profile).
7. `c8s-secret` or `c8s-volume` redeems a fresh token and asks CDS, which
   re-reads the pod's containers and requires a grant that still matches. Files
   therefore appear only after the main containers have started —
   [secrets.md](secrets.md), [volumes.md](volumes.md).
8. Public requests reach the router, which routes only by the operator-signed
   route manifest. A route names either a workload backend, whose leaf must
   carry that workload name under the router's own allowlist digest, or an
   address backend with its own server name and CA. A client can attest the
   router, and its session then routes only by what that handshake bound —
   [routes-evidence.md](routes-evidence.md).

## Design intentions

The reasoning behind the six promises is
[guarantees.md](guarantees.md#design-intentions).
