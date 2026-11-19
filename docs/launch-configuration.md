# Launch configuration

The fields of the launch file a measured worker boots from, and the rules its
bytes must meet. How the launch binds the document into the worker's evidence
is [below](#launch-binding).

A worker runs a cluster's workloads while the cluster's Kubernetes control
plane runs outside every TEE. Its launch file, `worker.yaml`, carries no
signature and no launch key: the document's whole bytes are the worker's init
data, and the launch commits their digest. `c8s worker new` drafts one from its
flags and the CDS pin and CA files they name, checks it under the rules below,
and writes it to `--out`, or to stdout without one.

## Document rules

- Exactly one YAML document, 1 byte to 1 MiB, with no unknown fields.
- No anchors, aliases, or merge keys.
- No duplicate keys, and every key is a string.
- Nesting at most 32 levels.

## Fields

Names below are YAML paths: `kubernetes.apiServer` is `apiServer` under
`kubernetes`. The document pins no measurement of its own: the node image entry
that admits it names the worker image it is bound to
([below](#admitting-a-worker-document)).

| Field | Required | Holds |
|---|---|---|
| `schemaVersion` | yes | `c8s-worker/v1`. |
| `cds.address` | yes | The CDS endpoint, `<host>:<port>`, the host a DNS name or an IPv4 address. A name is resolved by the clients that dial it, through the resolvers the worker image is built with, so it must resolve there. |
| `cds.measurements` | yes | One measurements JSON document ([measurements.md](measurements.md)), pinning the CDS image to the launch file that VM boots with. Every entry must bind that file. |
| `cds.chain` | no | `<seq>:<hash>` of one entry of the CDS replica set's chain ([cds-ha.md](cds-ha.md#what-nodes-pin)): the worker's CDS pins then follow the builds the chain accepts, and every CDS answer must name this entry. |
| `tlsSAN` | yes | The DNS name of the router's front-door certificate. The CDS configuration `cds.measurements` binds must let a leaf carry it. |
| `router.hostnames` | no | Up to 100 lowercase DNS names the router serves. A non-empty list puts the baked front door in ACME mode at boot. |
| `router.acmeEmail` | no | Bare email address for the ACME account. Requires `hostnames`. |
| `router.acmeDirectoryURL` | no | An `https` ACME directory URL, for example a staging directory. Requires `hostnames`. |
| `router.maxRequestBodyBytes` | no | Largest application request body the public listener accepts. Default 1048576. |
| `kubernetes.apiServer` | yes | The API server's `<host>:<port>`, the host a lowercase DNS name or a unicast IPv4 address (private ones included), the port 1..65535 without leading zeros. No scheme, path, user or brackets. |
| `kubernetes.caCertificate` | yes | One PEM `CERTIFICATE` block without headers, holding a CA certificate, with nothing but whitespace before or after it. |
| `kubernetes.podCIDR` | yes | The pod range: IPv4, written as its network address and prefix length. |
| `kubernetes.serviceCIDR` | yes | The Service range, under the same rules, and `/30` or wider. |
| `kubernetes.clusterDNS` | yes | The cluster DNS Service's IPv4 address: inside `serviceCIDR`, and neither its network nor its broadcast address. |

Neither range may reach into `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` or
`224.0.0.0/4`, overlap the other, or overlap a node subnet (`nodeCIDRs`) of
the CDS configuration that `cds.measurements` binds.

## Admitting a worker document

The CDS certifies a worker only under a node image entry bound to its exact
document: the worker image's measurements with `launch_file_digest` set to the
document's digest (SHA-256 on SEV-SNP, SHA-384 on TDX), under
`schema_version` `"2"`, among the node images the CDS configuration names.

A cluster whose nodes are all workers has no set in force before its first
worker: its launch file names no nodes (`c8s cds config new` without
`--node-pins`). Its Genesis admits the first document instead.
`c8s cds ha decree genesis` takes `--worker-document` and `--worker-image`
as above, checks the document against its `--cds-pin`, and starts the cluster
certifying that worker image alone. The document needs nothing from a running
cluster, so it can be written before Genesis.

## Launch binding

The launch commits the document's digest, and staging then checks the document
against the report. `‖` below is byte concatenation:

| | TDX | SEV-SNP |
|---|---|---|
| Who commits the digest | The measured initrd, before `switch_root` | The launcher, at launch |
| Where it lands | The RTMR[3] seed, `SHA-384(0x00 * 48 ‖ SHA-384(document))` | `HOST_DATA`, `SHA-256(document)` |

On SEV-SNP the host sets that field, so a verifier has to pin a launch digest
of an image known to read it and to refuse a document that does not match. On
a managed-cloud CVM — the `az-` and `gcp-` platforms — the cloud stack owns the
field instead, which is why this flow is for a measured node image on
`bare-metal`
([measurements.md](measurements.md#where-the-evidence-comes-from)).

The boot-time check order is [below](#staging-a-worker-document). A document
the launch did not bind leaves the worker with no staged output, and
`worker-stage.service` powers the VM off after its last retry.

## Staging a worker document

At boot, `c8s worker stage` reads the launch file the
initrd staged at `/run/confai/operator-pubkey` (`--document`) once. It
refuses, touching nothing, on an image without `/usr/lib/c8s/worker-image`.
It confirms through the node-local attestation API that a fresh, verified
self-report binds the document, and only then parses it under the rules
above. On TDX, RTMR[3] must hold the document's SHA-384 extended into the
zeroed register, followed by a prefix of the policies in the node's
measured-policy journal (`/run/nri-image-policy/measured-policies`), so a
rerun after the NRI plugin measured a policy still passes. On SEV-SNP,
`HOST_DATA` must be the document's SHA-256.

It then reads the Kubernetes bootstrap token from `--bootstrap-token-file`:
a regular file holding `<6 lowercase letters or digits>.<16 lowercase
letters or digits>` and at most one newline. The launch disk carries it
beside the document, outside the measurement. The node name is `n-` followed
by the node's primary IPv4 octets separated by hyphens, for example
`n-10-0-0-7`. A reboot at the same address rejoins the same Node.

Every template under `/usr/lib/c8s/worker/static-pods` is rendered with this
worker's `${NODE_NAME}` and `${POD_CIDR}`. Each may appear only as a whole
`<flag>=<placeholder>` element of a container's command or args, the rule
that fills the NRI floor's pins; a template naming either anywhere else is
refused. It writes:

| Output | Holds |
|---|---|
| `/run/c8s-node/cds.json` | The `cds.measurements` pin. |
| `/run/c8s-node/router/*` | The router settings `router.*` gives. |
| `/run/c8s-node/operator-pubkey` | The operator keys of the CDS configuration `cds.measurements` binds, which the router verifies route manifests under. |
| `/run/c8s-node/tls-san` | `tlsSAN`. |
| `/etc/nri/conf.d/image-policy.yaml` | The image's NRI floor, pulling from `cds.address`, the credential role reaching the CDS port, `podCIDR` and `serviceCIDR` as the mesh policy's cluster ranges, `clusterDNS` as its resolver, and its static-pod pins filled with this worker's values. Stage loads it as the NRI plugin will, and refuses one the plugin would refuse or that does not set `worker: true`. |
| `/run/nri-image-policy/node-ip` | The host's primary IPv4, the address the NRI inventory advertises. |
| `/run/kubernetes/bootstrap-kubelet.conf` | Mode 0600: `https://` and `kubernetes.apiServer`, verified against `kubernetes.caCertificate` alone, with the bootstrap token. |
| `/run/kubernetes/kubelet-config.yaml` | The kubelet's configuration: `kubernetes.clusterDNS` for the cluster domain `cluster.local`, the static pods' directory, no anonymous access or read-only port, and debugging, log, profiling and debug-flag handlers off, so the kubelet serves no exec, attach, port-forward, logs or checkpoint. What it still serves (`/pods`, `/stats`, `/metrics`) takes bearer tokens the API server reviews and authorizes. |
| `/run/kubernetes/manifests/*` | The rendered static pods. |
| `/run/kubernetes/kubelet.env` | `NODE_NAME`, and `NODE_IP`, the address in `node-ip`. |

Every output is removed first, and again if a step fails, so a document the
launch did not bind, one that breaks the rules, or a bad token leaves none.
`/run/kubernetes` is removed whole. A rerun in the same boot with the same
document and token writes the same bytes; under a running kubelet it
restarts the static pods.

## A worker's control plane

The worker image's static pods are the Cilium agent, kube-proxy and CoreDNS,
and, on a worker with an NVIDIA GPU, the NVIDIA device plugin and
dcgm-exporter, pulled by digest at boot. Stage leaves out a template annotated
`confidential.ai/gpu-only: "true"` when no PCI function has NVIDIA's vendor ID.
The device plugin advertises the GPUs as `nvidia.com/gpu` and hands each
allocation to the container as `k8s.device-plugin.nvidia.com/gpu` CDI devices;
dcgm-exporter serves GPU metrics on port 9400 of its pod. Neither reaches the
API server. The other three reach it with the kubelet's credentials, and
Cilium reads its configuration from the image
(`/usr/lib/c8s/worker/cilium/config.yaml`), not from the API. c8s's operator
and the Cilium operator run beside the control plane, outside the workers:
the operator's own pod would wait on a worker for the mesh endpoint its webhook
injects, and NodeRestriction keeps node credentials from the Cilium operator's
leader lease.

`c8s worker control-plane render --document worker.yaml --output-dir DIR`,
given the worker image build's `--hardware-platform`, `--kube-version` and
image flags, writes `DIR/cluster.yaml`, the objects the cluster holds for its
workers:

- the c8s-worker chart's CRD, namespaces, router and admission webhooks, with
  the webhooks at `https://<--webhook-host>:9443` and the operator's grants
  bound to the user `c8s-operator`; the router, pulled rather than baked, may
  run on any worker; each worker's NRI plugin admits host privilege;
- the grants the static pods need, bound to every node;
- the grants a kubelet's join rests on, which only kubeadm binds: requesting a
  client certificate with the bootstrap token, and automatic approval of that
  certificate and of each rotation of it, so no admin approves a worker by hand;
- the Cilium operator's grants, bound to the user `c8s-cilium-operator`;
- the `kube-dns` Service, at `kubernetes.clusterDNS`, which sends each lookup
  to its own node's CoreDNS;
- the `kube-system/dcgm-exporter` Service, port 9400, in front of every GPU
  worker's dcgm-exporter. Whoever reaches it reads each GPU's utilisation,
  memory and power.

`c8s worker control-plane credentials --kubeconfig admin.kubeconfig
--output-dir DIR` writes `DIR/c8s-operator.kubeconfig` and
`DIR/c8s-cilium-operator.kubeconfig`: each key is generated there, and the
cluster's `kubernetes.io/kube-apiserver-client` signer issues its certificate
through a CertificateSigningRequest the command approves.

Run the operator with the same get-cert and mesh images supplied to the worker
image build and control-plane render:

```sh
c8s operator \
  --kubeconfig DIR/c8s-operator.kubeconfig \
  --webhook-host '<WEBHOOK_HOST>' \
  --get-cert-image '<GET_CERT_IMAGE>' \
  --mesh-image '<MESH_IMAGE>'
```

Replace the placeholders with the webhook host and image references used for
the render. `--webhook-config-name` and `--workload-claims-host-dir` default
to what a worker control plane always needs: the name `c8s worker
control-plane render` emits, and the worker image's fixed inventory
directory, which also holds the attestation-api socket the injected
c8s-cert sidecar uses with no in-cluster service account to fall back to. An
external webhook host requires the injection images; missing either stops
the operator at startup.

Copy `/usr/bin/cilium-operator-generic` from `quay.io/cilium/operator-generic`
to the same path on each control-plane host, matching the worker static pod's
Cilium version. Run one supervised instance beside each external control-plane
replica, using the generated
kubeconfig; `DIR` is the credentials command's `--output-dir` above:

```sh
/usr/bin/cilium-operator-generic \
  --k8s-kubeconfig-path DIR/c8s-cilium-operator.kubeconfig \
  --k8s-namespace kube-system \
  --ipam kubernetes \
  --identity-allocation-mode crd \
  --enable-l7-proxy=false
```

Its leader lease lives in `kube-system`, where the rendered grants authorize
it. Kubernetes assigns the pod ranges, and the operator uses the worker's
CRD identity allocation and L7 policy settings.

The image flags must be the worker image build's, so the router it renders is
the launch the image's floor pins. Each API server reaches the operator at
`--webhook-host`, so a control plane with several replicas runs an operator
beside each. The control plane the workers join must also accept the bootstrap
token and run the client-certificate signer and approver, give each node a pod
range from `kubernetes.podCIDR` (Cilium's `ipam` is `kubernetes`), and deploy no
CNI, kube-proxy or cluster DNS of its own: a worker refuses them. A worker needs
no cloud controller manager: its kubelet joins untainted and reports the staged
`--node-ip` as the node's InternalIP. Keep each worker slot's IPv4 address
exclusive to one VM; stop or fence its previous VM before reusing the address.
The Node retains its labels, taints and pod range across boots, and pods may
remain assigned to it.

When upgrading workers that registered with boot-derived names, record their old
Node names before the upgrade. After stopping or fencing each old VM, delete its
exact old Node with `kubectl delete node <OLD_NODE_NAME>`. Do the same when a
worker is permanently removed or its address changes. Kubernetes and Cilium
clean up associated resources asynchronously; check their removal before relying
on the released pod range.

A k3s or RKE2 server prints its bootstrap token as `K10<hash>::<id>.<secret>`.
The worker's `--bootstrap-token-file` takes only `<id>.<secret>`: strip the
`K10<hash>::` prefix before writing the file.

### k3s and RKE2 control planes

A k3s server works as the control plane with `disable-agent: true` (no local
kubelet), `egress-selector-mode: disabled`, and `flannel-backend: none`,
`disable-kube-proxy: true` and `disable: [coredns, traefik, servicelb,
local-storage, metrics-server]`, since the worker image runs its own CNI,
kube-proxy and CoreDNS as static pods. Move the controller-manager,
cloud-controller-manager and scheduler ports (`kube-*-manager-arg:
[secure-port: ...]`) where the host already runs a Kubernetes of its own.

RKE2 needs the same settings, plus removing its bundled ingress-nginx; it is
less tested for this than k3s.

Every node credential, which a bootstrap token can mint, holds Cilium's agent
grants for the whole cluster, so Cilium identities and network policy separate
nothing a worker relies on: workloads authenticate each other over the attested
mesh.
