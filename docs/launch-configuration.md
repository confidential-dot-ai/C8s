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
`kubernetes`. The document pins no measurement of its own: the `node-images`
decree that admits it names the worker image it is bound to
([below](#admitting-a-worker-document)).

| Field | Required | Holds |
|---|---|---|
| `schemaVersion` | yes | `c8s-worker/v1`. |
| `cds.address` | yes | The CDS endpoint, `<host>:<port>`, the host a DNS name or an IPv4 address. A name is resolved by the clients that dial it, through the resolvers the worker image is built with, so it must resolve there. |
| `cds.measurements` | yes | One measurements JSON document ([measurements.md](measurements.md)), pinning the CDS image to the launch file that VM boots with. Every entry must bind that file. |
| `cds.pinFloor` | no | The lowest cluster version a worker takes a CDS pin decree at. |
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
document, which the customer signs into a `node-images` decree
([cds-ha.md](cds-ha.md#the-node-images-the-cluster-certifies)). Given the
document, the decree adds that entry itself:

```sh
c8s cds ha decree node-images \
    --config cds-config.yaml \
    --operator-key operator.key \
    --base-version 12 \
    --nodes nodes-v12.json \
    --worker-document worker.yaml \
    --worker-image worker-image.json \
    --to cds-1.example.org \
    --cds-pin cds-pin.json
```

| Flag | Holds |
|---|---|
| `--worker-document` | The worker document, read once. |
| `--worker-image` | The worker image's measurements, as `c8s measurements derive` writes them: the TEE family of `--nodes`, and no launch binding. |
| `--nodes` | The node images the cluster certifies now: the set of the `node-images` decree in force. |
| `--cds-pin` | Your CDS pin, as `c8s cds config new` wrote it. The document's `cds.measurements` must pin the same TEE family and the same images, each bound to the same configuration. |

The decree certifies, under `schema_version` `"2"`, every entry of `--nodes`,
unchanged, followed by each `--worker-image` entry with `launch_file_digest`
set to the document's digest (SHA-256 on SEV-SNP, SHA-384 on TDX) and the
digest's first 12 hex digits appended to its name. That set, the decree's
`node_pins`, is the `--nodes` of the next `node-images` decree: `--out` writes
it inside the signed decree, and `c8s cds ha decrees --json` prints it.

Nothing is signed if a check fails: the document breaks the rules above or
pins another CDS, `--nodes` already admits the worker image with this
document, or the set is one a `node-images` decree refuses. Otherwise the
command prints, to standard error, the API server, the CA's subject and
SHA-256 fingerprint, the pod and Service ranges, the cluster DNS address, the
CDS address and pin floor, the router's TLS SAN and hostnames, and the name of
every node image it would certify. It signs only once you confirm them on
standard input: any answer but `y` or `yes` (in any case), or none, signs
nothing. Every worker launched with this document joins with these facts.
Workers launched with the same document need no new decree; a changed
document, such as one naming a new CA, is admitted beside the old one by a
decree on the set in force.

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
beside the document, outside the measurement. The node name is `n-` and 16
hex digits derived from the kernel's boot ID, so every boot registers a new
node.

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
| `/etc/nri/conf.d/image-policy.yaml` | The image's NRI floor, pulling from `cds.address` with `cds.pinFloor` as its pin floor, the credential role reaching the CDS port, `podCIDR` and `serviceCIDR` as the mesh policy's cluster ranges, `clusterDNS` as its resolver, and its static-pod pins filled with this worker's values. Stage loads it as the NRI plugin will, and refuses one the plugin would refuse or that does not set `worker: true`. |
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
pulled by digest at boot. They reach the API server with the kubelet's
credentials, and Cilium reads its configuration from the image
(`/usr/lib/c8s/worker/cilium/config.yaml`), not from the API. c8s's operator
and the Cilium operator run beside the control plane, outside the workers:
the operator's own pod would wait on a worker for the mesh endpoint its webhook
injects, and NodeRestriction keeps node credentials from the Cilium operator's
leader lease.

`c8s worker control-plane render --document worker.yaml --output-dir DIR`,
given the worker image build's `--hardware-platform`, `--kube-version` and
image flags, writes `DIR/cluster.yaml`, the objects the cluster holds for its
workers:

- the chart's, as the worker image's build renders them, with the webhooks at
  `https://<--webhook-host>:9443` and the operator's grants bound to the user
  `c8s-operator`; the router, pulled rather than baked, may run on any worker;
- not the operator's own Deployment, Service, account and NetworkPolicy, the
  allowlist seed, or the router's nginx ConfigMap, which the image bakes; the
  host-namespace admission policies are off, and each worker's NRI plugin
  admits host privilege;
- the grants the static pods need, bound to every node;
- the Cilium operator's grants, bound to the user `c8s-cilium-operator`;
- the `kube-dns` Service, at `kubernetes.clusterDNS`, which sends each lookup
  to its own node's CoreDNS.

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

The image flags must be the worker image build's, so the router it renders is
the launch the image's floor pins. Each API server reaches the operator at
`--webhook-host`, so a control plane with several replicas runs an operator
beside each. The control plane the workers join must also accept the bootstrap
token and issue the kubelet's client certificate, give each node a pod range
from `kubernetes.podCIDR` (Cilium's `ipam` is `kubernetes`), and deploy no CNI,
kube-proxy or cluster DNS of its own: a worker refuses them. A worker needs no
cloud controller manager: its kubelet joins untainted and reports the staged
`--node-ip` as the node's InternalIP. Each boot registers the worker as a new
node.

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
