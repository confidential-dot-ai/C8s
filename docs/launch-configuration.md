# Launch configuration

The fields of the signed `launch.yaml` that a measured node boots from, the
detached signature beside it, and how both bind into the node's evidence. One
image serves both node roles; this document is what selects and constrains a
boot. Why a cluster is run this way is
[operator.md](operator.md#authenticated-launch-configuration).

## The disk

Every boot of a measured node image reads a disk labelled `opkeydata` — an ISO,
or a KubeVirt Secret volume with `volumeLabel: opkeydata` — holding three files
at its root. C8s reads `launch.yaml` and `launch.yaml.sig`; the measured initrd
reads `pubkey` before `switch_root`:

- **`pubkey`**: this cluster and role's launch key, PEM, as
  `openssl ec -pubout` writes it. The bytes are hashed byte for byte, so
  re-encoding them breaks the binding.
- **`launch.yaml`**: the document below.
- **`launch.yaml.sig`**: the detached signature over that document's exact
  bytes.

`c8s node launch-config new` writes all three per node, plus the cluster's
private keys, client policies and the launch file and pin of the CDS VM its
nodes trust; `c8s node launch-config add-agent` adds a node later, and
`c8s keys sign-launch` re-signs a hand-edited document.

## Document rules

- Exactly one YAML document, 1 byte to 1 MiB, with no unknown fields.
- No anchors, aliases, or merge keys.
- No duplicate keys. Keys are strings, except the `image.rtmrs` indices `1`
  and `2`.
- Nesting at most 32 levels.

## Fields

Names below are YAML paths: `image.measurement` is `measurement` under
`image`, and `image.rtmrs` is a map keyed by register index. The Required
column names the role that must carry the field.

| Field | Required | Holds |
|---|---|---|
| `schemaVersion` | yes | `c8s-launch/v2`. |
| `clusterID` | yes | The cluster's name, an RFC1123 label. |
| `role` | yes | `server` or `agent`. |
| `image.platform` | yes | `tdx` or `snp`, and it must be the platform this boot is on. |
| `image.measurement` | yes | The launch digest this image must report, 96 lowercase hex ([measurements.md](measurements.md)). |
| `image.rtmrs` | TDX | Exactly RTMR[1] and RTMR[2], 96 lowercase hex each. An SNP document carries none. |
| `node.name` | yes | This node's Kubernetes name, an RFC1123 label. |
| `node.ip` | no | This node's IPv4 address. |
| `node.externalIP` | no | A unicast IPv4 address to publish as the node's external address. |
| `rke2.serverToken` | server | The control-plane join token of RKE2, the Kubernetes distribution the node image boots: 64 lowercase hex, different from `agentToken`. An agent document must not carry it. |
| `rke2.agentToken` | yes | The agent join token, 64 lowercase hex. |
| `rke2.nodePassword` | no | This node's RKE2 node password, 64 lowercase hex, different from both tokens. Per node, so one node's document opens no other node's name. |
| `server.address` | agent | The server's unicast IPv4 address. A server may omit it; the boot-time stage step below then resolves `node.ip` or the primary interface. |
| `server.operatorPublicKey` | yes | The server launch key, PEM. A server boot is authorized only for these exact bytes. |
| `agentOperatorPublicKeys` | agent | The agent launch keys this cluster trusts, PEM, at most 128, all distinct and none equal to the server's. A server document may list them; an agent document must. |
| `tlsSAN` | no | DNS name for the front-door certificate. Default `c8s.local`. |
| `cds.address` | yes | The CDS endpoint, `<host>:<port>`, the host a DNS name or an IPv4 address. A name is resolved by the clients that dial it, through the resolvers the node image is built with, so it must resolve there. |
| `cds.measurements` | yes | One measurements JSON document ([measurements.md](measurements.md)), pinning the CDS image to the launch file that VM boots with. Every entry must bind that file. |
| `workloads` | refused | A cluster's workload entries belong in the CDS configuration: pass them to `c8s node launch-config new --tenant-workloads`. |
| `router.hostnames` | no | Server only: up to 100 lowercase DNS names the router serves. A non-empty list puts the baked front door in ACME mode at boot. |
| `router.acmeEmail` | no | Bare email address for the ACME account. Requires `hostnames`. |
| `router.acmeDirectoryURL` | no | An `https` ACME directory URL, for example a staging directory. Requires `hostnames`. |
| `router.maxRequestBodyBytes` | no | Largest application request body the public listener accepts. Default 1048576. |
| `registryMirrors` | no | Up to 8 entries mapping `host[:port]` to `http://<IPV4>[:port]`, the endpoint containerd pulls that registry through. Image references stay digest-pinned. |

The node's own measurement pins follow from the document rather than being
written in it: they are derived from `image` plus every launch key the
document names. The CDS — the Certificate Distribution Service, which holds
policy and signs workload certificates — runs on a confidential VM of its own,
on the TEE family its pin names, which need not be the one these nodes boot on.

## The signature

`launch.yaml.sig` holds one line: base64 of an ASN.1 DER ECDSA signature over
SHA-256 of the document's exact bytes. It is verified under the node's measured
launch key alone — not under the keys inside the document — so editing a byte
of the document means re-signing it (`c8s keys sign-launch --force`) with the
key that node's launch bound.

## How it binds into evidence

The launch key is committed to the hardware report at launch, and the document
is then checked against that report. `‖` below is byte concatenation:

| | TDX | SEV-SNP |
|---|---|---|
| Who commits the key | The measured initrd, before `switch_root` | The launcher, at launch |
| Where it lands | The RTMR[3] seed, `SHA-384(0x00 * 48 ‖ SHA-384(launch key))` | `HOST_DATA`, `SHA-256(launch key)` |

On SEV-SNP the host sets that field, so a verifier has to pin a launch digest
of an image known to read it and to refuse a key that does not match. On a
managed-cloud CVM — the `az-` and `gcp-` platforms — the cloud stack owns the
field instead, which is why this flow is for a measured node image on
`bare-metal` ([measurements.md](measurements.md#where-the-evidence-comes-from)).

`c8s launch-config stage` runs at boot, in this order:

1. Get one fresh nonce-bound self-report from the node-local attestation-api,
   the service that produces and checks this node's hardware evidence, and
   confirm that the launch key the initrd staged off the disk is the key
   this launch committed. The file is not measured, only its digest is, so
   this is what catches a key swapped after boot.
2. Verify the signature over the document's raw bytes, before parsing them.
3. Parse the document under the rules above.
4. Confirm `image.platform` is the platform this image booted as, then compare
   `image.measurement` and every `image.rtmrs` entry against that report.
5. Authorize the key for the role: a `server` boot requires the launch key to
   be `server.operatorPublicKey` byte for byte; an `agent` boot requires it to
   appear in `agentOperatorPublicKeys` and to differ from the server's.
6. Write the staged artifacts, root-only, under `/run/confos/launch`: the
   document as `config.json`, the launch key and this cluster's node peer
   pins. The node services render the CDS pins from the staged document, for
   the clients that verify it.
7. Stage what RKE2 reads: the join tokens, the node password, the role
   fragment under `/etc/rancher/rke2/config.yaml.d/`, and `registries.yaml`
   when the document sets mirrors. The role marker is written last, so a step
   that fails starts no role.

Missing, unsigned, or inconsistent input leaves RKE2 and the role's services
down. A role change, a new image, or any other edit means relaunching with
newly signed bytes.

A failed verification (for example the boot's first quote, or SEV-SNP
collateral that cannot be fetched) is retried with growing waits. If every
attempt fails, the node logs which step failed and powers off instead of
staying up with no services; KubeVirt (runStrategy Always or RerunOnFailure)
then relaunches the VM.
