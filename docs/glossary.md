Canonical names for the concepts in these docs, as C8s spells them in commands, flags,
annotations, certificates, and logs.

| Term | Meaning | Explained in |
|---|---|---|
| admission inventory | Node service that records a pod's containers and signs tokens naming its sandbox. | [armtls.md](armtls.md#sandbox-identity) |
| admission plugin (`nri-image-policy`) | The node's container-runtime plugin; admits or denies every container before it starts. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md) |
| allowlist | The operator policy of workload entries CDS serves and every node enforces. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md) |
| allowlist digest | SHA-256 of the canonical bytes of the allowlist snapshot that named a leaf's matched workload. | [armtls.md](armtls.md#matched-workload) |
| armTLS | Mutual TLS whose certificates carry TEE evidence, so peers verify measurements instead of names. | [armtls.md](armtls.md) |
| `attestation-api` | The node-local service that produces and verifies this node's hardware evidence. | [overview.md](overview.md) |
| base allowlist | Entries the node plugin holds itself — measured in the image or chart-rendered — admitted without CDS. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap) |
| `c8s operator` | The controller-manager and admission webhooks; an ordinary cluster pod, not a person. | [operator.md](operator.md) |
| `c8s verify` | Client command that checks a component's evidence against the pins you supply. | [verify.md](verify.md) |
| `c8s-secret` | Injected sidecar that fetches a pod's granted secrets and writes them to files. | [secrets.md](secrets.md) |
| `c8s-volume` | Injected sidecar that fetches a pod's volume keys and has the node open them. | [volumes.md](volumes.md) |
| CDS | Certificate Distribution Service: holds policy and secrets, signs workload certificates, verifies evidence. | [overview.md](overview.md) |
| CDS seed | The allowlist document CDS seeds its store from at start (`cds --allowlist-seed`). | [allowlist-and-capabilities.md](allowlist-and-capabilities.md#bootstrap) |
| challenge | A single-use nonce CDS issues; the sandbox token and the evidence both bind to it. | [armtls.md](armtls.md#sandbox-identity) |
| `confidential.ai/cw` | Pod annotation naming the workload a pod belongs to; it requests a SAN for the leaf. | [operator.md](operator.md) |
| CVM | Confidential VM: CPU-encrypted memory whose launch state the hardware measures. | [overview.md](overview.md) |
| CVM mode (`--cvm-mode`) | The deployment shape: `bare-metal`, `gke`, or `aks`. All three are node-as-CVM. | [overview.md](overview.md) |
| egress | A workload entry's egress entries: the CIDR and port pairs its pods may dial outside the mesh. | [allowlist-entries.md](allowlist-entries.md) |
| encrypted volume | Host-stored disk opened inside the CVM; immutable by default, writable with `--mutable`. | [volumes.md](volumes.md) |
| evidence | A hardware-signed attestation report plus the material a verifier needs to check it. | [overview.md](overview.md) |
| get-cert | Sidecar (`c8s-cert`) that obtains and renews a pod's leaf, key, and CA set. | [armtls.md](armtls.md) |
| grant | The secret paths a workload entry may read or write. | [allowlist-entries.md](allowlist-entries.md) |
| hardware platform (`--hardware-platform`) | The CPU TEE: `sev-snp` or `tdx`. Chosen independently of the CVM mode. | [overview.md](overview.md) |
| host privilege | Host namespaces, binds, devices, hooks, or sysctls; only measured node components may hold them. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege) |
| key blob | A volume's key, held in CDS and in the escrow file you keep. | [volumes.md](volumes.md) |
| launch configuration | The signed `c8s-launch/v1` `launch.yaml` fixing a node's role, identity, and image measurements. | [operator.md](operator.md#authenticated-launch-configuration) |
| launch key | Operator keypair a node boots with; its public half binds into the node's evidence. | [operator.md](operator.md#authenticated-launch-configuration) |
| launch measurement | Digest of what the CVM booted: the SEV-SNP measurement or the TDX MRTD. | [overview.md](overview.md) |
| leaf | The short-lived end-entity certificate CDS signs for one pod run. | [armtls.md](armtls.md) |
| matched workload | The entry name CDS stamps into a leaf when exactly one entry matches the pod. | [armtls.md](armtls.md#matched-workload) |
| measurement pin | A measurement or register value a verifier requires (`c8s install --rtmrs`, `c8s verify --rtmr`). | [armtls.md](armtls.md) |
| member pod | A pod the node treats as inside the mesh: injected, gated, and packet-captured. | [armtls.md](armtls.md) |
| mesh endpoint | The `c8s-mesh` sidecar; carries one pod's captured TCP over armTLS. | [armtls.md](armtls.md#the-mesh-endpoint-profile) |
| mount class | A mount rule's `kind`: `platform`, `emptyDir`, `data`, `host`, or `nodeRootFile`. | [allowlist-entries.md](allowlist-entries.md) |
| node image | The measured guest image a node boots: firmware, kernel, and dm-verity root. | [overview.md](overview.md) |
| node-as-CVM | The node is the confidential VM; its pods are processes inside it. | [overview.md](overview.md) |
| operator key | The operator's EC keypair authorizing policy writes; CDS pins its public half. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md) |
| operator write token | The write token of one policy write: an operator signature over that method, path, and body. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md) |
| platform role | An identity a measured base grants one C8s node-side invocation, such as the credentials role. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md#host-privilege) |
| `pod-injector`, `pod-validator` | The mutating and validating admission webhooks that give a pod its C8s shape. | [operator.md](operator.md) |
| policy history | The allowlist policies a TDX node extends into RTMR[3] for verifiers to replay. | [allowlist-and-capabilities.md](allowlist-and-capabilities.md#measured-policy-history) |
| privilege floor | The measured limits `c8s-runc` enforces on every container of a member pod. | [node-exec-mode.md](node-exec-mode.md) |
| public TLS mode | How the router gets its public certificate: `cds`, `acme`, or `webpki`. | [operator.md](operator.md) |
| route digest | The SHA-256 of the route manifest bytes, bound into the router's attestation. | [routes-evidence.md](routes-evidence.md) |
| route manifest | Operator-signed hosts, paths, and backends. The router serves nothing else. | [operator.md](operator.md#route-manifest) |
| router | The front door: terminates public TLS and routes application traffic by the signed manifest. | [operator.md](operator.md) |
| sandbox ID | Identifier of one pod run, carried in that pod's certificate. | [armtls.md](armtls.md#sandbox-identity) |
| sandbox token | Inventory-signed binding of a pod's key and CDS challenge to its sandbox. | [armtls.md](armtls.md#sandbox-identity) |
| secret store | CDS's in-memory store of values, each addressed by a store path. | [secrets.md](secrets.md) |
| SEV-SNP | AMD Secure Encrypted Virtualization with Secure Nested Paging, one of the two platforms. | [overview.md](overview.md) |
| TDX | Intel Trust Domain Extensions, the other platform; measures firmware (MRTD) and registers (RTMR). | [overview.md](overview.md) |
| TEE | Trusted Execution Environment: the hardware boundary C8s puts the workload inside. | [overview.md](overview.md) |
| volumed | Node agent that opens an entitled pod's encrypted volumes and mounts them in. | [volumes.md](volumes.md) |
| workload entry | One allowlist entry: a named container set with argv, mount, and environment policy. | [allowlist-entries.md](allowlist-entries.md) |
