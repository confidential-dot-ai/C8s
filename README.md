# C8s

[![CI](https://github.com/confidential-dot-ai/c8s/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/confidential-dot-ai/c8s/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENCE)

**C8s is confidential Kubernetes.** It runs Kubernetes workloads inside
hardware-backed Trusted Execution Environments, so that the data they process
(model weights, prompts, responses, datasets, credentials) stays encrypted in
memory the entire time it is in the cluster, and that property is
cryptographically provable to a third party over the network.

Encryption at rest and in transit are solved problems. Encryption **in use**
is not: the moment a workload runs, its secrets sit in plaintext memory,
readable by whoever operates the machine underneath it. Confidential computing
closes that gap. Modern CPUs (AMD SEV-SNP, Intel TDX) can run a virtual
machine whose memory is encrypted with keys held by the hardware, measure
exactly what booted into it, and sign that measurement so a remote party can
verify it. The infrastructure operator and hypervisor cannot see inside the VM. The
measured node kernel and its Kubernetes runtime are inside the trust boundary.

C8s applies that model to Kubernetes end to end, following five principles at
every layer:

1. **Encrypt the runtime.** Workloads run in hardware-encrypted memory.
2. **Measure the code.** The hardware computes a launch digest over exactly
   what booted.
3. **Bind identity to measurement.** Certificates issue only after the
   measurement verifies.
4. **Verify before connecting.** Peers require attestation-rooted identity
   before any traffic flows.
5. **Secure the egress.** Pod-originated TCP to pod and Service
   destinations is intercepted and wrapped in armTLS; TCP to non-pod
   external destinations is neither redirected nor dropped (it leaves the
   node plaintext). Non-TCP and unmeshed inbound fail closed rather than
   flowing in the clear. The exceptions are cluster DNS (UDP/53 to the
   cluster DNS server, the sanctioned name-resolution path).

C8s is built by [Confidential AI](https://confidential.ai) as the substrate
for private AI: inference, agents, training, and fine-tuning where the
infrastructure operator never sees the data. The platform itself is
workload-agnostic: anything that runs on Kubernetes can run confidentially.

## Links

- [Confidential AI](https://confidential.ai), the company behind C8s
- [Documentation](https://confidential.ai/docs/c8s), the full user-facing docs
- [Whitepaper](https://confidential.ai/docs/whitepapers/c8s), the C8s architecture paper (also on [arXiv](https://arxiv.org/abs/2604.26974))
- [Your first confidential cluster](https://confidential.ai/docs/c8s/tutorials/first-confidential-cluster), an end-to-end tutorial from bare cloud account to verified confidential workload
- [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js), verify a C8s cluster from a browser
- [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs), the TEE evidence verification service C8s uses
- [armTLS](docs/armtls.md), how attested TLS works in C8s — the handshake step by step, the guarantees, and which certificate is used where

## Features

- **Hardware-attested workload identity.** The Certificate Distribution
  Service (CDS) verifies TEE attestation evidence (AMD SEV-SNP, Intel TDX) and
  signs workload certificates with a mesh CA whose key never leaves the TEE.
  No verified measurement, no certificate. Issued leaves carry the evidence
  CDS accepted and the pod's sandbox ID, so a relying party can ask *which*
  workload is behind a key, not just whether it is a genuine TEE.

- **armTLS mesh.** A transparent L4 proxy wraps traffic between workloads in
  attestation-rooted mutual TLS. Bootstrap peers verify embedded evidence;
  CDS-issued certificates use mesh-CA chain verification. Final-hop plaintext
  confinement depends on [local-route validation](cmd/armtls-mesh/DESIGN.md#local-cidr-discovery);
  its HostIP fallback trusts Kubernetes placement metadata.

- **Node-as-CVM.** Run the whole node as one confidential VM. Supported modes
  are `bare-metal`, `gke`, and `aks`. See [Architecture](#architecture).

- **Measured boot end to end.** Node images boot via IGVM with dm-verity.

- **Container image and command-line allowlisting.** Every container is
  enforced against a CDS-served allowlist of named workload entries, each
  pinning the image digests a workload runs and the command line each may run
  with, and the environment values it launches with. Enforced by an NRI plugin
  on the node inside the CVM.

- **Attestation-gated secrets.** CDS releases an application secret only once
  a pod's running containers resolve to a single allowlist entry carrying a
  grant for that path. An injected sidecar writes the values to a
  memory-backed volume every container mounts read-only. The sidecar redeems
  its sandbox token from the node's admission inventory.

- **Encrypted volumes.** Data too large to be a secret — model weights, in
  practice — encrypted at rest on host-visible storage (dm-crypt) and opened
  only inside the TEE. Immutable volumes verify every read (erofs, dm-verity);
  mutable volumes are writable ext4. The key travels as a secret
  through the release path above, so possession of the volume implies nothing
  without attestation. On node-as-CVM the `volumed` node agent ships
  disabled — `c8s install --volumes` deploys it.

- **Fail-closed admission.** A mutating webhook injects certificate sidecars
  and workload labels; admission policies protect label integrity and deny
  tenant host-namespace access. The bootstrap ordering fails closed, never open.

- **Confidential GPUs.** NVIDIA GPUs attached to confidential nodes on
  SEV-SNP and TDX hosts, with GPU CC mode. Before a node sets the GPU CC
  Ready state it attests every GPU through its baked attestation service
  (SPDM evidence verified via NRAS, nonce-bound to the CPU TEE evidence) and
  powers off on any failure. That verdict stays inside the node; it is not
  wired into the C8s certificate flow, see
  [Known gaps](#known-gaps-and-open-items).

- **Verifiable from a browser.** A challenge-response protocol and a
  post-quantum over-encrypted channel let end users verify the cluster with
  no special client, via [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js).

- **One-command install.** `c8s install --cvm-mode=<shape>` brings all of this
  to an existing cluster (vanilla Kubernetes or RKE2, including AKS
  confidential node pools, where both SEV-SNP and Intel TDX attest through the
  Azure vTPM).

## Architecture

The unit of trust and attestation is the confidential node.

### Node-as-CVM

The entire Kubernetes node is one confidential VM. Pods are ordinary
containers inside it. A verifier checks the node's launch digest; everything
on the node is inside that one boundary, including the kubelet. Every pod
shares that boundary, so **node-as-CVM is single-tenant**: it isolates the
node from the host, not workloads from each other. This is the simplest and
densest shape, and the only one available on managed services without nested
virtualization (for example Azure AKS).

```text
                             NODE-AS-CVM
              one launch digest covers the whole node

════════════ TEE boundary (SEV-SNP / TDX encrypted memory) ════════════

  ┌────────────── Kubernetes node = one confidential VM ──────────────┐
  │                                                                   │
  │   ┌─────────┐   ┌─────────┐   ┌─────────┐      ┌───────────────┐  │
  │   │  pod A  │   │  pod B  │   │  pod C  │  ... │ kubelet, CNI, │  │
  │   │ (runc)  │   │ (runc)  │   │ (runc)  │      │ containerd    │  │
  │   └─────────┘   └─────────┘   └─────────┘      └───────────────┘  │
  │                                                                   │
  │   measured boot: IGVM + UKI + dm-verity node image                │
  └───────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════

  HOST / HYPERVISOR (untrusted)
  the cloud or bare-metal operator sees only ciphertext
```

## Quickstart

Install C8s onto an existing cluster. The full walkthrough is
[docs/QUICKSTART.md](docs/QUICKSTART.md); the hosted version with
provisioning guides is at
[confidential.ai/docs/c8s](https://confidential.ai/docs/c8s/how-to/install).

### Prerequisites

- A Kubernetes cluster (vanilla or RKE2) with platform-admin permissions.
- SEV-SNP / TDX confidential VMs as nodes for node-as-CVM
  (see the [first-cluster tutorial](https://confidential.ai/docs/c8s/tutorials/first-confidential-cluster)).
  Node kernels must be recent enough for the TEE (AMD SEV-SNP ≥ 6.11, Intel TDX
  ≥ 6.16), which also satisfies the Linux ≥ 6.5 `SO_PEERPIDFD` the admission
  inventory relies on — see [docs/QUICKSTART.md](docs/QUICKSTART.md).
- Helm 3, `kubectl`, and `crane` on PATH.
- Go 1.27+ to build the CLI.

### Install

```sh
# Build and install the c8s CLI
git clone https://github.com/confidential-dot-ai/c8s
cd c8s
make install

# Label the node that will run CDS
kubectl label node <cds-node> role=cds

# Generate the operator keypair whose public half authorizes allowlist writes
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl ec -in operator.key -pubout -out operator.pub

# Install the platform (node-as-CVM) and point the bundled router
# at your workload
c8s install --cvm-mode=bare-metal --hardware-platform=sev-snp --namespace c8s-system \
  --operator-keys operator.pub \
  --workload-ref vllm=vllm/deployment/serving:8000 \
  --upstream vllm
```

`--cvm-mode` is required and has no default — `bare-metal`, `gke`, and `aks` are the
node-as-CVM shapes. `--hardware-platform` is required the
same way: `sev-snp` or `tdx`. An unstated shape would silently mismatch the
cluster it lands on, so the install refuses to guess.

`--workload-ref` adopts an existing workload as a confidential workload and
resolves its images into the bootstrap allowlist (see
[existing workload adoption](docs/operator.md#existing-workload-adoption)).
If you would rather not trust install-time digest resolution, pass
`--resolve-digests=false` and allowlist the digests yourself — see
[Managing the image allowlist](#managing-the-image-allowlist).

### Opt workloads in

Application teams opt in by annotating their pod templates:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

The annotation value (`api` here) is a workload id you choose; the
certificate SAN and the `c8s-<id>` headless Service are derived from it.

The webhook injects `c8s get-cert` as a native sidecar, which fetches an
attestation-bound certificate from CDS and renews it. Certificates land in
`/etc/c8s/certs`.

### Production notes

- **Pin measurements.** `cds.measurements` is required: the chart refuses to
  render without it, and CDS and every component that dials it refuse to start.
  `armtlsMesh.measurements` pins mesh peers to each other and is still accepted
  empty, which accepts any TEE-attested peer.

- **Pin operator keys.** Pass `--operator-keys` at install time or allowlist
  writes stay disabled. Leaving writes disabled and re-deploying CDS on every
  allowlist change works too, but each restart mints a fresh mesh CA, forcing
  downstream consumers onto a new root of trust. See
  [Managing the allowlist](#managing-the-image-allowlist).

### A note on QEMU

- **Node-as-CVM needs QEMU 10.1 or newer, built with `--enable-igvm`.**
  Booting a measured node image via IGVM requires upstream QEMU's IGVM
  support, which most distributions do not ship. Check for it with
  `qemu-system-x86_64 -object igvm-cfg,help`.

## Verifying a cluster from outside

Anyone can verify that a C8s endpoint really terminates inside attested
hardware, without trusting the operator's word for it.

Browser JavaScript cannot inspect certificate evidence during a TLS handshake.
The [c8s-verify](https://github.com/confidential-dot-ai/c8s-verify-js)
npm package instead runs a challenge-response protocol: the client
sends a fresh nonce and an X-Wing encapsulation key, the TEE returns a
hardware-signed attestation report binding the complete key exchange in one
round trip, and all further traffic flows over a post-quantum over-encrypted
channel (X-Wing: X25519 + ML-KEM-768) inside the regular TLS
session. A malicious TLS-terminating proxy in front of the real endpoint
cannot forge it. The wire contract is
[PROTOCOL.md](https://github.com/confidential-dot-ai/c8s-verify-js/blob/main/PROTOCOL.md).

Operators and CLIs can verify directly: `c8s cds verify` checks a CDS's
attestation and reports the operator keys it pins.

## Components

| Component | Description | Docs |
|---|---|---|
| [`cmd/cds`](cmd/cds/) | Certificate Distribution Service - verifies TEE attestation evidence, signs workload CSRs with an in-process mesh CA, and serves the allowlist and secret-release APIs | [operator docs](docs/operator.md) |
| [`cmd/c8s`](cmd/c8s/) | Operator and install CLI for CRDs, status mirroring, webhook injection, and the embedded Helm chart | [operator docs](docs/operator.md) |
| [`cmd/get-cert`](cmd/get-cert/) | CLI tool and init-container for TEE-attested certificate provisioning | [README](cmd/get-cert/README.md) |
| [`cmd/armtls-mesh`](cmd/armtls-mesh/) | Transparent L4 proxy wrapping inter-node K8s traffic in armTLS | [README](cmd/armtls-mesh/README.md) |
| [`cmd/nri-image-policy`](cmd/nri-image-policy/) | NRI plugin enforcing the image and argv allowlist on the host; also the node's admission inventory | [allowlist](docs/allowlist-and-capabilities.md) |
| [`internal/cmds/volumed`](internal/cmds/volumed/) | Encrypted-volume agent — opens volumes into a pod's mount namespace as a node DaemonSet | [volumes](docs/volumes.md) |

## Libraries

| Package | Description |
|---|---|
| [`pkg/armtls`](pkg/armtls/) | armTLS library for hardware-attested mTLS (AMD SEV-SNP, Intel TDX) — see [docs/armtls.md](docs/armtls.md) |
| [`pkg/armtls/cdsclient`](pkg/armtls/cdsclient/) | CDS attestation client for certificate provisioning |
| [`pkg/attestclient`](pkg/attestclient/) | High-level client for the CDS attestation flow |
| [`pkg/allowlistclient`](pkg/allowlistclient/) | CRUD client for the CDS allowlist API |
| [`pkg/allowlist`](pkg/allowlist/) | Allowlist types, argv policy, and secret grants |
| [`pkg/workloadclaims`](pkg/workloadclaims/) | Sandbox-token fetch and the admission-inventory socket contract |
| [`pkg/overenc`](pkg/overenc/) | Post-quantum over-encryption channel and its identity transcript |
| [`pkg/operatorauth`](pkg/operatorauth/) | Operator-key signing and verification for allowlist and secret writes |
| [`pkg/types`](pkg/types/) | Shared request/response types for the C8s protocols (the attestation-api wire types live in [attestation-go/remote](https://github.com/confidential-dot-ai/attestation-go)) |
| [`pkg/runtimemeasure`](pkg/runtimemeasure/) | TDX image-pin manifests and RTMR[3] measurement replay |
| [`pkg/certutil`](pkg/certutil/) | Certificate utility functions |

## Repository layout

```text
api/               CRD types
cmd/               Binaries: c8s, get-cert, armtls-mesh, nri-image-policy
                   (cmd/cds is only
                   the Dockerfile for the `c8s cds` subcommand,
                   internal/cmds/cds)
internal/          Operator, webhook, attestation, mesh CA, secret store,
                   embedded Helm chart
pkg/               Public Go libraries (see Libraries above)
node-guest-image/  The node-image definition for node-as-CVM (new home;
                   phase 0 — nothing consumes it from here yet)
docs/              Design and operator docs
samples/           Example manifests
scripts/           Dev and CI helpers
test/              Integration tests: docker-compose get-cert flow
                   (test/integration) and the kind cluster harness
                   (test/integration/cluster, see docs/integration-tests.md)
```

## Build

Requires Go 1.27+.

```bash
# Build the c8s binary for the container images (linux/amd64)
make build

# Build and install the c8s CLI for your host platform, onto PATH
make install

# Run tests
make test

# Mutation-test the changes vs origin/main (BASE=<ref> to override)
make mutation-check

# Lint (format check + vet)
make lint

# Clean build artifacts
make clean
```

## Managing the image allowlist

CDS serves the image-digest allowlist that `nri-image-policy` enforces on
every node. The `c8s allowlist`
command reads and mutates it. By default, router publishes the complete
`/allowlist` API and verifies CDS's attestation before forwarding requests.
When router uses the chart default CDS-issued public certificate
(`router.publicTLS.secretName` is empty, discovery mode `cds`), point the CLI at
the same router URL used for application traffic; no port-forward is required.

```sh
ROUTER=https://<router-host>

# Reads are unauthenticated
c8s allowlist export --url "$ROUTER" \
  --measurements <router-launch-digest> > allowlist.json
c8s allowlist diff allowlist.json --url "$ROUTER" \
  --measurements <router-launch-digest>

# Writes are signed with the operator key. 'add' admits an image under any
# command line; 'apply' or 'derive' pins one or grants secrets.
c8s allowlist add sha256:<digest> registry.example.com/app@sha256:<digest> \
  --url "$ROUTER" --measurements <router-launch-digest> \
  --operator-key operator.key
c8s allowlist upload allowlist.json \
  --url "$ROUTER" --measurements <router-launch-digest> \
  --operator-key operator.key
```

For a bare-metal install, pass `--cvm-mode bare-metal` to `allowlist upload`;
its required component set uses the measured host attestation service. GKE, AKS,
and uploads without a mode require the attestation-api image. `--require`
overrides the required set.

`--measurements` identifies the trusted build of the endpoint you connected
to. For the default public route, use the router launch digest; the CLI reads
router's discovery document and verifies its attestation automatically.
Direct CDS URLs remain supported, in which case pin the CDS launch digest.

An empty set accepts any attested endpoint, so an https endpoint is
**refused** without one — reads included: the answer would come from whatever
attested thing held the address. A plaintext `--insecure` dev endpoint is
exempt: it already declares that nothing about it is attested.

Do not point this CLI at router when `router.publicTLS.secretName` is set. That
front door uses WebPKI (`public_tls.mode=webpki`), and its public certificate is
not cryptographically bound to the discovery attestation, so the CLI
deliberately refuses it. Use a direct CDS armTLS URL and the CDS launch digest;
if CDS is not otherwise routable, use a local port-forward:

```sh
kubectl port-forward -n c8s-system svc/c8s-cds 8443:8443 &
c8s allowlist export --url https://localhost:8443 \
  --measurements <cds-launch-digest>
```

Writes are authorized by an operator EC keypair whose **public** half CDS
pins at install time. Generate one and pin it:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl ec -in operator.key -pubout -out operator.pub

c8s install --operator-keys operator.pub   # plus your other install flags
```

Installing without `--operator-keys` leaves allowlist writes disabled, and
`c8s install` refuses that on the default path unless you pass `--force` to
acknowledge. Supply the private key to the CLI by flag (`--operator-key`) or
environment (`C8S_OPERATOR_KEY`). Write tokens are short-lived and bound to
the request body, so a captured token cannot be replayed against a different
payload. The private key remains on the operator machine: router forwards only
the signed request and CDS verifies it against the pinned public key.

Set `router.allowlist.enabled=false` to remove the built-in public route. A
direct CDS connection, including a local port-forward for debugging, can
still be passed explicitly with `--url`.

Verify CDS's root of trust — its launch measurement and the operator key set it
serves — before exposing public ingress, using your own install inputs (the
operator public-key bundle). The key list is fetched over the attested serving
certificate, so it cannot be substituted in transit
([docs/armtls.md](docs/armtls.md)):

```sh
c8s cds verify https://<cds>:8443 \
  --measurements <launch-digest> \
  --operator-keys operator.pub
```

A swapped key set fails this closed. The check protects the verifier that runs
it, so run it continuously (CI), not only at bootstrap.

Two caveats worth knowing before production: revocation is currently coarse
(remove the key from `cds.operatorKeys` and re-install), and this check protects
only verifiers that run it. For
GitOps consumers, `c8s render-values --operator-keys operator.pub` embeds the
PEM content (the chart value takes content, never a file path); the chart
wiring is described in [docs/operator.md](docs/operator.md).

## Docker images

All images are published to GHCR on pushes to `main`. Release-worthy merges also
receive stable `vX.Y.Z`, `X.Y.Z`, and `X.Y` aliases in that same workflow run.
Per-role image names remain stable, but each image copies the same multi-mode
`c8s` binary and sets an appropriate entrypoint. See
[docs/releases.md](docs/releases.md) for the version policy.

The measured `node-guest-base` artifacts follow the same root release with
platform-qualified exact aliases such as `rke2-tdx-v0.1.0` and
`rke2-snp-cdi-v0.1.0`; they intentionally have no ambiguous bare or moving
SemVer alias.

| Image | Base | Notes |
|---|---|---|
| `ghcr.io/confidential-dot-ai/c8s-operator` | distroless | Multi-mode `c8s` binary for operator/install and non-node roles |
| `ghcr.io/confidential-dot-ai/cds` | distroless | |
| `ghcr.io/confidential-dot-ai/get-cert` | distroless | |
| `ghcr.io/confidential-dot-ai/armtls-mesh` | debian-slim | Needs iptables |
| `ghcr.io/confidential-dot-ai/nri-image-policy` | debian-slim | |
| `ghcr.io/confidential-dot-ai/volumed` | debian-slim | Needs cryptsetup/veritysetup |

The chart also deploys `ghcr.io/confidential-dot-ai/attestation-api`, the TEE
evidence verification service, which is built and published from
[attestation-rs](https://github.com/confidential-dot-ai/attestation-rs).

## Known gaps and open items

C8s is built around a strong threat model, and we would rather list the holes
than let you discover them:

- **Mesh peer measurements are not pinned by default.** Until
  `armtlsMesh.measurements` is set, mesh peers accept any attested peer. Fine
  for demos, mandatory homework for production. CDS pins (`cds.measurements`)
  have no such state: the chart does not render without them.

- **CDS is a singleton.** The mesh CA key lives only in CDS process
  memory; a restart mints a new CA and workloads re-bootstrap.

- **Secrets and volume keys live only in CDS memory.** There is no persistent
  or external key store: a CDS restart destroys every secret and volume key,
  every workload holding one must be rolled, and volume keys come back only
  from the operator's escrow file. Rotation, versioning and delete are absent
  — a replaced value is gone, and pods keep what they read at startup.

- **Mesh peers are verified by CA chain, not per-peer measurement.** Leaves
  carry the evidence CDS verified at issuance, and `VerifyPolicy` has a
  `RequireCAEvidence` mode that re-checks it — measurement included — on every
  connection, but no shipped profile enables it. There are no SPIFFE-style URI
  SANs, and per-workload peer policy is not enforced.

- **A workload's sandbox identity is CA-vouched, not hardware-bound.** The
  sandbox ID in a leaf is signed in by the mesh CA on the word of an on-node
  admission inventory; it is not folded into the TEE report. Any process that
  can bind the node's privileged inventory port can vouch for a sandbox it
  does not run.

- **The image allowlist gates digest and command line, not the rest of the
  pod spec.** Each container's `command` prefix and `args` remainder are
  enforced against the effective argv, env values are enforced by both backends,
  and bind-mount destinations are enforceable in the guest; capabilities and the
  remaining pod-spec fields are not. Nothing enforces which images run
  *together* — every running image must be allowlisted, but no gate requires
  the set in one pod to match a single workload entry.

- **Init containers cannot consume a released secret.** The secret volume is
  mounted into every container in the pod, but CDS releases only once *every*
  main container is running — that is when the sandbox matches a whole
  workload entry. An ordinary init container runs to completion before that
  point, so it sees an empty directory, and one that blocks waiting for its
  file deadlocks the pod it gates. Secrets are consumable from main
  containers, which must wait for the file rather than read it at startup. The
  injected fetcher is a native sidecar for this reason: it is the one entry in
  `initContainers` that keeps running alongside the workload.

- **Encrypted volumes are attached at node boot, and a force-deleted volume
  pod leaks its dm stack.** A volume reaches a node-as-CVM node as a block
  device declared in the VM spec; adding one to a running node is not
  supported (it is a VM spec change and a node reboot). `volumed` tears a
  volume down only when the pod's cgroup empties; a `kubectl delete pod
  --force --grace-period=0` that leaves it populated leaves the
  dm-crypt/dm-verity targets and the mount behind, with the volume key
  resident in kernel memory, until an operator closes them by hand
  (`dmsetup ls | grep ^c8s-`). `volumed` does not reconcile existing
  mappings on start, so restarting it does not recover them. See
  [docs/volumes.md](docs/volumes.md).

- **GPU attestation is not wired end to end.** GPU passthrough into
  confidential nodes works, and the node CVM fails closed unless every GPU
  is in CC mode and its attestation verifies before the CC Ready state is
  set (`gpu-cc-enforce.service`, via the node's baked
  [attestation-rs](https://github.com/confidential-dot-ai/attestation-rs)
  and NRAS). That is a self-check inside the measured node: CDS does not
  require GPU evidence at certificate issuance, so no positive GPU
  attestation reaches the relying party.

- **The browser over-encryption channel does not stream.** Requests and
  responses are buffered per envelope; responses over 32 MiB fail rather than
  stream.

- **Operator key revocation is coarse.** No CRL/OCSP; revoking an operator
  key means removing it and re-installing.

## Roadmap

The direction of travel:

- **GPU attestation end to end.** Require GPU evidence at certificate
  issuance, so a positive GPU attestation reaches the relying party rather
  than stopping at the node's boot-time self-check.

- **In-TEE volume encryption.** Stream plaintext into a CVM that generates the
  key, writes the encrypted volume, and commits the key straight to the secret
  store, so the party supplying the data never holds the key that opens it.
  `c8s volume create` encrypts on the operator's machine, which means the key
  is generated outside the TEE and escrowed to a local file.

- **Encrypted RDMA.** Encrypted GPU-to-GPU and node-to-node RDMA for
  confidential multi-node training and inference.

## Standing on the shoulders of the community

C8s exists because a lot of excellent open work came before it, and we want
to be loud about that:

- [Confidential Containers](https://github.com/confidential-containers)
  helped establish the foundations of confidential container workloads
  that informed C8s's development.

- The [Confidential Computing Consortium](https://confidentialcomputing.io/)
  and the wider ecosystem (the AMD SEV-SNP and Intel TDX stacks, the IGVM
  format, OVMF, and the NVIDIA confidential computing work) provide the
  hardware and firmware bedrock all of this stands on.

Where we fix or extend something upstream, we aim to contribute it back.

## Contributing and security

Please, before you open an issue or a PR, read
[CONTRIBUTING.md](CONTRIBUTING.md). It is short, and it explains the
contribution terms (you sign the CLA on your first PR), the review bar, our
policy on LLM-assisted contributions, and the requirement that commits be
signed.

And before you report anything security-shaped, read
[SECURITY.md](SECURITY.md). C8s is trust infrastructure: attestation
bypasses, policy bypasses, and certificate mis-issuance are security issues.
**Do not open public issues for them.** Email
[security@confidential.ai](mailto:security@confidential.ai) instead.

For anything else: [hello@confidential.ai](mailto:hello@confidential.ai).

## Licence

C8s is licensed under the [GNU Affero General Public License v3.0](LICENCE).
Contributions are accepted under the terms in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related repositories

- [`confidential-dot-ai/c8s-verify-js`](https://github.com/confidential-dot-ai/c8s-verify-js) - browser-side cluster verification library (npm: `c8s-verify`)
- [`confidential-dot-ai/attestation-rs`](https://github.com/confidential-dot-ai/attestation-rs) - TEE attestation evidence verification service (publishes the `attestation-api` image)
- [`confidential-dot-ai/attestation-go`](https://github.com/confidential-dot-ai/attestation-go) - TEE attestation evidence verification library for go
