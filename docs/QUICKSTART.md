# C8s quickstart

This is the supported install path for the consolidated C8s chart.

## Prerequisites

- A Kubernetes cluster with platform-admin permissions.
- Helm 3 and `kubectl` on PATH, plus `crane` (digest resolution is on by
  default; not needed if you pass `--resolve-digests=false`).
- C8s images published with the same tag as the release, for example `v0.1.0`,
  resolved to digests by default or supplied in a values file.
- One node labelled to run CDS (`role=cds` by default).
- Nodes with the TEE device shape expected by `attestationApi.teeDevices`.
- Node kernels new enough for `SO_PEERPIDFD` (Linux ≥ 6.5), which the
  admission inventory (nri-image-policy) requires to pin a caller's peer
  credentials against PID reuse; a node without it fails sandbox-token fetches
  closed. TEE-capable kernels already exceed this — AMD
  SEV-SNP hosts need ≥ 6.11 and Intel TDX ≥ 6.16 — so this is satisfied on any
  supported node.

## Install C8s

This installs the supported chart-managed CVM shape: operator, RBAC, CRDs,
webhook, attestation-api, and CDS.

```sh
c8s install --namespace c8s-system --cvm-mode=bare-metal --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm
```

`--cvm-mode` is required — one of `bare-metal` (node-as-CVM: the nodes themselves are TDX/SNP CVMs, shown here;
single-tenant), `gke`, or `aks`. So is `--hardware-platform`, naming the nodes' CPU TEE: `sev-snp` or
`tdx` (under `aks` it selects the Azure vTPM shape instead). `--operator-keys`
takes a PEM bundle of EC public keys that authorize
`c8s allowlist` writes; without it the install refuses to proceed (pass
`--force` to install with allowlist writes disabled):

```sh
openssl ecparam -genkey -name prime256v1 -noout -out operator.key
openssl ec -in operator.key -pubout -out operator-pub.pem
```

router ships no default upstream: `--upstream` (with the port on its
`--workload-ref`) points router at an adopted workload's mesh-wrapped headless Service.
Without an upstream choice, router renders no catch-all route until one is
attached rather than shipping an unencrypted inference hop. Alternatives and details: the
[Upstream](operator.md#router-upstream).

For existing workloads, use `--workload-ref <cw-id>=<namespace>/<kind>/<name>` so install
adopts them as CWs and resolves their images into the NRI bootstrap allowlist.
Details and the vLLM router/engine example: [existing workload adoption](operator.md#existing-workload-adoption).

By default `c8s install` resolves each component image tag to its registry
digest (via `crane`) and pins it. The image policy admits C8s components by
digest, so this is what lets a plain install satisfy the floor: without pinned
digests the render fails closed rather than ship a cluster whose own components
its image policy would deny. `crane` must be on PATH. To pin the digests
yourself instead, pass `--resolve-digests=false` and supply them via
`-f values.yaml`.

Label the node that will run CDS so the chart's default `role: cds` selector
matches (override `cds.node.selector` for a different label):

```sh
kubectl label node <cds-node> role=cds
```

`c8s install` passes the CLI build version as the chart image tag when it is a
stable release version (for example `v0.1.0`), for which CI publishes a matching
image alias. Any other build (a local `git describe` derivative, a commit SHA,
or the unstamped default) falls back to the `main` branch tag, the only other
fallback tag published for every component.

The chart itself is versioned separately. CI publishes it to
`oci://ghcr.io/confidential-dot-ai/charts` under a SemVer chart version (`X.Y.Z`
for a stable release, `<Chart.yaml version>-g<short-sha>` for a development
build), never a `main` tag, because Helm chart versions must be SemVer. The chart
carries no default image tag of its own, so the image tag above is supplied by
`c8s install` rather than baked into the published chart.

To install without the advisory CRDs:

```sh
c8s install --namespace c8s-system --cvm-mode=bare-metal --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem --install-crds=false \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm
```

The cluster still runs without CRDs. CRDs only provide demo/status UX such as
`kubectl get cwl`; pod injection is driven by pod annotations. In this mode the
status-mirror controller is disabled.

## Private registry credentials

When the C8s images (or your mirrors of them) live in a registry that requires
authentication, create a registry-credential Secret in the release namespace
and pass its name at install time:

```sh
kubectl create namespace c8s-system
kubectl create secret docker-registry ghcr-pull-secret \
  -n c8s-system \
  --docker-server=ghcr.io \
  --docker-username=<user-or-x-access-token> \
  --docker-password="$GITHUB_TOKEN"

c8s install --namespace c8s-system --cvm-mode=bare-metal --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem \
  --image-pull-secret ghcr-pull-secret \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm
```

`scripts/deploy-image-pull-secret.sh` wraps the secret-creation step
idempotently (re-run it to rotate the credential in place):

```sh
IMAGE_PULL_SECRET=<ghcr-token> NAMESPACE=c8s-system ./scripts/deploy-image-pull-secret.sh
c8s install --namespace c8s-system --cvm-mode=bare-metal --hardware-platform=sev-snp \
  --operator-keys operator-pub.pem \
  --image-pull-secret ghcr-pull-secret \
  --workload-ref vllm=vllm/deployment/serving:8000 --upstream vllm
```

Pass `NAMESPACE=c8s-system` explicitly — the script defaults to `default`,
and `imagePullSecrets` references are namespace-local, so a Secret there is
invisible to the C8s pods.

The chart appends the Secret to every component's `imagePullSecrets` —
including components that set their own local list — so all pods authenticate
from their first start: no Secret references to patch in afterwards, no pods
to bounce. The install fails fast if the named Secret is missing from the
namespace or is not a registry-credential type
(`kubernetes.io/dockerconfigjson`). Helm-values consumers (e.g. a fleet
HelmRelease) get the same behavior by setting `imagePullSecret`.

The chart never creates or adopts the Secret itself, so it works equally with
a kubectl-created Secret, external-secrets, or a previous manual rollout, and
rotating the credential is a plain Secret update with no helm interaction.

Note this is the cluster-side (kubelet) credential: `--resolve-digests` runs
`crane` on your workstation and uses your local docker login, not this
Secret.

## Certificate path

The chart wires workload injection to chart-managed CDS. CDS generates its
mesh CA key in process memory and persists only the public CA bundle. The
persisted bundle lets already-issued leaves keep verifying across CDS
restarts; it does not preserve issuance — a restart generates a new CA key,
and workloads must re-bootstrap to trust new leaves. See docs/operator.md
for the singleton operational guidance. Run this chart inside the intended
CVM trust boundary; the supported chart path no longer has external CDS
URL values.

The chart's RA-TLS handshakes accept any TEE-attested peer unless the
operator pins `cds.measurements` and `ratlsMesh.measurements` to the
expected launch digests. Leave these empty only on a trusted Pod network.

## Workload opt-in

Application teams opt in by annotating their pod templates:

```yaml
metadata:
  annotations:
    confidential.ai/cw: api
```

The webhook injects `c8s get-cert` as an init container and renewal sidecar.
They write `tls.crt` and `tls.key` into `/etc/c8s/certs`.

See:

- `docs/DEMO.md` for a minimal demo flow.
