# Run the integration tests

Exercise C8s on a plain Linux or macOS host with no TEE hardware, so nothing
here proves a confidential property. Two harnesses:

- **docker-compose**: the armTLS certificate flow, where armTLS is C8s's mutual
  TLS whose certificates carry TEE evidence.
- **kind**: a whole cluster.

CI runs both as the Integration and Integration (cluster) jobs; terms are
defined in [glossary.md](glossary.md).

Prerequisites:

- Both harnesses: docker with Compose v2 (`docker compose`), make, OpenSSL
  (macOS LibreSSL lacks `x509 -ext`), and curl.
- The kind harness also: kind, kubectl, helm, go, and python3 with PyYAML.
  Podman works as kind's provider with `KIND_EXPERIMENTAL_PROVIDER=podman`, but
  `docker` must stay on PATH: the harness builds images and reaches into the
  node with it. CI pins helm and kind in
  `.github/actions/setup-kind-harness`.

Run both from the repository root:

```sh
make test-integration
make test-integration-cluster
```

The first starts a mock CDS — the service that verifies evidence and signs
workload certificates — and a mock attestation-api, the node-local service that
produces hardware evidence for CDS and every other component. It runs get-cert,
the sidecar that obtains a pod's certificate, through the real armTLS flow, and
checks that nginx serves HTTPS with the issued certificate. The second boots a
kind cluster, builds the component images, and runs
`c8s install --cvm-mode=bare-metal`. Each ends with its check count:

```text
=== All <N> integration checks passed ===
=== All <N> cluster integration checks passed ===
```

## What the kind harness substitutes

The TEE is replaced at exactly one point: evidence generation.
`test/mock-attestation` serves synthetic SNP reports with an all-zero launch
measurement on the node IP `:8400`, the address `bare-metal` consumers dial for
the node-baked attestation-api. It answers verification requests too, so no hop
proves a hardware property; what matches production is the pinning — that
measurement is the pinned CDS measurement, compared exactly as in production —
and every component delegating verification to the attestation-api works
unchanged.

The rest is real: the admission webhook and validating admission policies in a
real API server, the admission plugin registered against the node's containerd,
certificate issuance with sandbox identity, the armTLS mesh, workload adoption,
and uninstall. Allowlist and route writes are signed with the production
operator-token signer and verified by CDS; only the client-side evidence check
is skipped, so they travel plain `curl`.

The kind node image is pinned by digest in `test/integration/cluster/lib.sh`;
bump it with the kind release. A replacement needs a containerd whose NRI
supports `ValidateContainerAdjustment`, the call the plugin's environment and
mount enforcement runs in.

## What it does not cover

No TEE property is asserted. Hardware verification, measurements that mean
anything, encrypted volumes (`volumed` needs the node kernel's device mapper),
`c8s get-kubeconfig`, and the `c8s verify`, `c8s allowlist` and `c8s routes`
CLIs stay on the hardware CI lanes (`snp-metal-e2e`, `tdx-metal-e2e`,
`cvm-e2e`): those verify evidence in process with real hardware cryptography,
which synthetic evidence cannot pass.

## Keep the cluster for another driver

```sh
C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1 C8S_IT_WORKDIR=/tmp/c8s-it ./test/integration/cluster/run.sh
```

`C8S_IT_SETUP_ONLY=1` stops once the stack is installed, before the checks.
`C8S_IT_KEEP=1` leaves the kind cluster and the work directory (operator key,
`optoken`, image-store scan) in place, at `C8S_IT_WORKDIR`.

The run writes `$C8S_IT_WORKDIR/env`, which exports a `KUBECONFIG` for the kept
cluster whatever kubectl's current context is. Source
`test/integration/cluster/lib.sh` and then that file to drive the cluster with
the harness's own helpers (`cds_write`, `cds_get`, `node_exec`, `run_pod`, and
the rest). They open the shared CDS port-forward on demand with `cds_pf_start`,
record its pid in `$C8S_IT_WORKDIR/cds-pf.pid`, and `cds_pf_stop` ends it.
Delete the cluster with `kind delete cluster --name c8s-it`.

## When a run fails

- A pod stuck in `CreateContainerError` with `image not in allowlist` is the
  admission plugin doing its job: the image's containerd store digest is absent
  from the install-time allowlist, which the harness writes from the node's
  image store before install. Pre-pull the image in the
  `node_exec ctr -n k8s.io images pull` block near the top of `run.sh`.
- The mock-attestation Deployment is `Recreate` on purpose: two host-network
  pods cannot both bind `:8400` on a single-node cluster.
