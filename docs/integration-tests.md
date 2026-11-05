# Run the integration tests

These local harnesses exercise C8s without TEE hardware, so they do not
prove confidential properties:

- **docker-compose**: the armTLS certificate flow, where armTLS is C8s's mutual
  TLS whose certificates carry TEE evidence.
- **kind**: a whole cluster.
- **CDS HA**: three `c8s cds` replicas of one cluster as real processes on
  loopback addresses, each with its own attestation-api
  (`make test-integration-cdsha`, Linux only).

CI runs them as the Integration, Integration (cluster) and CDS HA jobs; terms
are defined in [glossary.md](glossary.md).

The Pod runtime lane at the end of this page adds a privileged runtime harness
to ordinary CI; like the others it proves no hardware property.

Prerequisites:

- Every harness: make, go, OpenSSL (macOS LibreSSL lacks `x509 -ext`) and
  curl.
- The docker-compose harness also: docker, with Compose v2
  (`docker compose`). The CDS HA harness needs none: its replicas are
  processes on this host.
- The kind harness also: docker, kind, kubectl, helm and python3 with PyYAML.
  Podman works as kind's provider with `KIND_EXPERIMENTAL_PROVIDER=podman`, but
  `docker` must stay on PATH: the harness builds images and reaches into the
  node with it. CI pins helm and kind in
  `.github/actions/setup-kind-harness`.

Run them from the repository root:

```sh
make test-integration
make test-integration-cluster
make test-integration-cdsha
```

The first starts a mock CDS — the service that verifies evidence and signs
workload certificates — and a mock attestation-api, the node-local service that
produces hardware evidence for CDS and every other component. It runs get-cert,
the sidecar that obtains a pod's certificate, through the real armTLS flow, and
checks that nginx serves HTTPS with the issued certificate. The second boots a
kind cluster, builds the component images, and runs
`c8s install --cvm-mode=bare-metal`. The first two end with their check count:

```text
=== All <N> integration checks passed ===
=== All <N> cluster integration checks passed ===
```

The CDS HA harness runs a cluster of three `c8s cds` processes behind one
attestation-api each, and an operator that signs the decrees they act on and
posts them to the replicas over the attested channel. `run.sh -short` is the
subset a pull request runs.

## What the kind harness substitutes

The TEE is replaced at exactly one point: evidence generation.
`test/mock-attestation` serves synthetic SNP reports with an all-zero launch
measurement on the node IP `:8400`, the address `bare-metal` consumers dial for
the node-baked attestation-api. It answers verification requests too, so no hop
proves a hardware property; what matches production is the pinning — that
measurement is the one this cluster's CDS pin and node pins carry, compared
exactly as in production — and every component delegating verification to the
attestation-api works unchanged.

The CDS runs outside the cluster, as a container of the kind network with an
attestation-api of its own reporting the launch binding of the configuration it
boots on (`HOST_DATA` = SHA-256 of that file). That is what the pin the install
carries names, so every client holds it to the configuration it serves, exactly
as it holds a CDS VM to its launch file.

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
the rest). They address the CDS at `$C8S_IT_WORKDIR/cds-address`, which the run
wrote. Delete the cluster with `kind delete cluster --name c8s-it`, and the CDS
with `docker rm -f c8s-it-cds c8s-it-cds-attestation`.

## When a run fails

- A pod stuck in `CreateContainerError` with `image not in allowlist` is the
  admission plugin doing its job: the image's containerd store digest is absent
  from the install-time allowlist, which the harness writes from the node's
  image store before install. Pre-pull the image in the
  `node_exec ctr -n k8s.io images pull` block near the top of `run.sh`.
- The mock-attestation Deployment is `Recreate` on purpose: two host-network
  pods cannot both bind `:8400` on a single-node cluster.

## Pod runtime CI

Run `make test-integration-pod-runtime` with Go and Docker supporting
privileged containers. The existing `Integration (Pod runtime)` CI job invokes
this command and requires all three checks:

1. Start authorization: one offline workload executes only after its exact NRI
   container, sandbox and process identity is consumed once. Seven cases reject
   execution: missing authority, policy denial, measurement failure, callback
   timeout, lost socket, plugin disconnect and replay.
2. Production NRI recovery: separate containerd and full plugin processes restart
   while the original sandbox and task remain alive. The test verifies the task's
   actual cgroup/process identity, complete admission history including a removed
   same-image workload, unchanged measurements and credential identity, and refusal
   of old permissions. Missing, malformed and interrupted recovery state must
   refuse startup.
3. Standalone kubelet recovery: the real kubelet owns a static Pod with a mesh
   sidecar and application. Restarting kubelet, containerd and the full plugin must
   preserve the staged manifest/configuration, Pod UID, running task identities,
   complete claims and measurements. The kubelet's `/pods` response is checked
   against its serving certificate and the actual containerd tasks.

The runner extracts digest-pinned RKE2 runtime/kubelet and CNI release binaries
for the Docker daemon's native architecture. It uses the production `c8s-runc`,
full NRI callbacks for recovery, real namespace protection, and memory-backed
recovery/credential volumes. The first check isolates the start-permission
boundary; the recovery checks use the complete configured plugin.

Measurement registers, CDS transport and credential issuance are fixtures.
Containerd uses the native snapshotter and cgroupfs. This lane does not issue
a real Pod certificate, or establish guest-airgap byte equivalence, systemd
ordering, overlay filesystem behavior or Cloud acceptance.

The runtime lane requires fresh result receipts and fails when
prerequisites or required assertions are missing. The runtime lane requires
`result.json`, `recovery-result.json` and `kubelet-recovery-result.json`, each bound
to the current invocation, plus successful cleanup. Evidence includes runtime,
kubelet and CNI binary hashes and bounded logs. The lane removes only its owned
local resources; the runtime container has no host mounts or network access.
Set `C8S_POD_RUNTIME_ARTIFACTS` to a new evidence
directory. CI retains those artifacts for seven days.
