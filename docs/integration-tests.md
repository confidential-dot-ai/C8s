# Integration tests

Two harnesses run in CI on plain GitHub-hosted runners (no TEE hardware), plus
live-cluster scripts that run on the metal lanes. This doc maps what each
covers and why the kind harness is shaped the way it is.

| Harness | Entrypoint | CI job | Subject |
| --- | --- | --- | --- |
| docker-compose | `make test-integration` | Integration | get-cert's RA-TLS flow against mock CDS + mock attestation-api, nginx serving the issued leaf |
| kind cluster | `make test-integration-cluster` | Integration (cluster) | the full bare-metal-mode control plane and workload path (below) |
| live-cluster scripts | `test/e2e/*.sh` | snp/tdx-metal-e2e | cw-label policy, mesh enforcement, allowlist enforcement, control-plane convergence on real TEEs |

## The kind harness

`test/integration/cluster/run.sh` boots a single-node kind cluster, builds the
component images from the checkout, and runs the real `c8s install
--cvm-mode=bare-metal`. The TEE is substituted at exactly one point: **evidence
generation**. `test/mock-attestation` serves synthetic SNP reports (launch
digest all-zero) on the node IP :8400 — the address bare-metal-mode consumers dial
for the node-baked api — and an `attest-proxy` sidecar publishes it on the
hostPath unix socket the host plugin uses. Every component that delegates
verification to the attestation-api (get-cert, CDS, ratls-mesh, the NRI
plugin) works unchanged against it. The all-zero digest is pinned via
`--measurements`, so every RA-TLS hop is verified exactly as in production.

The NRI image-policy plugin runs for real: the harness renders the chart's
full installer DaemonSet and applies it out-of-band (bare-metal mode renders only
the baked pins patcher, and the kind node bakes no plugin for it to pin). The
installer patches the node's containerd config and restarts it, which kind
survives. The install-time bootstrap entries are generated from the node
containerd's image store, because `policy.enforceExisting` checks
already-running containers against them.

Tenant fixtures satisfy the Restricted controls: workload and adoption
Deployments use digest-pinned `nginxinc/nginx-unprivileged` on port 8080;
curl Pods run as UID 1000. All use non-root execution, RuntimeDefault seccomp,
no privilege escalation, and dropped ALL capabilities. `pod-fixture.py` is the
shared JSON renderer used by the shell harness and Go admission regression tests,
so negative fixtures violate only their intended label or host-network rule.
Workload pre-pulls, the allowlist floor, mesh probes, Service target ports, and
adoption routing use the same image and backend-port settings.

Two operator-facing commands verify evidence **in-process** with real hardware
cryptography, which synthetic evidence cannot pass: `c8s verify` and the `c8s
allowlist` CLI. Those stay on the metal lanes. The harness still exercises the
allowlist write path server-side: writes are signed with the production
`pkg/operatorauth` signer (`optoken/`) and CDS performs its full token
verification — only the client-side evidence check is skipped (curl `-k` over
a port-forward).

## Covered scenarios

- `c8s install` end-to-end: preflights, helm install, CRDs, RBAC,
  MutatingWebhookConfiguration, ValidatingAdmissionPolicies.
- Control-plane readiness: operator, CDS (RA-TLS serving cert via the mock
  api), router (mesh cert from CDS), ratls-mesh DaemonSet.
- NRI plugin: installer writes the binary + config, patches containerd,
  restarts it, registers, serves the admission inventory socket.
- Allowlist authorization: unsigned writes and wrong-key writes are 401; a
  write signed by the pinned operator key lands, is served, and deletes.
- Webhook injection: `confidential.ai/cw` pods gain the get-cert sidecar, the
  wait gate, and the cw label; the operator provisions the `c8s-<id>` headless
  Service.
- Workload identity: get-cert redeems a sandbox token from the NRI admission
  inventory, CDS calls the digests endpoint back, and the issued leaf carries
  the workload's in-cluster DNS SAN.
- Image admission, fail-closed: a non-allowlisted image is denied at
  container creation; a signed allowlist write flips the same pod to Running
  after the plugin's next pull.
- Admission rejections: cw label/annotation mismatch (webhook) and
  hostNetwork tenant pods (host-namespace policy).
- Dynamic provisioning: a PVC on kind's default (local-path) class binds and
  is writable — the provisioner's hostPath helper admits in the VAP-exempt
  `local-path-storage` namespace (issue #210's regression).
- Mesh: a pod-IP dial to a cw workload is wrapped (the inbound counter
  moves); a dial from a mesh-excluded namespace hits the FORWARD guard and
  DROPs, and a Service-VIP dial is either dropped or mesh-wrapped — never
  plaintext — proven by the drop/wrap counters (rule ordering between
  kube-proxy and the mesh is not stable). Mirrors
  `test/e2e/mesh-cw-enforcement.sh`.
- router front door: HTTPS verified against the CDS mesh CA.
- Workload adoption: `c8s install --workload-ref` patches a running
  deployment, its rollout goes through injection, the status mirror reports
  `kubectl get cwl`, and router routes the front door to it over the mesh.
- `c8s uninstall`: release, webhook, and admission policies are removed.

## Deliberately out of scope

No TEE properties are asserted: hardware verification, measurements that mean
anything, encrypted volumes (volumed needs device-mapper control
of the node kernel), `get-kubeconfig` (SNP-gated), and the
`c8s allowlist`/`c8s verify` CLIs (in-process hardware verification, above).
The metal lanes (snp-metal-e2e, tdx-metal-e2e, cvm-e2e) own those.

### An extra suite on the metal lanes

`snp-metal-e2e.yml` and `tdx-metal-e2e.yml` take `suite_artifact` and
`suite_run` from a calling workflow. After their own asserts pass, they
download that artifact of the same run onto the launcher and run the command
against the attested guest with the e2e scripts' environment
(`.github/actions/extra-suite` lists it); whatever the command writes to
`$SUITE_RESULTS` is uploaded as `<artifact>-results-<lane>`. The lane holds
no credential for the suite. Called from another repository, the SNP lane
still takes its scripts and actions from this one, at the default branch.

## Running it

```sh
make test-integration-cluster
```

Needs docker (or podman with `KIND_EXPERIMENTAL_PROVIDER=podman`), kind,
kubectl, helm, go, OpenSSL (macOS's LibreSSL lacks `x509 -ext`), curl, and
python3 with PyYAML. It runs on Linux and macOS hosts: the component images
get a Linux build of c8s, the install a host build. The kind node image is
pinned by digest in run.sh; bump it with the kind release. CI installs helm
and kind with `.github/actions/setup-kind-harness` (kind pinned by sha256). Custom node images
must provide NRI `ValidateContainerAdjustment` support (the pinned image uses
containerd 2.3.4 / NRI 0.12.0); older runtimes reject the env-enforcing plugin
at registration.

### Keeping the cluster for another driver

```sh
C8S_IT_KEEP=1 C8S_IT_SETUP_ONLY=1 C8S_IT_WORKDIR=/tmp/c8s-it ./test/integration/cluster/run.sh
```

`C8S_IT_SETUP_ONLY=1` stops once the stack is installed, before the checks;
`C8S_IT_KEEP=1` leaves the kind cluster and the work directory (operator key,
`optoken`, floor scan) in place. The run writes `$C8S_IT_WORKDIR/env`, which exports a `KUBECONFIG` for
the kept cluster whatever kubectl's current context is; source
`test/integration/cluster/lib.sh` and then that file to drive the cluster
with the harness's own helpers (`cds_write`, `node_exec`, `run_pod`,
`mesh_metric`, …). The CDS port-forward they open is shared through
`$C8S_IT_WORKDIR/cds-pf.pid` across processes; `cds_pf_stop` ends it. Delete
the cluster with `kind delete cluster --name c8s-it`.

### Failure notes

- A pod stuck `CreateContainerError` with `image not in allowlist` is the NRI
  plugin doing its job: the image's containerd store digest has no bootstrap
  entry. The entries are written from the node's image store before install,
  so an image first pulled *during* the run lands here — pre-pull it next to
  the other fixtures in run.sh.
- The mock-attestation deployment is `Recreate` on purpose: two hostNetwork
  pods cannot both bind :8400 on a single-node cluster.
