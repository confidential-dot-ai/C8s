# Integration tests

Two harnesses run in CI on plain GitHub-hosted runners (no TEE hardware), plus
live-cluster scripts that run on the metal lanes. This doc maps what each
covers and why the kind harness is shaped the way it is.

| Harness | Entrypoint | CI job | Subject |
| --- | --- | --- | --- |
| docker-compose | `make test-integration` | Integration | get-cert's armTLS flow against mock CDS + mock attestation-api, nginx serving the issued leaf |
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
verification to the attestation-api (get-cert, CDS, armtls-mesh, the NRI
plugin) works unchanged against it. The all-zero digest is pinned via
`--measurements`, so every armTLS hop is verified exactly as in production.

The NRI image-policy plugin runs for real: the harness renders the chart's
full installer DaemonSet and applies it out-of-band (bare-metal mode renders only
the baked pins patcher, and the kind node bakes no plugin for it to pin). The
installer patches the node's containerd config and restarts it, which kind
survives. The install-time bootstrap entries are generated from the node
containerd's image store, because `policy.enforceExisting` checks
already-running containers against them.

Tenant fixtures satisfy the Restricted controls: workload and adoption
Deployments use digest-pinned `nginxinc/nginx-unprivileged` on port 8080, and
the adopted one serves TLS on 8443 with its get-cert leaf once adopted;
curl Pods run as UID 1000. All use non-root execution, RuntimeDefault seccomp,
no privilege escalation, and dropped ALL capabilities. `pod-fixture.py` is the
shared JSON renderer used by the shell harness and Go admission regression tests,
so negative fixtures violate only their intended label or host-network rule.
Workload pre-pulls, the allowlist floor, mesh probes, Service target ports, and
adoption routing use the same image and backend-port settings.

Two operator-facing commands verify evidence **in-process** with real hardware
cryptography, which synthetic evidence cannot pass: `c8s verify` and the `c8s
allowlist` and `c8s routes` CLIs. Those stay on the metal lanes. The harness still exercises the
allowlist write path server-side: writes are signed with the production
`pkg/operatorauth` signer (`optoken/`) and CDS performs its full token
verification — only the client-side evidence check is skipped (curl `-k` over
a port-forward).

## Covered scenarios

- `c8s install` end-to-end: preflights, helm install, CRDs, RBAC,
  MutatingWebhookConfiguration, ValidatingAdmissionPolicies.
- Control-plane readiness: operator, CDS (armTLS serving cert via the mock
  api), router (mesh cert from CDS), armtls-mesh DaemonSet.
- NRI plugin: installer writes the binary + config, patches containerd,
  restarts it, registers, serves the admission inventory socket.
- Allowlist authorization: unsigned writes and wrong-key writes are 401; a
  write signed by the pinned operator key lands, is served, and deletes.
- Route API: before any manifest is stored the front door answers 503;
  unsigned and wrong-key `PUT /routes` are 401, a manifest
  anchored on the mesh CA is 422, a signed write is 204 and the same revision
  again 409; `GET /routes` serves the PUT bytes with a token whose `pbh` is
  their digest.
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
- router front door: HTTPS verified against the CDS mesh CA, from a pod of an
  exempt namespace — the in-cluster stand-in for the external clients it
  serves, because a member's dial would be captured into armTLS.
- Route publication: `/.well-known/c8s/routes` through the front door is 404
  at the chart default. The adoption install sets
  `router.routePublication.enabled`; the path then serves the CDS `GET /routes`
  envelope of the applied revision byte for byte, with
  `Cache-Control: no-store`. No lane verifies the transcripts that bind the
  route digest. Instead, `TestProductionRouterAgainstVerifier` in
  `internal/cmds/verify` runs the production `cds-attest` handler against the
  verifier's gather path in both attested modes with both route checks,
  including a route update between publication and admission. Other
  implementations interoperate through the `pkg/overenc/testdata` vectors
  ([Upgrade from the earlier layout](routes-evidence.md#upgrade-from-the-earlier-layout)).
- Workload adoption: `c8s install --workload-ref` patches a running
  deployment, its rollout goes through injection, and the status mirror
  reports `kubectl get cwl`.
- Routing by the route manifest: `c8s install --upstream` writes a new
  manifest to `--routes-out`, which the harness stores with `optoken`, naming
  the floor entry that describes the adopted pod (`--resolve-digests=false`
  writes no `web` entry). The adopted nginx reloads on each `get-cert`
  renewal, and the harness waits until the leaf it serves carries that entry's
  name. Through a router port-forward with `Host` set to the manifest
  host, `/` reaches the workload over TLS (200); an unknown host and a path
  with an empty segment get 404; a revision naming a workload name the
  backend's leaf does not carry gets 502, and an unrouted path 404. CDS
  refuses an address backend anchored on the mesh CA (422). The harness sets
  `router.routing.pollInterval=2s` so each write applies within seconds.
  The harness never runs the default adoption path, so unit tests cover its
  model instead: the entry install writes for the fixture
  (`test/integration/cluster/testdata/adopt-me-entry.json`) must match what
  the webhook injects (`internal/webhook`) and what the NRI plugin observes of
  the injected container (`internal/cmds/nri-image-policy`). Install's signed
  delivery (`--operator-key`, which reads the served allowlist) verifies CDS
  in-process, so only a metal lane can cover it.
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

### Connected Pod acceptance on TDX

The manual `tdx-metal-e2e.yml` input `pod_acceptance: true` starts a real CDS
server and two standalone Pod guests. The image, image manifest, disk, mesh
container and matching CLI source are pinned in
`.github/scripts/fixtures/pod-connected/production-image.json`. Image profile
and component sources must agree. Update the complete pin set together after
a paired production image build; the harness does not accept a development
image or substitute a fake CDS.

```sh
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref podcvm/no-mesh-gate -f pod_acceptance=true
```

The two signed workloads test authenticated peer traffic, IPv4 HTTPS, system
DNS, TCP/UDP DNS, and guest/link-local connection denials. Authenticated Pod
status must show readiness withdrawing and recovering, followed by successful
checker exits after at least 65 minutes. Public mesh leaves must rotate late in
the observation window, with new serials and keys, stable Pod identities and
CA, and no application, checker or endpoint restarts. Certless, wrong-CA and
plaintext requests must be rejected, followed by fresh healthy Pod status.

Three run-owned Services allocate the addresses signed into the launch inputs.
Guest-to-guest traffic uses those Services. If runner network policy prevents
direct observations, the runner uses owned VMI port-forwards for attestation,
status and certificate probes. Keys remain in the private runner directory or
their intended guest. The test uses one shared read-only root import, a private
server scratch disk, and approximately 8 vCPUs and 32 GiB of guest memory.

The `pod-connected-acceptance-<run>-<attempt>` artifact retains image identity,
authenticated attestations/status, public certificates, negative-probe receipts,
bounded boot logs and cleanup results for seven days. Acceptance requires both
the exact expected-digest checks and the timed observations. Failure artifacts
include bounded CLI errors and separately labeled diagnostic attestations;
those diagnostic reports cannot satisfy acceptance. Completion requires
`result.json` with `passed: true` and `cleanup.json` with `complete: true`, plus
a successful workflow. Cleanup always removes owned resources; `keep_cvm` does
not apply. Select exactly one Pod mode per dispatch.

This lane validates static Pods on native KubeVirt TDX hardware. Cloud API
provisioning and Kubernetes provider assignment, discovery and deletion remain
separate acceptance work. Guest exclusion checks observe connection denial;
the privileged Linux suite supplies controlled listener and source-NAT checks.

### Diagnosing Pod runtime startup on TDX

The manual input `pod_runtime_diagnostic: true` uses separate immutable pins in
`.github/scripts/fixtures/pod-connected/development-image.json` and the same real
CDS/two-Pod provisioning. It collects bounded systemd unit, journal, CRI and
containerd-plugin observations through the run-owned Pod consoles. Private raw
console transcripts are not uploaded; public evidence contains fixed projections
with sensitive records omitted. UID checks bind observations and cleanup to the
resources created by that run.

Runtime diagnostics use their own serialized workflow queue and request eight
CPUs and 32 GiB of guest memory, plus virtualization overhead. Scheduling is
bounded; unavailable capacity fails the run and triggers cleanup. Terminal
control sequences are removed before parsing the projected console records;
framing failures retain counts only, without publishing raw console text.

```sh
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref podcvm/no-mesh-gate -f pod_runtime_diagnostic=true
```

The development image has different measurements and bypasses `c8s-runc` through
`60-dev-runc.toml`. Its outcome is diagnostic-only and cannot satisfy production
acceptance. The runner does not perform the timed acceptance observations.
The `pod-runtime-diagnostic-<run>-<attempt>` artifact retains public observations
and the cleanup receipt for three days. A complete diagnostic run requires
`captureComplete: true` and cleanup `complete: true`; neither means the Pod
workload passed. Cleanup always runs, and `keep_cvm` does not apply.

### Diagnosing a Pod boot on a commit's dev image

The manual `tdx-metal-e2e.yml` input `pod_diagnostic: true` boots the
`rke2-tdx-dev` image published for one commit (root autologin on the serial
console, its own measurement) with the Pod fixture signed by the CLI built from
that same commit, so the serial log shows which unit or admission step stops a
Pod that the production image only reports as Pending. `pod_image_source`
names that commit by full SHA; empty means the dispatched commit. The lane
resolves `rke2-tdx-dev-<sha7>` and `rke2-tdx-dev-cdi-<sha7>` from the registry
at run time and fails by naming the missing tag, with the manual image build
command that publishes it. The fixture Pod carries no mesh endpoint; the guest
injects the measured one.
The job builds the paired CLI from `pod_image_source` and the lane tool
(`test/poddiag`) from the dispatched commit with the source commit's Go toolchain,
so the dispatched tree's `go` directive must not exceed the source's.
It uses the existing TDX launcher, a private root import and run-owned VM and
launch Secret. Cleanup always runs; `keep_cvm` does not retain diagnostic VMs.
The `pod-boot-diagnostic-<run>-<attempt>` artifact contains the first and last
256 KiB of the serial log per sample (`NNN-serial`, `NNN-serial-tail`; a dev
image forwards its journal to ttyS0, so the tail carries the latest service
output), bounded launcher logs, image identity, native status and the cleanup
receipt. It omits
private signing keys and expires after seven days.

```sh
gh workflow run c8s-image-manual.yml --repo confidential-dot-ai/C8s \
  --ref <branch at the commit> -f dev=true -f c8s_ref=<sha7>
gh workflow run tdx-metal-e2e.yml --repo confidential-dot-ai/C8s \
  --ref <branch with this lane> -f pod_diagnostic=true -f pod_image_source=<full sha>
```

This mode diagnoses boot only. It deliberately uses an unavailable CDS and a
separately measured development image; it does not establish production-image,
mesh, internet or DNS acceptance. The normal node lane and automatic exact-image
acceptance keep their existing validation.

## Running it

```sh
make test-integration-cluster
```

This mode diagnoses boot only. It deliberately uses an unavailable CDS and a
separately measured development image; it does not establish production-image,
mesh, internet or DNS acceptance. The normal node lane and automatic exact-image
acceptance keep their existing validation.

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

A driver that should not depend on those helpers directly, such as the
conformance steps in `test/conformance/steps`, uses the fixed question-and-answer interface of
[`test/conformance/backends/kind.sh`](../test/conformance/README.md) instead;
the metal lanes offer the same interface through `metal.sh`.

### Failure notes

- A pod stuck `CreateContainerError` with `image not in allowlist` is the NRI
  plugin doing its job: the image's containerd store digest has no bootstrap
  entry. The entries are written from the node's image store before install,
  so an image first pulled *during* the run lands here — pre-pull it next to
  the other fixtures in run.sh.
- The mock-attestation deployment is `Recreate` on purpose: two hostNetwork
  pods cannot both bind :8400 on a single-node cluster.
