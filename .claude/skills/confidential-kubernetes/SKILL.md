---
name: confidential-kubernetes
description: Use when working in the C8s (confidential Kubernetes) codebase, or on anything that crosses its trust boundary - attestation, armTLS and the per-pod mesh, the Certificate Distribution Service (CDS), SEV-SNP or TDX confidential VMs, the measured worker, Pod CVM or CDS guest images, launch configuration, the admission plugin and allowlist, c8s-runc and exec denial, the router and its attested handshakes, secrets, or encrypted volumes.
---

# Confidential Kubernetes (C8s)

C8s runs Kubernetes workloads inside confidential VMs, so a tenant's weights,
prompts and secrets stay in TEE memory on hardware the tenant does not own.

This file is a map: where each topic is documented, how the code is laid out, and
the facts that are easiest to get wrong. It was checked against `5f9f3784d`
(2026-11-13). **The code is authoritative, then the pages below. Where this file
disagrees with them, follow them and say in your hand-off that this file is
stale.**

## Read first

| File | Owns |
|---|---|
| `AGENTS.md` | How to work here: process, hand-off, what needs authorization |
| `docs/overview.md` | Trust boundary, what runs where, CVM modes, the life of a confidential pod |
| `docs/glossary.md` | The one name for each concept; use these names in code, docs and PRs |
| `docs/guarantees.md`, `docs/security-model.md` | The six promises, what enforces each, where a CVM mode is weaker |
| `docs/engineering-standards.md` | PR shape, code style, comments, testing and documentation rules |
| `docs/review-guide.md` | What a correctness and security review checks |
| `docs/README.md` | Index of every page, by subject and by reader |

Then read the README beside the code you change: `images/node-guest/`,
`images/cds-guest/`, `charts/*/helpers/`, `cmd/get-cert/`, `cmd/armtls-mesh/`,
`test/conformance/`.

The terms used below (leaf, member pod, sandbox token, admission inventory, base
allowlist, workload entry, platform role, route manifest) are defined in
`docs/glossary.md`. "The operator" is the person who holds the operator key;
`c8s operator` is a process.

## Mental model

- **The trust boundary is the TEE.** Inside: the measured node software, the pods
  it admits, and the CDS. Outside, and adversarial: the host and hypervisor, the
  Kubernetes control plane in every CVM mode, the pod network and the internet.
- **The host can launch genuine TEEs of its own.** "A TEE answered" proves
  nothing, so a verifier names the measurements it accepts: its pins.
- **Kubernetes objects are not attested.** What decides whether code runs and what
  it may hold sits in the node CVM, below the API server: the admission plugin
  and, on the measured image, `c8s-runc`.
- **Identity is hardware evidence plus an allowlist match.** A leaf proves a key
  generated in the TEE, the node image that booted, and the workload entry the
  pod's containers matched. Names, namespaces and service accounts confer no
  identity.
- **A node is one trust domain.** Its pods share its TEE. Tenants that distrust
  each other belong on separate nodes.
- **The CVM modes are not equal.** The full node-side defence exists only on the
  measured worker image. On `gke` and `aks` the base allowlist and the plugin's
  mode are chart values a cluster administrator can write, and the node
  host-privilege policy is off; `docs/guarantees.md` calls an install on a
  provider's stock node image test and evaluation.
- **"Works on an ordinary cluster" is not the bar.** A change must hold with the
  host and the control plane as adversaries. A test on a mock or a plain cluster
  proves only what it exercised.

Five principles apply at every layer (`README.md`): encrypt the runtime, measure
the code, bind identity to measurement, verify before connecting, secure the
egress. Out of scope: availability, side channels, physical attacks.

## Shapes

The docs call the node shape the CVM mode: `bare-metal` (the measured worker
image), `gke` or `aks`.

- **CDS.** A measured VM outside the cluster (`images/cds-guest`), booted on the
  configuration `c8s cds config new` writes and pinned by the `cds-pin.json`
  written with it. No chart deploys it, and only test harnesses run it as a
  container. It runs as one VM, or as replicas that share
  state over a replicated log and take operator-signed decrees
  (`docs/cds-ha.md`). It calls back to each node's admission inventory on TCP
  1019.
- **Cloud.** `c8s install --platform aks-snp|aks-tdx|gke-snp` deploys
  `charts/cloud` onto the provider's confidential VMs (`docs/operator.md`;
  `docs/cloud-cds.md` for where that cluster's CDS runs).
- **Cluster of workers.** Every node boots the measured worker image
  (`images/node-guest/worker`) on a `worker.yaml` that `c8s worker new` writes and
  the node's evidence binds by digest. The control plane and `c8s operator` run
  outside every TEE (`docs/launch-configuration.md`).
- **Pod CVM.** One measured VM per pod, TDX only (`images/node-guest/pod`),
  scheduled by an optional provider in the operator
  (`docs/pod-cvm-provider.md`).

## Code map

Every image ships the one binary built from `cmd/c8s`, each with its own
entrypoint. `cmd/get-cert`, `cmd/armtls-mesh`, `cmd/nri-image-policy` and
`cmd/c8s-runc` are thin mains over the same packages, and the directories under
`cmd/` hold the role images' Dockerfiles. A command is a package under
`internal/cmds/<name>`. The exceptions are `launch-config` (`internal/podlaunch`)
and the commands defined in `cmd/c8s` itself: `install`, `uninstall`, `operator`,
`node-image`, `node-services` and `worker control-plane`.

| Role | Runs in | Code |
|---|---|---|
| `cds` | the CDS VM | `internal/cmds/cds`, `internal/cdsha`, `internal/issuer`, `internal/secrets`, `internal/allowlist` |
| `operator`: controllers, `pod-injector`, `pod-validator`, Pod CVM provider | a cluster pod on cloud; a host process beside the control plane in a cluster of workers | `cmd/c8s/operator.go`, `internal/controller`, `internal/webhook`, `internal/podprovider` |
| `nri-image-policy`: admission plugin, admission inventory, packet rules | the node host | `internal/cmds/nri-image-policy`, `internal/podmesh` |
| `c8s-runc`: privilege floor, exec denial | measured images | `internal/cmds/c8srunc` |
| Sidecars: `get-cert` (`c8s-cert`), `armtls-mesh` (`c8s-mesh`), `probe-file` (`c8s-cert-wait`), and when a pod asks for them `get-secret` (`c8s-secret`) and `get-volume` (`c8s-volume`) | every member pod | `internal/cmds/{getcert,armtlsmesh,probefile,getsecret,getvolume,sidecar}` |
| `cds-attest`, `allowlist-proxy`, `acme` | the router pod | `internal/cmds/{cdsattest,allowlistproxy,acme}`, `pkg/overenc`, `pkg/routes` |
| `volumed`, `attest-proxy`, `volume attach\|detach` | the node | `internal/cmds/{volumed,attestproxy,volume}` |
| `worker stage`, `launch-config stage`, `node-services`, `pod-status` | guest boot | `internal/cmds/{worker,nodeservices,podstatus}`, `internal/podlaunch` |
| Operator CLIs: `keys`, `measurements`, `allowlist`, `routes`, `secrets`, `volume create`, `verify`, `cds verify\|ca\|config\|ha` | the operator's machine | `internal/cmds/{keys,measurements,allowlist,routes,secrets,volume,verify,cdsca,cdslaunch,cds}`, with `internal/cmds/cdsconn` for the CDS connection |

Shared libraries: `pkg/armtls` (TLS configs, pins, certificate extensions),
`pkg/workloadclaims` (inventory socket and sandbox token), `pkg/allowlist`
(entry matching), `api/v1alpha2` (the CRD). Charts are `charts/cloud`,
`charts/worker`, `charts/control-plane` and `charts/lib`, embedded by
`charts/embed.go`. Guest images are under `images/`, harnesses under `test/`.

Hardware evidence is produced by the node-local `attestation-api`, which is built
outside this repository. armTLS peers and CDS verify evidence through it. `c8s
verify`, the operator CLIs (through `cdsconn`) and the operator's Pod CVM
provider verify in-process with the attestation-go library
(`internal/localverify`, `internal/guestverify`).

## Easy to get wrong

How the system behaves today, where older descriptions and habits from ordinary
Kubernetes mislead.

1. **Injection is by namespace, not by annotation.** `pod-injector` shapes every
   pod in a namespace its selector admits, and `pod-validator` admits only that
   final shape. `confidential.ai/cw` names the workload (its Service, its label
   and the SAN it requests); it grants nothing.
2. **The mesh is per pod.** The node installs packet rules in the pod's network
   namespace and the `c8s-mesh` sidecar carries the pod's TCP over armTLS. No
   node-level proxy exists. `docs/armtls.md` lists the few destinations that stay
   uncaptured.
3. **armTLS has two paths and never mixes them.** Evidence path: a peer presents
   a self-issued certificate carrying evidence, which the other side checks
   against its pins on every handshake: the server's for CDS, both sides' for the
   admission inventory. Chain path: both sides present a leaf the mesh CA signed,
   as pod to pod. A leaf that does not chain is rejected, never retried against the
   evidence it embeds.
4. **Stamped certificate fields are the CA's word, not the hardware's.** Sandbox
   ID and matched workload mean something only on a leaf verified against the
   mesh CA. A handler that reads them sets `ServerConfig.ClientCA`, not
   `ClientPolicy`. CDS does both jobs: clients check its evidence against pins,
   and it checks a client's leaf against its own mesh CA.
5. **A leaf is named only on a unique match.** CDS stamps the entry name when
   exactly one entry matches every container the pod has run. A pod that also ran
   a container from another entry renews unnamed, and a container the node
   refused costs the sandbox its identity (`docs/getcert-workload-binding.md`).
6. **Secrets and volume keys arrive after the main containers start.** Each
   release needs the pod's leaf, a fresh sandbox token, exactly one matching
   entry and a grant for the path (`docs/secrets.md`, `docs/volumes.md`).
7. **Policy is replaced whole, never merged.** An allowlist write is one
   versioned document under a single-use operator signature over the method,
   path and body. Nodes apply it after a delay, then stop any running container
   it no longer admits.
8. **A one-VM CDS keeps nothing across a restart.** Its state is in memory and on
   a tmpfs: a restart loses the mesh CA, the secrets, operator-written entries
   and the route manifest, and voids every leaf. A replica set keeps them while a
   majority stays up; past that, only a `recover` decree on a surviving voter
   does (`docs/operator.md`, `docs/cds-ha.md`).
9. **The router routes application requests only by the operator-signed route
   manifest** (`docs/operator.md`, `docs/routes-evidence.md`).
10. **A worker document is unsigned and holds no secret.** Its digest in the
    hardware report is what binds it. The bootstrap token beside it on the launch
    disk is outside the measurement.
11. **The worker image refuses entry into a running container.** The kubelet
    serves no exec, attach, port-forward or logs, and `c8s-runc` denies every
    exec the measured base does not grant; the worker's base grants none
    (`docs/node-exec-mode.md`). Member-pod probes are HTTP
    (`internal/podmesh/probes.go`), and an exec probe or a `preStop` exec hook
    cannot work.

## Invariants

What a change must preserve. The page or code named owns the detail.

1. Verify evidence before trusting any claim in it. The `attestation-api` verdict
   is unsigned, so it is reached only on the node itself, through the node's Unix
   socket or guest loopback. `c8s cds` refuses a non-loopback URL and
   `cmdsutil.RequireNodeVerifier` holds the pod-side clients to the node socket;
   keep a new caller behind the same checks (`docs/armtls.md`).
2. A verifier names a guest. Inside the cluster, and in the CLIs that dial CDS,
   an empty pin set is refused rather than read as "any TEE"
   (`docs/armtls.md`). On TDX, guest identity needs RTMR[1] and RTMR[2]; SEV-SNP
   has one launch digest per vCPU count (`docs/measurements.md`). Take pins
   through `cmdsutil.BindImagePolicyFlags` and compare them with
   `armtls.EnforceImages`, never field by field in new code.
3. For an armTLS connection use the `pkg/armtls` constructors:
   `NewServerTLSConfig`, `NewClientTLSConfig`, `NewMeshServerTLSConfig`,
   `NewMeshClientTLSConfig`, `NewVerifyingHTTPClient`, or the refreshing clients
   built on them such as `NewRefreshingHTTPClient`. They keep the evidence and
   chain paths separate and never resume a session.
4. Inside the cluster, secret values, the mesh CA key, pod keys and volume
   plaintext exist only in TEE memory, never as a Kubernetes object or in the
   clear on a host disk (`docs/guarantees.md`). Do not move one into an
   environment variable, an argument list or a log.
5. Admission keys on the image digest, fails closed and holds below the API
   server. An entry with no command-line policy requires an empty command line,
   one with no mounts policy denies mounts, and one with no environment policy
   allows any environment (`docs/allowlist-entries.md`).
6. Platform roles, `node_tcb` and granted execs come only from the plugin's boot
   configuration (measured on a worker, chart-rendered on cloud), never from a
   served allowlist. What a served entry may grant is in
   `docs/allowlist-and-capabilities.md`.
7. Every runtime handler the worker image offers ordinary pods is wrapped by
   `c8s-runc`. `make test-node-guest-image-containerd` checks it
   (`images/node-guest/tools/README.md`).
8. A measurement is exact: any change to a measured input changes it (see
   *Measured inputs*). Images are referenced by digest.
9. Certificate extensions live under OID arc `1.3.6.1.4.1.66378.1`, and a retired
   number is never reused. `docs/certificate-extensions.md` is the registry.

## Unsafe switches

Each of these weakens a guarantee. A measured worker sets none of them. A cloud
install sets some by default (the plugin's `policy.sandbox: off`, the provider's
exempt namespaces), which is one reason it is not the production shape.

- Chart: `nriImagePolicy.policy.mode: audit`; `nriImagePolicy.policy.exemptNamespaces`
  with `exemptRepositories`; `controlPlane.webhook.extraExcluded`.
- Admission plugin boot configuration: `policy.sandbox: audit|off`,
  `policy.deny_missing_annotation: false`, `policy.enforce_existing: false`.
- CLI: `--insecure` on `allowlist`, `routes`, `secrets` and `volume`;
  `c8s verify --allow-debug`, and `c8s verify` with no measurements; `--force` on
  `install`, `uninstall`, `allowlist upload`, `secrets put` and `volume create`;
  `get-cert --no-workload-claims`.
- Builds: `c8s-runc` linked in debug mode; the `c8s_dev` build tag; a guest image
  built from an unpublished binary (`C8S_BINARY`, `C8S_IMAGES_DIR`) or with an
  added profile such as `ssh`.
- TDX node pins without RTMRs, which CDS accepts with a warning.
- The mock services under `test/`.

## Working in the repo

`AGENTS.md` and `docs/engineering-standards.md` own the rules. This section
covers what they leave to discovery.

**Checks.** Go 1.27.3. At the repository root run `make build`, `make test`
(race, every module in `go.work`) and `make lint` (gofmt and vet), then
`golangci-lint run` (CI pins 2.14.0; no make target runs it) and
`make check-crd-chart`. The slim node build must compile too:
`make build-c8s-node`. Harnesses are in `docs/integration-tests.md`.

**Local traps.**

- Use `umask 022`. Under `0002` the capability tests in `internal/cmds/c8srunc`
  and `internal/cmds/nri-image-policy` fail.
- Use helm v3 (CI: v3.14.4). Chart and install tests fail without `helm`, and
  `TestRouterRejectsInvalidValues` fails under helm v4.
- `make manifests` needs controller-gen v0.20.1: the CRD records the generator
  version.
- Many tests skip without root, `KUBEBUILDER_ASSETS` or particular capabilities,
  and the CDS replication tests need `-tags integration`. Read what skipped
  before trusting a green run.

**Add a command.** Create package `internal/cmds/<name>` exporting
`NewCmd() *cobra.Command`, and register it from a one-line `init()` in
`cmd/c8s/<name>.go`. `test/workflows/command_imports_test.go` refuses a new import
of cobra or of a command package from outside `cmd/` and `internal/cmds/`. Tag the
registration file and its tests `!c8s_node` when the slim node binary must not
carry the command, as `install`, `operator` and `cds` are;
`scripts/shipped-deps-guard.sh` checks what that binary links. Require flags with
`cmdsutil.RequireFlags`, and reuse `cmdsutil.BindImagePolicyFlags`,
`cdsconn.BindFlags` and `sidecar.BindFlags`. Return `*cmdsutil.ExitStatusError`
for an exit status other than 1.

**Add a server or sidecar.** Copy `internal/cmds/allowlistproxy`: `NewCmd`, then
`run`, then `runContext` with an injected listener. CDS is the full-size case.
Use `http.ServeMux`, `log/slog`, `cmdsutil.ShutdownOnDone` and the
`internal/httputil` error helpers.

**Add or change a component image.** Add one entry to
`charts/lib/files/components.yaml`, list its pod-spec template in
`c8s.componentPodTemplates` (cloud chart) or `worker.componentPodTemplates`
(worker chart), and declare any new value in that chart's `values.schema.json`,
which is closed. Each rendered container becomes an exact allowlist shape, so a
component digest with no rendered container fails the render
(`charts/lib/helpers/allowlist/README.md`).

**Change the CRD.** After editing `api/v1alpha2`, run
`make manifests generate check-crd-chart`.

**Measured inputs.** These are baked into the worker image, so changing one
changes its launch measurement:

- everything under `images/node-guest/` except tests, tools, docs and `pod/`;
- `charts/worker/files/static-pods/` and `charts/lib/files/router-nginx/`;
- the allowlist floor rendered from `charts/worker`;
- the builder and `attestation-api` pins in `.github/build-pins.json`;
- the `c8s` binary and the component digests, so each release has its own
  measurements.

When a PR touches the image sources, those chart files or the build pins, the
`image-repro-gate` workflow builds the image twice and requires the two builds
to match. Production pins come from
`c8s measurements derive` on published images, never from a gate build
(`images/node-guest/README.md`).

**Docs are checked.** A test renders the helm examples in `docs/operator.md`, and
`scripts/check-doc-install-commands.sh` runs the `c8s` commands in `docs/DEMO.md`
as far as they go without a cluster.

**Releases.** The squashed PR title decides: `fix` cuts a patch release, `feat`
or `!` a minor one while the project is on v0, any other type none
(`docs/releases.md`).

## Renamed or removed

These components, packages and options are gone. Older documents, forks and
model knowledge still use the names, and a few linger in stale comments and
error strings. Do not reintroduce them.

| Gone | Today |
|---|---|
| RA-TLS, `pkg/ratls`, the `ratls-mesh` node DaemonSet | armTLS, `pkg/armtls`, the per-pod `c8s-mesh` (`cmd/armtls-mesh`) |
| A CDS Deployment in the chart | The CDS VM and `c8s cds --config`; a cloud install names it with `--cds-address` and `--cds-pin` |
| `c8s install --cvm-mode` | `c8s install --platform`; bare metal is the worker image and `c8s worker` |
| Server CVMs, a control plane in the guest, a signed `launch.yaml` for a node, `launch-config new\|add-agent` | A control plane outside every TEE and `worker.yaml`; `launch-config` and a signed `launch.yaml` serve the Pod CVM only |
| `c8s get-kubeconfig`, `c8s render-values` | Nothing |
| `internal/helmchart/c8s`, `c8sComponents` | `charts/`, `charts/lib/files/components.yaml` |
| The `node-guest-image/` directory | `images/node-guest/` |
| `confos-pod-exec`, `cw-label-integrity`, `hostNamespacePolicy.*` | Kubelet handlers off plus `c8s-runc`; `pod-validator`; the cloud chart's `<release>-deny-host-namespaces`, which has no switch |
| `router.publicTLS.mode` | The front-door mode; the charts set `cds` or `acme` |
| Evidence fallback in the mesh, `RequireCAEvidence`, `CheckWorkloadPin` | The chain path alone; `MatchedWorkloadFromCert` |
| Empty pins meaning "any genuine TEE" inside the cluster | Empty pins are refused there |
| kata, peer-pods, `tls-lb`, `tee-proxy`, `/sign-csr`, `/attest-key`, `/handshake`, EAR and JWKS signing, OID arc `59888`, the admission plugin's push mode | Nothing; the per-pod VM today is the Pod CVM |
