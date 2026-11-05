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

## Pod Cloud acceptance

The Cloud lane launches signed `c8s-launch/v2` Pod guests and a dedicated
measured CDS guest through the Cloud API and verifies them through their own
attested interfaces. It requires deployed Cloud API/operator support for
`launchFile` and separately admitted `c8s-pod` and `c8s-cds` artifacts; catalog
changes alone are insufficient. [Launch and cleanup requirements](../test/integration/pod-cloud/README.md)
include the exact wire contract. There is no Kubernetes control plane in this
lane: the harness signs each launch document, assigns Pods to generic guests
and deletes guests itself, so it exercises the guest and Cloud contracts, not a
scheduler.

The runner tool's own tests drive `run.sh` against process doubles: the test
binary stands in for docker, go, git and timeout. They are excluded from the
race build, because each run forks that binary dozens of times, and `make test`
runs the package separately without the detector. The harness's offline tests
(`go test -tags pod_cloud_integration -run '^TestCloudAcceptance' ./test/integration/pod-cloud/acceptance`)
cover ownership, ledger-before-POST, boot-wait termination, assignment fencing
and cleanup against local HTTP doubles; CI runs them in the Pod Cloud acceptance
(offline) job.

The live lane needs Go, Docker, jq and GNU timeout, an authorized Cloud
credential, and an admitted matching production Pod/CDS image pair. Every
invocation, cleanup included, builds the runner tool in `test/integration/pod-cloud/tool`
from the current checkout for the host lock and private markers. Supply an
absolute JSON input path with these fields:

```json
{
  "source": "<40-character production source commit>",
  "cloudURL": "https://api.cloud.confidential.ai",
  "tokenFile": "/private/path/cloud-token",
  "image": "c8s-pod@<version>",
  "cdsImage": "c8s-cds@<same-version>",
  "manifestFile": "/private/path/manifest.json",
  "manifestDigest": "sha256:<manifest digest>",
  "diskDigest": "sha256:<Pod raw disk digest>",
  "cdsManifestFile": "/private/path/cds-manifest.json",
  "cdsManifestDigest": "sha256:<CDS manifest digest>",
  "cdsDiskDigest": "sha256:<CDS raw disk digest>",
  "cliFile": "/private/path/matching-linux-c8s",
  "cliSHA256": "<64-character digest>",
  "probeFile": "/private/path/linux-pod-mesh-probe",
  "probeSHA256": "<64-character digest>",
  "meshImage": "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:<digest>",
  "size": "s1.2x",
  "location": "us-west-1",
  "vCPUs": 2,
  "memoryMiB": 8192
}
```

Build the CLI from the production image's source and the probe from
`test/integration/pod-cloud/probe`, both for the Docker daemon's Linux
architecture. The two manifests and raw disks are independently pinned
artifacts from the same production source; they must not share hashes. The mesh
image and matching CLI also come from that source. The runner checks file
digests and catalog identity; the caller supplies publication provenance.
Source/build evidence must cover both ordinary images, with development and
recovery-overlay modes disabled.

Bootstrap creates a raw measured `c8s-cds/v1` configuration with `c8s cds config new`
and authenticates its CA on port 8443 using the generated image/configuration pin.
Every scenario requires unsigned writes and writes signed by the Pod and unused
server authorities to be refused by the authenticated CDS, while its complete
initial policy stays unchanged. The CDS policy-write key is separate from both
authorities. Private `cds-access.json` records those refusals; connection
failures and unrelated HTTP errors cannot pass.

The acceptance binary runs in a disposable read-only container of the cluster
harness's digest-pinned node image, with the state directory bind-mounted. The
state directory must therefore be under a host path shared with the Docker
daemon. For Colima or another Docker VM, use a path configured in that VM's
mounts, such as a shared checkout's `target/` directory; `/private/tmp` is not
necessarily shared. The runner compares a fresh host nonce and the binary's
SHA256 inside a container before starting any Cloud work. A failed mount check
leaves only local setup, which the cleanup command recognizes.

```sh
export C8S_PODCLOUD_LIVE=1
export C8S_PODCLOUD_INPUT=/private/path/input.json
export C8S_PODCLOUD_STATE=/absolute/docker-shared-checkout/target/new-run
make test-integration-pod-cloud
```

The default `connected` scenario creates one CDS guest and two Pod guests. The
harness records each launch on its ownership ledger before the Cloud POST,
waits for each guest to run, attest and present its endpoints, then checks
exact measured workloads, authenticated status, readiness withdrawal and
recovery, peer mesh traffic, HTTPS and DNS egress, certificate renewal over at
least 65 minutes, rejected unauthenticated traffic, and deletion through the
Cloud API with confirmed termination. It reuses the connected native lane's
acceptance predicates. The run requires at least six Cloud vCPUs and 24 GiB of
memory with the example shape; provisioning and cleanup add time to the
observation window.

Set `"scenario": "warm-assignment"` to test generic boot and a one-shot
assignment. This needs a paired image containing the generic assignment guest,
plus capacity for CDS and one guest (four Cloud vCPUs and 16 GiB with the
example shape). The harness launches an unassigned guest, verifies empty
attested measurements and no Pod authority while it idles with only the
pod-status ingress, then assigns one Pod to it over the key-pinned assignment
channel. The exact signed assignment is persisted before its POST, a
conflicting signed assignment for another Pod UID must be rejected, the
application ingress is added afterwards, and authenticated readiness, exact
workload digests and a stable leaf over two minutes complete the proof.
Deletion confirms Cloud termination, and no assignment POST may follow
verified readiness. Private evidence includes the signed assignment and must
stay private.

Set `"scenario": "cds-outage"` to test retention of an authenticated CDS policy
update through a network outage and one application restart. It needs one CDS
guest and one Pod guest (four Cloud vCPUs and 16 GiB with the example shape).
The immutable Pod launch policy and initial measured CDS configuration admit only
the mesh. Before adding the app rule, the harness verifies the complete
authenticated export against that measured policy, then freezes the baseline
and verifies the absence of any app admission. The signed app update precedes
the launch. The harness removes only the run-owned CDS ingress on port 8443 and
waits for the change to apply; during the outage it retains Cloud ownership and
boot checks plus authenticated Pod observations. The app first proves CDS
reachability, then requires 120 seconds of continuous connection failures
before its one controlled exit. Acceptance requires fresh admission during the
outage, unchanged guest boot and mesh identity, and exact measured digests. The
harness restores the original ingress and endpoint, authenticates the same CA,
deletes the signed app rule and observes at least 70 seconds without
readmission, with readiness withdrawn, before owned deletion and cleanup.

Set `"scenario": "cds-renewal-outage"` for the same two-VM setup with an outage
spanning certificate renewal. The production guest schedules renewal at most one
hour after issuance; this lane keeps the owned CDS ingress closed for at least
65 minutes. The harness requires authenticated task/boot/assignment continuity
and an unchanged leaf throughout that interval. Restoring ingress must restore
readiness and produce a new serial and SPKI under the same CDS CA within 25
minutes. Signed revocation and 70 seconds without readmission finish the test
before owned deletion and confirmed cleanup. This proves renewal after temporary
unavailability, not leaf expiry, guest service restart, CDS process restart or
multi-replica HA.

These scenarios compile the current checkout's harness. Its commit, dirty status
and executable hash are recorded in `acceptance-build.json`; the result's hash
must match the executable that ran. The input `source` identifies the paired
guest/CLI publication. Preflight refuses a legacy shared Pod/node-CDS image pair.
The `warm-assignment` scenario requires the generic guest in its pinned image; a
successful connected run does not establish warm-assignment acceptance. The
live runner stops boot polling promptly if a guest stops, fails or reboots
before acceptance; the private `boot-failed-<side>.json` preserves the bounded
failure reason.

The state directory contains credentials and signed launch material. Keep it
private and never upload it as a CI artifact. Ownership is persisted before
Cloud creates. On interruption, retain the directory and resume cleanup:

```sh
export C8S_PODCLOUD_LIVE=1
export C8S_PODCLOUD_STATE=/absolute/docker-shared-checkout/target/existing-run
make cleanup-integration-pod-cloud
```

Cleanup reuses the run's original `acceptance.test` and ledger and deletes only
the Cloud instances that ledger owns, confirming each termination. If the host
shell died while a container of the run was still active, cleanup refuses until
that container is gone.
