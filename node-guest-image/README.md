# node-guest-image

The c8s node image (`node-guest-base`, `rke2[-cdi]-*` tags), defined in THIS repo
and built by [confidential-os-builder] acting purely as a builder.
Tracking issue: [#264].

Layout:

- `c8s/` — the mkosi profile (config, `mkosi.extra/`, `mkosi.sync`).
  Staged into the confos build via
  `confos build --profile-dir` (confos ≥ the release carrying
  confidential-os-builder#81); the dir basename **is** the profile name, so
  it must stay `c8s`.
- Platform: `build` requires `C8S_PLATFORM=tdx|snp`. Both roles share the
  same image for the selected platform and VM shape. Platform-specific
  service settings, node labels, measurement policy and image artifacts are
  generated at build time; TDX and SNP do not share a measurement or image
  digest. SNP also has one launch digest per supported vCPU count. Both
  platforms support operator-key-bound launch configuration and credential
  release: TDX binds the public key in RTMR[3], SNP in HOST_DATA.
- `kernel/` — the guest-kernel config fragments (`c8s.config`,
  `c8s-dev.config`), passed via `--kernel-config-fragment`.
  confos's `required`/`hardening`
  baselines stay in confos: a fragment request that conflicts with them
  fails the build (see the balloon catch in #263).
- `build` — drop-in replacement for confos's `bin/build-c8s`: same env
  contract (`C8S_PLATFORM`, `C8S_REF`, `C8S_REGISTRY`, `C8S_DEV`, `C8S_NAME`, `C8S_MEMORY`) and the same profile stack
  and order; only the c8s profile content and kernel fragments come from
  here. Point `CONFOS_DIR` at a confos checkout (default: a sibling dir).

  The locked image keeps the kubelet debugging handlers on so `kubectl logs`
  works for every kubeconfig holder, and bakes the `pod-exec-policy.yaml`
  AddOn so `kubectl exec`, `attach`, `port-forward` and `debug` (ephemeral
  containers) are denied in admission for everyone, the operator included, 
  and routes every ordinary pod through the measured
  runtime wrapper, which denies `runc exec` outright — see
  [Post-start exec](#post-start-exec).
  `C8S_DEV=1` skips that AddOn (with the serial autologin), at a different
  measurement.

## Launch requirements

The `node-image` domain in [`.github/build-pins.json`](../.github/build-pins.json)
pins the confos commit the image builds with. Every pin since
[confidential-os-builder#120](https://github.com/confidential-dot-ai/confidential-os-builder/pull/120)
includes its immutable root.
The independent `kata-guest` and `kernel-snapshot` pins stay unchanged. The
node-image invariant gate requires immutable-root support by default and CI
sets `EXPECT_IMMUTABLE_ROOT=1` explicitly.

Every node VM needs a write-storage disk with virtio-blk serial
`confai-scratch`, at least 64G. The serial is what matters: the confos
initrd scans `/dev/vd{b,c,d}` for it and ignores labels. In KubeVirt that's
`disk: {bus: virtio}` plus `serial: confai-scratch` (see the vendored
`tdx-metal-e2e.yml`); confidential-metal attaches one by default
(`--datadisk-gi`, 0 opts out).

The initrd encrypts the disk and, via a dm mapping named `scratch`, backs
writable overlays for directories declared by the measured image. The root
and undeclared paths stay read-only. In addition to the base state directories,
this profile declares `/etc/rancher`, `/etc/cni`, `/opt/cni` and `/etc/nri` in
`/usr/lib/confai/state.d/60-c8s.conf`. All runtime state disappears on reboot.
Without the disk
the initrd falls back to a 2G RAM tmpfs: the guest comes up Ready, then
wedges once RKE2 fills it — a flapping node, not a boot error.
`scratch-enforce.service` closes that hole by checking for the dm mapping
and powering the VM off before rke2 starts. It also verifies the crypt UUID and
`confai-scratch` backing device, then writes boot-local provenance under
`/run/c8s/scratch-provenance.json` for NRI mount classification.

Every boot also requires an ISO labelled `opkeydata` with these three files
at its root:

- `pubkey`: the launch public key for this cluster and role. The measured
  initrd stages the exact PEM bytes in read-only `/run/confai`, exposed through
  `/etc/confai/operator-pubkey`, and binds them into TDX RTMR[3]. An SNP
  launcher must set HOST_DATA to the SHA-256 of
  those same bytes.
- `launch.yaml`: the strict `c8s-launch/v1` document selecting `server` or
  `agent`, the image measurements, cluster/node identity, join tokens,
  trusted role keys and TLS SAN.
- `launch.yaml.sig`: the detached signature over those exact bytes.

`c8s node launch-config new` writes all three for a server and its agents,
with distinct server and agent keys and fresh tokens per cluster
(`c8s node launch-config add-agent` extends a bundle later; `c8s keys
sign-launch` re-signs a hand-edited document). The private keys stay with
the operator. Agents receive only the
RKE2 agent token; their documents must omit the server token entirely.
There is no diskless/default-server boot. Missing or invalid signed input
fails the role gate before RKE2 or core services can start.

See [Authenticated launch configuration](../docs/operator.md#authenticated-launch-configuration)
for complete server/agent bundle creation, image-manifest extraction,
ISO and KubeVirt attachment examples, and the exact schema. A server may
omit its address to use `node.ip` or primary-interface IPv4 autodetection;
an agent must specify the server's reachable IPv4 address. Switching roles
requires relaunching with the new role's authorized bundle and launch key.

Additional optional disks:

- serial `confai-containerd` (or label `containerd`): backs containerd's
  image cache (`containerd-data-disk.service`).
- serial `confai-models`: a pre-populated, read-only weights disk mounted at
  `/var/lib/models`. It is unencrypted and host-writable; attach public
  weights whose digests the workload verifies (`models-disk.service`).

## Operator kubeconfig bootstrap

After launching the server with its signed `opkeydata`, use the matching
image manifest and server private key to obtain a kubeconfig:

```sh
c8s get-kubeconfig --node "$SERVER_IP" \
  --operator-key demo/server.key --image-manifest manifest.json \
  --out demo/kubeconfig --release-wait 5m
```

Bootstrap uses the RA-TLS credential service on port 8443 for both the
operator-authenticated nonce attestation and credential release. The raw
attester stays on loopback. The client verifies the full image and launch-key
binding in both the serving certificate and the fresh report before requesting
credentials. Port 6443 is the Kubernetes API; `--release-url` and
`--apiserver-url` support forwarded ports. The credential listener starts only
after the RKE2, operator-RBAC and PodSecurity readiness gates pass.

Use a rebuilt image containing the authenticated credential-service `/attest`
endpoint. Updating only the operator CLI does not add this guest endpoint.
See [the operator trust gate](../docs/operator.md#trust-gate-c8s-get-kubeconfig)
for the explicit legacy attestation URL option and verification rules.

## Measured services and Kubernetes integration

Both roles use the same measured image. Host units are enabled at build time;
role conditions skip server-only units on agents. Kubernetes owns the core
application services:

| Component | Lifecycle | Placement |
|---|---|---|
| Signed launch verification and policy staging | systemd oneshot | Every node, before RKE2 |
| Local attestation API and Unix-socket proxy | systemd services | Every node |
| NRI image admission | Required containerd plugin | Every node, before pods |
| RKE2 | systemd service | Authenticated server or agent role |
| RA-TLS mesh and iptables reconciliation | DaemonSet with native sidecars | Every node |
| CDS | Singleton Deployment | Server |
| Router, certificate renewal and attestation helpers | Singleton Deployment | Server |
| Operator, webhook and admission integration | Kubernetes resources | Cluster-wide |
| Attested operator credential release | systemd service | Server |

`rke2-role.service` verifies and stages launch settings before either RKE2
role starts. The local attester must precede this gate because launch
verification uses it. The host attester listens on `127.0.0.1:8400`;
pods access its Unix socket in the admission-inventory directory. CDS uses
its Kubernetes Service and server NodePort `30808`; agents join RKE2 at
`9345`; the router exposes the server's port `443`.

`c8s/mkosi.sync` resolves the c8s binary and core image digests from `C8S_REF`,
then runs `c8s node-image render` with the checksum-pinned build-time Helm
binary and baked RKE2 Kubernetes version. The complete chart renders once
into `/var/lib/rancher/rke2/server/manifests/c8s-integration.yaml`, including
CDS, router, mesh, operator, CRDs, RBAC, webhook and admission policies.
Only `rke2-server` applies that directory; including it in the agent image
is intentional. There is no guest Helm install, chart archive, runtime
values merge or separate host nginx configuration.

The renderer also emits the component allowlist seed and a list of pinned
core images. `airgap-images.sh` preserves their complete OCI content under
`/var/lib/rancher/rke2/agent/images`; RKE2 imports these archives on either
role. Core pods use `imagePullPolicy: Never`. Before containerd starts,
boot preparation merges the measured component seed into the NRI system
floor, allowing CDS and its clients to start while CDS is unavailable.
Signed tenant workload entries are added to CDS's served seed without
replacing measured bootstrap components.

Boot preparation publishes only public identity inputs under `/run/c8s-node`:
peer pins, server-only CDS pins, and, on the server, the operator public key,
merged workload seed and TLS hostname. Core pods mount these root-owned
files read-only. They never mount `/run/confos/launch`, which contains join
credentials. The operator reads the server policy from this mount and passes
it to workload helpers, which use the in-cluster CDS Service URL. Every CDS
client requires the server's launch key; peer connections accept the
configured role keys. The shared image measurement alone does not
identify the role.

The router's get-cert helper runs alongside nginx again. It reads the signed
hostname from `tls-san`, and CDS permits that exact hostname in addition to
its in-cluster Service DNS pattern. nginx uses one default virtual host;
TLS clients validate the signed certificate hostname. Certificate and
discovery files live in the router Pod's memory-backed volumes. The router
and attestation helpers share the existing chart implementation. Adding a
workload route, including an over-encrypted channel, therefore uses the same
router code; the signed launch schema does not yet expose route configuration.
The supported topology still has one server and one front door; moving the
services into Pods does not add HA.

The launch measurement commits to the initial manifests, image archives and
bootstrap code. It does not attest the current contents of Kubernetes API
objects. Tenant credentials cannot modify the platform namespace or mount
host policy files; cluster administrators remain trusted. The NRI bootstrap
floor pins platform image digests, not every possible argument or mount for
those images. `c8s install` refuses the `confidential.ai/baked=true` namespace
so an ordinary chart install cannot replace this deployment accidentally.

Core version upgrades rebuild the image and relaunch with updated signed
measurement pins. Restarting a Pod uses the same baked image. The current
launch schema accepts one image policy and does not support mixed-image
rolling upgrades. CDS has an ephemeral database and an in-memory CA;
recreating CDS or rebooting its VM requires certificate re-bootstrap and
reapplying the initial workload seed. Launch settings do not enable volume
support, arbitrary service arguments or front-door routes.

Published `C8S_REF` images must include the renderer and the SAN-file flags
used by the manifests. The reproducibility gate's `C8S_BINARY` overrides the
host binary and embedded chart; container images still resolve from
`C8S_REF`. A source-only binary override does not replace those containers.

The staged SNP metal CI lane requires compatible image metadata with
`launchConfigVersion=c8s-launch/v1`:

| ConfigMap | Additional required fields |
|---|---|
| `snp-rke2-image-refs` | `image`, `rootPvc`, `manifestRef`, `igvmFile`, `igvmHookImage`, `smp`, `snpLaunchDigest`, `c8sRef` |

The SNP lane requires digest-pinned OCI references for `image`, `manifestRef`
and `igvmHookImage`, and a hook that sets HOST_DATA from the launch public key.
Its `smp` is currently `4`; `snpLaunchDigest` must match that variant in the
published `manifest.json`. The paired `c8sRef` identifies the image build.
Changing the attester requires a new measured image. The ordinary TDX lane
resolves its published image and manifest from the selected source commit.
Automatic TDX acceptance reads the image identity and
`launch_config_version=c8s-launch/v1` from the publication run's validated
evidence. Neither TDX path reads a refs ConfigMap.

Before either platform boots, the lane builds the paired CLI and generates
a fresh operator key and signed server launch document. The `opkeydata` disk
carries `pubkey`, `launch.yaml` and `launch.yaml.sig`. Clients use the matching
full image tuple and server-key policy when testing the baked services.

## Baked workload checks

With Go and Helm installed, validate both platform renders from the repository
root. The archive test also needs ORAS, jq, Python 3 and GNU tar; the systemd
harness needs Docker with privileged-container support:

```sh
go test -count=1 ./cmd/c8s -run TestNodeImage
make test-node-guest-image-airgap
make test-node-guest-image-role-systemd
```

The rendering tests check complete workload manifests, image pins, namespace
placement and required identity inputs. The offline archive test uses real
ORAS copying to verify complete multi-platform content, canonical image
names and reproducibility. The systemd harness checks the remaining host
bootstrap dependencies in a disposable privileged container.
These checks do not replace boot and attestation testing on TDX or SNP hardware.

## Immutable root checks

From the repository root on a disposable Linux system, check out the
`node-image` confos pin at `./confos`, then run as root. Set `CONFOS_DIR` to
use another checkout:

```sh
sudo make test-node-guest-image-immutable-root
sudo make test-node-guest-image-immutable-root CONFOS_DIR=/path/to/confidential-os-builder
```

The Bash test requires GNU coreutils/findutils, grep, cmp, and util-linux
with mount namespace and overlay support. It stages the actual base, GPU,
attestation and c8s profile extra trees, then executes the pinned base
finalizer and initrd unchanged in a private mount namespace and chroot.
Real overlays must permit c8s state writes and atomic NRI floor replacement
while `/usr`, `/opt/nri` and undeclared `/etc` paths stay read-only and the
lower image stays unchanged.
A missing declared directory must stop boot before `switch_root`. Sync-created
CNI/NRI directories are fixture inputs; the invariant gate separately checks
that `mkosi.sync` creates them. Each case unmounts its fixture before cleanup.

This checks initrd handoff with tmpfs state backing. Hardware discovery and
`switch_root` are shims: it does not boot a full CVM, start systemd or validate
encrypted scratch storage. Those require validation on the built node image.

## Workload isolation

"Tenant" in these docs names the workload side of the trust boundary: pods,
and the namespaced credentials that create them, as opposed to the platform
components in the release namespace and `kube-system`. A node CVM serves one
tenant; the word says which side of the boundary a pod is on, not that
several share a node.

Tenant pods run on the node's own kernel under runc, so what a pod may ask
for is what stands between it and the measured host. The image enforces the
restricted PodSecurity standard by default
(`etc/rancher/rke2/psa-config.yaml`): no privileged pods, no host
namespaces, no root user, dropped ALL capabilities (only `NET_BIND_SERVICE`
may be added back), and no unconfined seccomp or AppArmor. Only `kube-system`
and `local-path-storage` are exempt; `default` is not.

A namespace label can normally lower that level. The baked
`psa-level-policy.yaml` AddOn denies an `enforce` label other than
`restricted`, or an `enforce-version` other than `latest`, unless the
caller is authorized to grant `podsecurityexemptions.confidential.ai` (verb
`grant`), a virtual resource no default role includes. Only the in-guest
`rke2.yaml` (system:masters) passes; the released operator credential holds
no wildcard and does not, nor does a tenant holding `admin` or `edit` in
its own namespaces. The launch measurement vouches for the floor every pod
runs under. No released credential can delete or edit the policy: the
operator's `c8s-node-operator` ClusterRole (`cred-release-rbac.yaml`) has
no admission or cluster-scoped RBAC writes, and the `confos-operator-scope`
policy (`operator-scope-policy.yaml`) denies them in admission for every
`c8s:` group regardless of RBAC, together with every write in the
privileged namespaces (`kube-system`, `local-path-storage` and the baked
operator's `c8s-system`) and the kubelet-proxy subresources. The
`psa-ready.sh` gate proves that deny path before cred-release serves.

`kubectl exec`, `attach`, `port-forward` and ephemeral containers are closed
by the baked `pod-exec-policy.yaml` AddOn (`confos-pod-exec`), a constant
deny on those subresources for every principal. The kubelet's debugging
handlers stay on because they also serve `kubectl logs`, which the
`log-reader` credential (`c8s get-kubeconfig --role log-reader`, bound by the
baked `log-reader-rbac.yaml` AddOn to read pods, their logs, namespaces and
events) exists for. As with the PodSecurity policy, no released credential
can delete it.

The guard AddOns live in `server/manifests`, which is on the writable
overlay because RKE2 stages its bundled charts there. `mkosi.sync` therefore
copies each guard to `/usr/lib/confai/guards` on the read-only root, and
`psa-ready.sh` renders every copy through a server-side dry-run and requires
the live objects to match it field for field before cred-release serves.

RKE2 reconciles AddOns after kube-apiserver starts. The attested credential
endpoint therefore remains closed until `psa-ready.sh` sees both policies,
both credential bindings, and proves, through server-side dry-runs as a synthetic non-granter,
that a restricted namespace is admitted and a privileged one is denied by
`confos-psa-level`. No externally released operator credential can enter the
first-boot reconciliation window.

The floor also covers namespaces hosting confidential workloads. In bare-metal mode,
`nri-image-policy` mounts the inventory socket directory read-only into credential
sidecars through NRI, below the Pod spec. Tenant namespaces keep Restricted
enforcement, warning, and audit. `c8s install` labels its release namespace
privileged for trusted platform components, including node DaemonSets.

The chart's fail-closed `deny-host-namespaces` policies enforce Restricted
controls and deny every tenant `hostPath` volume on Pod CREATE/UPDATE and
`pods/ephemeralcontainers` updates. Existing Pods that still declare the old
claims hostPath must be recreated to pick up NRI wiring; an unchanged prior
sidecar or chart image never exempts the volume. Admission does not evict
already-running Pods. The ephemeral policy also preserves the host-namespace
and host-port checks over the full Pod.

### Cluster storage

The image bakes rancher/local-path-provisioner as the default StorageClass
(`local-path`), so a PVC with no `storageClassName` binds dynamically. The
provisioner's helper pods mount hostPath and run as root, which is what the
`local-path-storage` PSA and admission-policy exemptions exist for. Volumes
live under `/var/lib/local-path-provisioner` on the writable state overlay
and are local to the node; the helper creates them mode 0777, so a non-root
consumer writes without an init container. The requested capacity is
advisory — nothing enforces it. For encrypted, attested volumes see
[../docs/volumes.md](../docs/volumes.md).

Ephemeral containers may inherit safe pod-level `runAsNonRoot` and seccomp
settings when their own settings are absent. Explicit unsafe Pod settings,
including root UID, Unconfined seccomp or AppArmor, disallowed SELinux settings,
and unsafe sysctls, are rejected even when the debugger specifies safe
container settings. Explicit `runAsNonRoot: false` and legacy Unconfined
AppArmor annotations are rejected too. The same Pod-level guards apply to
ordinary Pod admission.

Below admission sits AppArmor, the only enabled major LSM. Both kernel
fragments pin the complete `CONFIG_LSM` order; the invariant gate checks
them and the committed snapshot, and `build` checks the actual resolved
kernel `.config`, including cache hits. Before either RKE2 role starts,
`apparmor-enforce.service` requires an active AppArmor LSM, an executable
parser, and a disabled, inactive `apparmor.service`. It loads a temporary
profile, verifies its enforce-mode label and a denied read against a
successful unconfined control, then removes the profile. Failure blocks
RKE2. The package's stock host profiles are not loaded.

Containerd selects `cri-containerd.apparmor.d` for non-privileged containers
with omitted or explicit RuntimeDefault AppArmor settings. It denies mounts
and selected `/proc` and `/sys` writes, but permits shared-memory sysctls
under `/proc/sys/kernel/shm*` and access to `/sys/fs/cgroup/**`. It also
permits ptrace between processes using the same profile, which all
RuntimeDefault containers share. PID namespaces, capabilities, DAC, Yama,
seccomp and read-only mounts remain necessary isolation layers. Restricted
PodSecurity rejects `Unconfined` but allows `Localhost`, which names an
already loaded profile; no stock host profiles or boot probe profile remain
available for tenants to select.

From the repository root, run the configuration and boot regression tests
with Docker available, then the real parser/kernel probe on a Docker host
with AppArmor. Set `CONFOS_RELEASE` to the pinned confos base release
(currently Resolute); CI reads it from that checkout:

```sh
CONFOS_RELEASE=resolute make test-node-guest-image-apparmor
CONFOS_RELEASE=resolute bash node-guest-image/tests/apparmor-kernel-test.sh
```

The fault-injection harness copies the production script and `/bin/sh`
byte-for-byte into a private chroot, placing fixtures at their actual
absolute paths. It does not rewrite the script or mount host filesystems.
The separate real-kernel probe uses Resolute userspace and the Docker host's
kernel; neither test boots the node image. To verify containerd labels, mount
denial/control and Unconfined admission rejection on the actual image,
point `KUBECONFIG` at the operator credentials for a disposable single-node
c8s cluster and run `make test-node-guest-image-apparmor-runtime` (requires
`kubectl` and `jq`). This creates and cleans up a test namespace and a
`kube-system` pod with `SYS_ADMIN`.

Automatic main-push publication in `c8s-image-publish.yml` calls the separate
`tdx-image-acceptance.yml` workflow after the build finishes. Only this
automatic publisher can call exact-image acceptance; neither workflow has a
manual-dispatch trigger. It consumes the same run and attempt's
immutable evidence: the source SHA, CDI and ORAS digests, the published
manifest, and `launch_config_version=c8s-launch/v1`. Evidence validation
binds these to the publication run and attempt and rejects a missing or
incompatible launch version. Disk and UKI hashes plus MRTD/RTMR1/RTMR2 must
match the fresh build; a differing nonmeasured build timestamp is not a
mismatch. The validated tuple supplies the signed launch configuration before
boot. The published manifest is also passed unchanged to `get-kubeconfig`
for attestation, together with that launch's operator private key.
Tests are checked out at the build SHA. Before allocating the launcher,
the reusable workflow independently requires a successful same-repository
`main` push and exposes no c8s-ref override in exact-image mode. A read-only
hosted preflight fetches trusted `main` history and verifies that the full
build SHA is an ancestor before handing it to the launcher. It executes no
code from the requested build. On the launcher, the action checks that the
workspace HEAD equals that full SHA, then reuses the verified workspace for
the CLI build and every E2E script. The seven-character ref selects only OCI
image tags in exact mode.

The `tdx-metal-e2e.yml` wrapper checks out its workflow revision independently.
It builds the CLI and runs tests from that checkout, or from the explicit
`c8s_ref` when supplied. The resolved commit selects its published
`rke2-tdx-cdi-<sha>` disk and `rke2-tdx-<sha>` manifest; a missing image fails
the run. The disk is pinned by digest and imported into a shared root PVC.
Reusing that PVC requires its full import endpoint to match the selected
image. The published manifest must contain the full MRTD/RTMR1/RTMR2 tuple
and supplies both the signed launch configuration and attested kubeconfig
retrieval. No refs ConfigMap is needed for TDX.
Both wrappers share the lifecycle in `.github/actions/tdx-metal-e2e/action.yml`
and the same concurrency group; checkout and evidence acquisition stay
outside that shared action. Run the real-Git provenance, matching-prefix tag,
source rejection, E2E routing and caller-isolation tests with
`go test ./test/workflows`. These local tests do not boot a node image.

The exact-image job imports the digest-pinned disk into its own 80Gi
`local-path` PVC.
A restricted scheduling pod selects a TDX node before CDI import starts;
the pod has no service-account token or disk mount. Import has a 20-minute
deadline, and cleanup checks ownership of the temporary pod and PVC. This
requires working CDI, enough local disk space, and the launcher's existing
namespace-scoped Pod/PVC permissions; no shared image ConfigMap, root PVC,
or cluster-wide RBAC is changed. The hardware path must still be exercised
on the TDX runner; the local evidence/lifecycle fixtures are run with:

```sh
bash .github/scripts/tests/test-tdx-image-acceptance.sh
```

The ordinary `confidential-e2e` TDX lane tests the image published for the
requested commit. It does not consume publication-run acceptance evidence
or run the automatic new-image AppArmor gate. Exact-image acceptance is
post-publication validation, not a gate on stable-alias promotion. Manual, development and
PR reproducibility builds do not invoke it. Attempt-bound evidence means
rerunning the full publication workflow, including the builder, if the
current attempt has no artifact; there is no fallback to older evidence.
For manual image builds, dispatch `c8s-image-manual.yml` (Actions name:
`c8s-image manual`), with the existing `dev`, `c8s_ref`, `confos_ref` and
`gate` inputs. It builds through the same reusable builder but cannot call
exact acceptance or promote stable aliases. `tdx-metal-e2e.yml` remains
manually dispatchable for published-image regression and `keep_cvm` debugging.

### Post-start exec

The kubelet setting above closes the kubelet's HTTP API. It does not close CRI
`ExecSync`, which is how exec probes and lifecycle exec hooks start a process
in a running container, nor a direct call to containerd. The locked image
points the containerd runc handler's `BinaryName` at `/usr/local/bin/c8s-runc`
(`mkosi.extra/.../config-v3.toml.d/10-c8s-runc.toml`), a measured wrapper that
denies `runc exec` and passes every other verb to RKE2's runc. All of those
paths end in that one call, so all of them fail.

The consequences for anything running on such a node: an exec probe never
passes and a `preStop` exec hook never runs. c8s's own components use HTTP
probes and SIGTERM handling instead. See
[docs/node-exec-mode.md](../docs/node-exec-mode.md) for the wrapper, the build
gate that proves no handler escapes it, and what to do in a new component.

## Refreshing measurements

A builder-pin change requires rebuilding both platforms and deriving fresh
measurement configurations from their `manifest.json` files. Given built or
downloaded image directories, use the existing CLI:

```sh
c8s measurements derive --tee tdx --out measurements-tdx.json output/rke2-tdx
c8s measurements derive --tee sev-snp --out measurements-snp.json output/rke2-snp
```

The input can also be a manifest path. Keep one configuration per platform:
TDX includes MRTD and RTMR[1]/RTMR[2]; SNP includes each measured vCPU variant.

The PR reproducibility gate builds both platforms twice with a shared
ephemeral module-signing key and the published component ref pinned by
`c8s/mkosi.sync`. Its manifests and derived configurations are candidate
evidence for that build. They are not production reference values: automatic
publication uses the production signing key and components paired with its
source commit. Derive production references from those newly published
measured images, retaining their manifest and immutable artifact identity.
Do not substitute gate measurements into an existing cluster's trusted
reference configuration.

Exact-image TDX hardware acceptance runs only after automatic publication,
using that publication's source SHA, digests and manifest as described above.
A successful PR comparison does not prove the new image boots on hardware;
manual and PR gate builds cannot invoke the exact-image acceptance path.

## Module loading

`kernel/c8s.config` sets `CONFIG_MODULES=y`, which the confos base kernel
compiles out. It is on for exactly two out-of-tree modules, `nvidia.ko` and
`nvidia-uvm.ko` (see [MODULE-SIGNING.md](MODULE-SIGNING.md)); every symbol
kubelet, containerd and Cilium need is `=y`, so nothing modprobes at runtime.

Because the key exists on this kernel, the runtime lock has to be set here:
confos's `99-kspp-hardening.conf` omits `kernel.modules_disabled` on the
grounds that the base kernel has no such key. `c8s-modules-latch.service`
sets it to 1 once boot-time loading is done, ordered after the gpu profile's
`nvidia-modules-latch.service` and before the rke2 pair, which it is
`RequiredBy`. The latch is one-way for the rest of the boot.

The gpu profile ships a latch of its own, so on the canonical GPU build both
run and the second rewrites a 1. This one also covers the GPU-less
composition (`attest` + `c8s`, no `gpu`), where that unit is absent. The same
split applies to `99-c8s-bpf.conf`: the c8s profile owns the runtime locks its
own kernel fragment makes necessary.

## Component pins

Every external input is pinned by immutable reference. Moving any pin
moves `root_hash` and the launch measurement — bump deliberately, in a
reviewed commit.

`.github/build-pins.json` is the canonical source for the measured workflows'
confos, attestation-rs, and mkosi pins. They validate and export the selected
domain through `.github/scripts/pin-manifest.sh`; automated pin-watch PRs
therefore change the manifest rather than workflow files.

`mkosi.sync` resolves c8s container digests from the registry tag `C8S_REF`
at build time. The rendered manifests, component seed and measured OCI
archives record those pins. The NRI system floor comes from the pinned RKE2
bundles. A rebuild after a mutable `C8S_REF` tag moves will not match.

## Physical host prerequisites

### TDX

The authenticated launch gate requires a freshly generated and verified
quote. Host quote-generation or certificate-provisioning failures block that
gate before RKE2 and dependent services can start.

- `qgsd` running on the host — the Intel DCAP Quote Generation Service
  that signs the TDREPORT into a full TDX quote. Talks over vsock.
- Intel PCS API key in `/etc/sgx_default_qcnl.conf` — DCAP fetches
  TCB collateral from Intel PCS during verify.
- **The platform registered with Intel**, so PCS can serve its PCK
  certificate. A CPU whose platform manifest was never uploaded gets no
  PCK cert, and every quote then fails inside qgsd with
  `[QPL] No certificate data for this platform` (`0xe011`). Cloud TDX hosts
  arrive registered; bare metal often
  does not, and the MPA agent (`sgx-ra-service`) only registers when
  the BIOS has "SGX Auto MP Registration" enabled. Without touching the
  BIOS, register indirectly once (`sgx-pck-id-retrieval-tool`):

  ```
  PCKIDRetrievalTool -f pckid.csv
  awk -F, '{print $6}' pckid.csv | tr -d '\r\n' | xxd -r -p > manifest.bin
  curl -sS -X POST https://api.trustedservices.intel.com/sgx/registration/v1/platform \
    -H 'Content-Type: application/octet-stream' --data-binary @manifest.bin
  # HTTP 201 = registered; restart qgsd afterwards
  ```

  Registration is permanent for the platform (survives reinstalls).

Two host-kernel gotchas seen on bare metal: if `dmesg` shows
`virt/tdx: initialization failed: Hibernation support is enabled`, add
`nohibernate` to the kernel command line (TDX and S3/hibernation are
mutually exclusive), and make sure `kvm_intel.tdx=1` is set (module
option or command line) — `cat /sys/module/kvm_intel/parameters/tdx`
must print `Y`, or QEMU refuses to launch TDs.

### GPU passthrough

Per the install constraints, the GPU **host** setup is not done by c8s.
Provision it with your host-provisioning system before installing c8s:

- **vfio-pci binding** of the GPUs (`vfio-pci.ids=10de:...` on the host cmdline,
  nvidia/nouveau blacklisted).
- **GPU confidential-compute (CC) mode** set in GPU firmware (`nvidia_gpu_tools.py
  --set-cc-mode=on`). A CC-mode/runtime mismatch panics the in-guest driver
  (`conf_compute.c:162` — "CPU does not support confidential compute").
- **BAR resize** on Blackwell (default → 8 GiB), before kubelet. Two mechanisms
  exist and each fails on one Blackwell part: prefer the kernel sysfs path
  (unbind → `echo 13 > resource2_resize` → rebind — the one that works on
  B200), fall back to `setpci` + remove/rescan (needed on `preserve_config`
  hosts like RTX PRO 6000, but a **silent no-op on B200**: the control
  register accepts the write while the device keeps decoding the old window —
  always verify with `lspci`).
- **Runtime PM pinned off** for every passthrough GPU
  (`echo on > /sys/bus/pci/devices/<bdf>/power/control`). An idle vfio-bound
  B200 gets runtime-PM autosuspended into D3cold and does not survive the
  resume (observed on kernel 7.0.9): BAR0 reads `0xFF`, the guest driver
  reports "GPU has fallen off the bus". Note
  `nvidia_gpu_tools.py` resets `power/control` to `auto` on every run, so
  host provisioning must re-apply the pin after any gpu-admin-tools
  invocation. Recovery for a bricked GPU: force D0 →
  `--reset-with-sbr` → D3→D0 power-control cycle; FLR alone is insufficient.
- On SEV-SNP hosts, `kvm_amd.sev_snp=1` and an IOMMU on the host cmdline.

## Troubleshooting

Inspect the core workloads with the attested kubeconfig:

```sh
kubectl -n c8s-system get pods -o wide
kubectl -n c8s-system describe deployment/c8s-router
```

`kubectl logs` works on every image. The locked image denies `kubectl exec`,
`attach` and `port-forward` (see [Post-start exec](#post-start-exec)). On a
debug image (`C8S_DEV=1`), you can also use the guest's serial console and
local container runtime to inspect nginx directly:

```sh
export CONTAINER_RUNTIME_ENDPOINT=unix:///run/k3s/containerd/containerd.sock
/var/lib/rancher/rke2/bin/crictl ps --name nginx
/var/lib/rancher/rke2/bin/crictl logs <nginx-container-id>
```

**`Read-only file system` inside a container** — check its `volumeMounts` and
`readOnlyRootFilesystem` setting. For a host service, check the unit's systemd
sandbox (`ProtectSystem` and `ReadWritePaths`), then the measured writable
paths in `/usr/lib/confai/state.d/*.conf`. The image invariant checks that
each declared writable directory exists.

Changes to service binaries or persistent configuration belong in the measured
image build. Changes made on the running guest are outside the image's
measurement and disappear on reboot. Deploy workloads through Kubernetes and
use the signed launch document for the supported per-boot settings.

Migration state (see [#264] for the full plan):

1. This directory is the canonical definition: `c8s-image.yml` builds via
   `node-guest-image/build`, which stages `c8s/` into a confos checkout
   with `--profile-dir` and passes the kernel fragment and
   `c8s-ref`/`c8s-registry` sync inputs explicitly. The
   `node-guest-image lint` workflow is permanent: it carries the
   invariants that moved here from confos `bin/lint` (fragment supersets
   vs confos's gpu/dev fragments at the `node-image` confos pin in
   `.github/build-pins.json`, the NRI
   floor template's no-hardcoded-digest rule, and the nested RKE2/Cilium
   pod-CIDR match), plus the cloud-init disable gate.
2. The switch was gated on building the same c8s ref both ways (confos
   in-tree vs staged from here) with identical `manifest.json`
   measurements; `c8s-image-manual.yml`'s `gate=true` dispatch input reruns that
   A/B check against any confos ref.
3. Remaining cleanup, so the inherited interface doesn't become canonical
   selector.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
[operator.md]: ../docs/operator.md
