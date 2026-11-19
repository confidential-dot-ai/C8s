# C8s worker image

The C8s worker image (`guests/worker`, `<version>-<tee>[-kubevirt]` tags),
defined in THIS repo and built by [confidential-os-builder] acting purely as a
builder.
Tracking issue: [#264].

A worker runs a cluster's workloads while the cluster's Kubernetes control
plane runs outside every TEE
([docs/launch-configuration.md](../../docs/launch-configuration.md)).

Layout:

- `worker/` — the mkosi profile (config, `mkosi.extra/`, `mkosi.sync` and the
  NRI floor template). Staged into the confos build via
  `confos build --profile-dir` (confos ≥ the release carrying
  confidential-os-builder#81); the dir basename **is** the profile name, so
  it must stay `worker`.
- Platform: `build` requires `C8S_PLATFORM=tdx|snp`. Platform-specific
  service settings, node labels, measurement policy and image artifacts are
  generated at build time; TDX and SNP do not share a measurement or image
  digest. SNP also has one launch digest per supported vCPU count. Both
  platforms bind the worker document into the launch: TDX in RTMR[3], SNP in
  HOST_DATA.
- `kernel/` — the guest-kernel config fragment (`c8s.config`), passed via
  `--kernel-config-fragment`. confos's `required`/`hardening`
  baselines stay in confos: a fragment request that conflicts with them
  fails the build (see the balloon catch in #263).
- `build` — drop-in replacement for confos's `bin/build-c8s`: same env
  contract (`C8S_PLATFORM`, `C8S_REF`, `C8S_REGISTRY`, `C8S_NAME`,
  `C8S_MEMORY`) and the same profile stack and order; only the worker profile
  content and kernel fragments come from here. Point `CONFOS_DIR` at a confos
  checkout (default: a sibling dir).

  The image's kubelet serves no debugging handler, so `kubectl exec`,
  `attach`, `port-forward`, `debug` and `logs` reach no endpoint on it, and it
  routes every ordinary pod through the measured runtime wrapper, which denies
  `runc exec` — see [Post-start exec](#post-start-exec).

## Launch requirements

The `node-image` domain in [`.github/build-pins.json`](../../.github/build-pins.json)
pins the confos commit the image builds with. Every pin since
[confidential-os-builder#120](https://github.com/confidential-dot-ai/confidential-os-builder/pull/120)
includes its immutable root.
The image invariant gate requires immutable-root support by default and CI
sets `EXPECT_IMMUTABLE_ROOT=1` explicitly.

Every worker VM needs a write-storage disk with virtio-blk serial
`confai-scratch`, at least 64G. The serial is what matters: the confos
initrd scans every attached virtio disk except the image disk for it and
ignores labels, so the disk may be attached in any order. In KubeVirt that's
`disk: {bus: virtio}` plus `serial: confai-scratch`; confidential-metal
attaches one by default (`--datadisk-gi`, 0 opts out).

The initrd encrypts the disk and, via a dm mapping named `scratch`, backs
writable overlays for directories declared by the measured image. The root
and undeclared paths stay read-only. In addition to the base state directories,
this profile declares `/etc/cni`, `/opt/cni` and `/etc/nri` in
`/usr/lib/confai/state.d/60-worker.conf`. All runtime state disappears on
reboot. Without the disk
the initrd falls back to a 2G RAM tmpfs: the guest comes up Ready, then
wedges once the runtime fills it — a flapping node, not a boot error.
`scratch-enforce.service` closes that hole by checking for the dm mapping
and powering the VM off before containerd starts. It also verifies the crypt
UUID and `confai-scratch` backing device, then writes boot-local provenance
under `/run/c8s/scratch-provenance.json` for NRI mount classification.

Every boot also requires an ISO labelled `opkeydata` with these two files at
its root:

- the worker document, the strict `c8s-worker/v1` launch file naming the CDS
  this cluster's clients trust, the router's TLS SAN, and the API server, CA,
  ranges and cluster DNS of the control plane the worker joins. The measured
  initrd stages its exact bytes in read-only `/run/confai` and binds their
  digest into TDX RTMR[3]; an SNP launcher must set HOST_DATA to the SHA-256 of
  those same bytes.
- `bootstrap-token`: the Kubernetes bootstrap token the kubelet requests its
  client certificate with, outside the measurement.

`c8s worker new` drafts a document. CDS certifies a worker booted on it only
under a node image entry that binds the document's digest (`c8s cds ha
accept-node`). There is no diskless boot: a missing or unbound document
fails staging, and `worker-stage.service` powers the VM off.

Every field, the admission rule and the boot-time staging order are
[docs/launch-configuration.md](../../docs/launch-configuration.md). Each boot
registers the worker under a node name derived from its primary IPv4 address.

The worker checks its router eligibility against CDS every 30–36 seconds after
each attempt. It clears stale eligibility at startup, then publishes
`confidential.ai/router-eligible=true` after a successful check. A policy mismatch
removes the label and deletes an unready router waiting for its certificate;
transient check failures preserve the last known decision. Ready routers retain
their existing credential lifetime. Router placement requires this label.

Additional optional disks:

- serial `confai-containerd` (or label `containerd`): backs containerd's
  image cache (`containerd-data-disk.service`).
- serial `confai-models`: a pre-populated, read-only weights disk mounted at
  `/var/lib/models`. It is unencrypted and host-writable; attach public
  weights whose digests the workload verifies (`models-disk.service`).

## Measured services and Kubernetes integration

Host units are enabled at build time, and every one of them requires and
follows `worker-stage.service`, the invariant gate's rule. The boot gates run
before it: `scratch-enforce`, `apparmor-enforce`, `gpu-cc-enforce`,
`c8s-modules-latch` and the two data-disk units, each a oneshot containerd
waits for. Kubernetes owns the core application services:

| Component | Lifecycle | Placement |
|---|---|---|
| Launch verification, floor and kubelet staging | systemd oneshot | Every worker, before containerd |
| Local attestation API and Unix-socket proxy | systemd services | Every worker |
| NRI image admission | systemd service; the plugin containerd requires | Every worker, before pods |
| containerd and the kubelet | systemd services | Every worker, after staging |
| Cilium agent, kube-proxy and CoreDNS | kubelet static pods | Every worker |
| armTLS mesh endpoint and packet rules | Sidecar the webhook injects; rules installed by NRI image admission | Every member pod, on any worker |
| Router, certificate renewal and attestation helpers | Deployment | Any worker |
| Operator, webhook and admission integration | Kubernetes resources | The control plane, outside the TEEs |

`worker-stage.service` verifies and stages launch settings before containerd
starts. The local attester must precede this gate because launch
verification uses it. The host attester listens on `127.0.0.1:8400`;
pods access its Unix socket in the admission-inventory directory. Every CDS
client dials the address the worker document names; the router exposes port
`443`. Cilium's VXLAN runs on UDP `8473`, not the kernel default `8472`: a
nested guest's outer host often runs its own VXLAN on `8472` and drops the
inner overlay. Open UDP `8473` between nodes in any firewall or security
group.

`worker/mkosi.sync` resolves the c8s binary and core image digests from
`C8S_REF`, then runs `c8s node-image render` with the checksum-pinned
build-time Helm binary and the baked Kubernetes version, and `c8s worker floor`
over that render, which carries the c8s-worker chart's static pod templates,
and this profile's floor template.
The CDS those components trust runs on a confidential VM of its own, which
`c8s cds config new` writes the configuration and the pin for, so the image
neither renders a CDS nor preloads its image.

The sync also installs the router's nginx configuration in
`/usr/lib/c8s/router-nginx`, and the router mounts it from there instead of
from a ConfigMap the control plane could edit. The static pods pull their
images by digest at boot, and every other platform pod is the control plane's
to schedule. Before containerd starts, staging writes the measured floor to
`/etc/nri`, so the components start while CDS is unavailable.

Staging publishes only public identity inputs under `/run/c8s-node`: the CDS
pin the document carries, the operator keys of the CDS configuration that pin
binds, the TLS hostname and the router's settings. Core pods mount these
root-owned files read-only. They never mount the kubelet's inputs under
`/run/kubernetes`, which carry the bootstrap token. Every CDS client holds the
CDS to the document's pin.

The router's get-cert helper runs alongside nginx. It reads the hostname from
`tls-san`, which the CDS configuration carries as a leaf DNS name, so CDS
permits that exact hostname in addition to its in-cluster Service DNS pattern.
nginx uses one default virtual host; TLS clients validate the signed
certificate hostname. Certificate and discovery files live in the router Pod's
memory-backed volumes. The router and attestation helpers share the existing
chart implementation. Adding a workload route, including an over-encrypted
channel, therefore uses the same router code.

The launch measurement commits to the baked floor, the static pod templates
and the bootstrap code. It does not attest the current contents of Kubernetes
API objects. The NRI floor pins platform image digests, not every possible
argument or mount for those images.

Core version upgrades rebuild the image and relaunch with updated measurement
pins. Restarting a Pod uses the same baked image. CDS has an ephemeral
database and an in-memory CA; rebooting its VM requires certificate
re-bootstrap.

Published `C8S_REF` images must include the renderer and the SAN-file flags
used by the manifests. The reproducibility gate builds the host binary and
core containers from the same checkout. `C8S_BINARY` supplies the binary;
`C8S_IMAGES_DIR` supplies the same unpublished OCI layouts to both build legs,
tagged with `C8S_REF`.

## Pod CVM image

`C8S_PROFILE=pod images/node-guest/build` (TDX only) stacks `pod/` after the
worker profile and writes `output/c8s-pod/`. A pod CVM runs one assigned pod
under a standalone kubelet and joins no cluster. It reuses the worker's
kernel, runtime binaries, runtime wrapper, NRI plugin, boot gates and floor,
and changes what stages and starts them:

- `40-pod.preset` turns off worker staging, the worker's containerd,
  kubelet, attest-proxy and volumed. `pod-stage.service` replaces worker
  staging: `c8s launch-config stage` verifies the signed pod launch document
  on the `opkeydata` disk under the measured pod launch key, then
  `c8s node-services prepare` stages the pod network and kubelet inputs.
  Like worker staging, a failure powers the VM off.
- `podcvm-status.service` serves the attested status and assignment endpoint
  on 8443. Once a pod is assigned it installs the runtime policy, starts
  `podcvm-containerd` (which wants `nri-image-policy`) and, once the plugin
  reports the pod registered, publishes the manifest and starts
  `podcvm-kubelet`.
- The pod's runtime policy is rendered from the worker floor: the mesh
  endpoint entry and role only, the assigned entries, the CDS from the launch
  document, and RTMR[3] image measurement. The endpoint is the worker's:
  the worker sync pins armtls-mesh by digest in the floor, the pod's endpoint
  container names that `repo@digest`, and containerd pulls it at pod start.
  The image bakes no endpoint bytes.
- `scratch-enforce` keeps its crypt check but drops the 64G floor on an image
  that bakes `/usr/lib/c8s/pod-image`, and accepts memory-backed state there:
  a pod CVM runs one pod and is launched with a small scratch disk or none.
- The pod network uses the bridge, host-local and loopback CNI plugins the
  pod sync bakes into `/opt/cni/bin` from the CNI release the worker sync
  verified.

`opkeydata` is the `pod/` directory `c8s launch-config new-pod` writes: the
pod launch public key (`pubkey`) as the launch file the initrd binds into
RTMR[3], with `launch.yaml` and `launch.yaml.sig` beside it.

## Image checks

With Go, Docker and a `./confos` checkout (or `CONFOS_DIR`), validate the
profile from the repository root:

```sh
make test-node-guest-image-invariants
make test-node-guest-image-systemd
make test-node-guest-image-containerd
make test-node-guest-image-attester-finalize
```

The invariants target runs two checks: a shell gate over the kernel fragment,
the boot gates, the programs the image bakes and the staging dependency of
every host unit, each against a copy of the profile, and
`go test ./images/node-guest/worker` over the profile's own consistency,
including the measured runtime wrapper's path. The systemd harness
runs the host units under real systemd with stubbed payloads, in a disposable
privileged container. The containerd check proves that every ordinary-pod
handler runs the wrapper, and the finalize check that each image narrows its
attester to a loopback bind.
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
attestation and worker profile extra trees, then executes the pinned base
finalizer and initrd unchanged in a private mount namespace and chroot.
Real overlays must permit C8s state writes and atomic NRI floor replacement
while `/usr`, `/opt/nri` and undeclared `/etc` paths stay read-only and the
lower image stays unchanged.
A missing declared directory must stop boot before `switch_root`. Sync-created
CNI/NRI directories are fixture inputs; the invariant gate separately checks
that `mkosi.sync` creates them. Each case unmounts its fixture before cleanup.

This checks initrd handoff with tmpfs state backing. Hardware discovery and
`switch_root` are shims: it does not boot a full CVM, start systemd or validate
encrypted scratch storage. Those require validation on the built worker image.

## Workload isolation

"Tenant" in these docs names the workload side of the trust boundary: pods,
and the namespaced credentials that create them, as opposed to the platform
components in the release namespace and `kube-system`. A node CVM serves one
tenant; the word says which side of the boundary a pod is on, not that
several share a node.

Tenant pods run on the node's own kernel under runc, so what a pod may ask
for is what stands between it and the measured host. The node's admission
plugin refuses a container that holds host privilege outside the measured
floor, and the runtime wrapper bounds every container of a member pod
([../../docs/allowlist-and-capabilities.md](../../docs/allowlist-and-capabilities.md),
[../../docs/node-exec-mode.md](../../docs/node-exec-mode.md)). The control
plane that writes every pod spec is outside the worker's TEE, so those two are
the floor every pod runs under, and the launch measurement vouches for them.

`nri-image-policy` mounts the inventory socket directory read-only into
credential sidecars through NRI, below the Pod spec.

### Cluster storage

Encrypted workload volumes use attested key release and `volumed` block
attachment. See [../../docs/volumes.md](../../docs/volumes.md).

Below admission sits AppArmor, the only enabled major LSM. The kernel
fragment pins the complete `CONFIG_LSM` order; the invariant gate checks
it and the committed snapshot, and `build` checks the actual resolved
kernel `.config`, including cache hits. Before containerd starts,
`apparmor-enforce.service` requires an active AppArmor LSM, an executable
parser, a disabled, inactive `apparmor.service`, and
`kernel.apparmor_restrict_unprivileged_unconfined = 0`. It loads a temporary
profile, verifies its enforce-mode label and a denied read against a
successful unconfined control, then removes the profile. Failure blocks the
runtime. The package's stock host profiles are not loaded.

The apparmor package turns that sysctl on in `/usr/lib/sysctl.d/10-apparmor.conf`;
`worker/mkosi.extra/etc/sysctl.d/20-apparmor.conf` turns it back off. On, it
makes the kernel stack the profile a task asks for at exec with unconfined
when the task lacks `CAP_MAC_OVERRIDE` (Linux 6.18.60, upstream
`08c2f7c8d4b1`). runc has dropped the pod's capabilities by then, so every
RuntimeDefault container would run as `cri-containerd.apparmor.d//&unconfined`,
and containerd's `signal` and `ptrace` rules, which name the plain profile as
the peer, would no longer match a container's own processes. The restriction
stops an unconfined, unprivileged task from switching into a more permissive
loaded profile; this image has none to switch into, and container tasks are
confined by a profile with no `change_profile` rule, so turning it off removes
nothing here. If a permissive profile is ever loaded on the node, turn it back
on with that change. The user-namespace restriction from the same package file
stays on. The invariant gate checks that the drop-in sets the key to 0, that
`apparmor-enforce.sh` asserts it, and that no sysctl.d file sorting after it in
the profile or the pinned confos base sets the key again; without that, the
failure would be a node powering itself off at first boot.

Containerd selects `cri-containerd.apparmor.d` for non-privileged containers
with omitted or explicit RuntimeDefault AppArmor settings. It denies mounts
and selected `/proc` and `/sys` writes, but permits shared-memory sysctls
under `/proc/sys/kernel/shm*` and access to `/sys/fs/cgroup/**`. It also
permits ptrace between processes using the same profile, which all
RuntimeDefault containers share. PID namespaces, capabilities, DAC, Yama,
seccomp and read-only mounts remain necessary isolation layers.

From the repository root, run the configuration and boot regression tests
with Docker available, then the real parser/kernel probe on a Docker host
with AppArmor. Set `CONFOS_RELEASE` to the pinned confos base release
(currently Resolute); CI reads it from that checkout:

```sh
CONFOS_RELEASE=resolute make test-node-guest-image-apparmor
CONFOS_RELEASE=resolute bash images/node-guest/tests/apparmor-kernel-test.sh
```

The fault-injection harness copies the production script and `/bin/sh`
byte-for-byte into a private chroot, placing fixtures at their actual
absolute paths. It does not rewrite the script or mount host filesystems.
The separate real-kernel probe uses Resolute userspace and the Docker host's
kernel; neither test boots the worker image.

### Post-start exec

The kubelet setting above closes the kubelet's HTTP API. It does not close CRI
`ExecSync`, which is how exec probes and lifecycle exec hooks start a process
in a running container, nor a direct call to containerd. The image
points the containerd runc handler's `BinaryName` at `/usr/local/bin/c8s-runc`
(`worker/mkosi.extra/etc/containerd/conf.d/10-c8s-runc.toml`), a measured wrapper
that denies `runc exec` and passes every other verb to the pinned runc. All of
those paths end in that one call, so all of them fail.

The consequences for anything else running on such a node: an exec probe never
passes and a `preStop` exec hook never runs. C8s's own components use HTTP
probes and SIGTERM handling instead. See
[docs/node-exec-mode.md](../../docs/node-exec-mode.md) for the wrapper, the build
gate that proves no handler escapes it, and what to do in a new component.

## Refreshing measurements

A builder-pin change requires rebuilding both platforms and deriving fresh
measurement configurations from their `manifest.json` files. A build is one
platform, and `--tee` refuses a platform the image was not built for, so each
platform's configuration comes from its own image directory. From the confos
checkout, after builds named `C8S_NAME=worker-tdx` and `C8S_NAME=worker-snp`
(for a downloaded image, pass its own directory):

```sh
c8s measurements derive --tee tdx --out measurements-tdx.json output/worker-tdx
c8s measurements derive --tee sev-snp --out measurements-snp.json output/worker-snp
```

The input can also be a manifest path. Keep one configuration per platform:
TDX includes MRTD and RTMR[1]/RTMR[2]; SNP includes each measured vCPU variant.

The PR reproducibility gate builds both platforms twice with a shared
ephemeral module-signing key and the published component ref pinned by
`worker/mkosi.sync`. Its manifests and derived configurations are candidate
evidence for that build. They are not production reference values: automatic
publication uses the production signing key and components paired with its
source commit. Derive production references from those newly published
measured images, retaining their manifest and immutable artifact identity.
Do not substitute gate measurements into an existing cluster's trusted
reference configuration.

## Module loading

`kernel/c8s.config` sets `CONFIG_MODULES=y`, which the confos base kernel
compiles out. It is on for exactly two out-of-tree modules, `nvidia.ko` and
`nvidia-uvm.ko` (see [MODULE-SIGNING.md](MODULE-SIGNING.md)); every symbol
kubelet, containerd and Cilium need is `=y`, so nothing modprobes at runtime.

Because the key exists on this kernel, the runtime lock has to be set here:
confos's `99-kspp-hardening.conf` omits `kernel.modules_disabled` on the
grounds that the base kernel has no such key. `c8s-modules-latch.service`
sets it to 1 once boot-time loading is done, ordered after the gpu profile's
`nvidia-modules-latch.service` and before containerd, which it is
`RequiredBy`. The latch is one-way for the rest of the boot.

The gpu profile ships a latch of its own, so on the canonical GPU build both
run and the second rewrites a 1. This one also covers the GPU-less
composition (`attest` + `worker`, no `gpu`), where that unit is absent. The same
split applies to `99-c8s-bpf.conf`: the worker profile owns the runtime locks
its own kernel fragment makes necessary.

## Component pins

Every external input is pinned by immutable reference. Moving any pin
moves `root_hash` and the launch measurement — bump deliberately, in a
reviewed commit.

`.github/build-pins.json` is the canonical source for the measured workflows'
confos, attestation-rs, and mkosi pins. They validate and export the selected
domain through `.github/scripts/pin-manifest.sh`; automated pin-watch PRs
therefore change the manifest rather than workflow files. The mkosi pin is
derived, not chosen: `.github/scripts/confos-mkosi-pin.sh` reads it from the
pinned confos commit's own `base.yml`, pin-watch writes what it reads, and
pin-hygiene fails a PR whose `mkosi_ref` or `mkosi_version` no longer matches,
so a hand-moved `confos_ref` has to carry mkosi along. `attestation_api_digest`
is the published attestation-api image of that release: the CDS image fetches
it by that digest (`images/cds-guest/cds/mkosi.sync`) and the host DaemonSet
runs it as the chart's `attestationApi` `pinnedDigest`
(`charts/lib/files/components.yaml`), a copy that
`.github/scripts/chart-attestation-api-digest.sh` reads and writes and that
pin-hygiene holds equal to the manifest. pin-hygiene also resolves
`attestation-api:<attestation_rs_tag>` and
`attestation-api:sha-<attestation_rs_ref[0:7]>` with
`.github/scripts/ghcr-digest.sh` (attestation-rs names one manifest both
ways) and fails when either names another build, so the host and the guests
verify with the same attestation-api release. pin-watch resolves the digest of
a new attestation-rs release and writes the manifest and the chart together.

The chart's third-party image, the router's nginx, is digest-pinned in
`charts/lib/files/components.yaml` and seeded into the allowlist
floor. The line above each digest names the tag it was resolved from
(`# Resolve REPOSITORY:TAG to bump this digest.`), which
`.github/scripts/chart-image-pins.sh list` reads and `set` rewrites.
pin-hygiene fails a digest without that line or one the registry no longer
serves, and notices a tag upstream has rebuilt since; pin-watch's second step
(`confos-pin-watch.yml`, weekly) proposes that rebuild as its own PR, never a
version change. A version bump
is a hand edit of the Resolve line, then `set` with the new tag's digest, then
the block's `entrypoint` and `imageEnv` aligned with the image's config, which pin-hygiene then checks (`chart-image-pins.sh check`).

The confos and attestation-rs pins are release commits: each `*_ref` SHA is
what the builds check out, and the `*_tag` beside it is the release that
names it (`vMAJOR.MINOR.PATCH`). The SHA stays the build input because a tag
can be repointed; the pin-hygiene workflow resolves each tag in its source
repository (`.github/scripts/release-pin.sh`) and fails when it no longer
names the pinned SHA. Pin-watch follows each repository's latest release, not
its `main`, so an unreleased commit never enters a measured build, and it
only moves a pin forward: a latest release older than the pinned one is kept
out. An attestation-rs release that changes the attestation-api config or
`/verify` contract still needs the c8s and confos ports in the same PR as its
bump.

Published builds resolve C8s container digests from the registry tag
`C8S_REF` at build time. The rendered floor, the router configuration and the
static pod pins record those digests. A rebuild after a mutable `C8S_REF` tag
moves will not match.

## Physical host prerequisites

### TDX

The authenticated launch gate requires a freshly generated and verified
quote. Host quote-generation or certificate-provisioning failures block that
gate before containerd and dependent services can start.

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

Per the install constraints, the GPU **host** setup is not done by C8s.
Provision it with your host-provisioning system before installing C8s:

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

Attach GPUs at VM launch. The guest kernel has PCI hotplug compiled out, so a
GPU attached later is not enumerated. `gpu-cc-enforce.service` checks CC mode
and attestation once per boot and relies on this; the invariant gate fails if
the kernel fragment or the resolved snapshot enable any `HOTPLUG_PCI*`
symbol. A `/sys/bus/pci/rescan` by guest root or by any privileged platform
pod still enumerates new devices without a check
([#669]). Tenant pods cannot do this under the measured floor.

## Troubleshooting

Inspect the core workloads with the control plane's kubeconfig:

```sh
kubectl -n c8s-system get pods -o wide
kubectl -n c8s-router describe deployment/c8s-router
```

A worker's kubelet answers no log request, so `kubectl logs` reads nothing
there, and the image denies `kubectl exec`, `attach` and `port-forward` (see
[Post-start exec](#post-start-exec)).

**`Read-only file system` inside a container** — check its `volumeMounts` and
`readOnlyRootFilesystem` setting. For a host service, check the unit's systemd
sandbox (`ProtectSystem` and `ReadWritePaths`), then the measured writable
paths in `/usr/lib/confai/state.d/*.conf`. The image invariant checks that
each declared writable directory exists.

Changes to service binaries or persistent configuration belong in the measured
image build. Changes made on the running guest are outside the image's
measurement and disappear on reboot. Deploy workloads through Kubernetes and
use the worker document for the supported per-boot settings.

Migration state (see [#264] for the full plan):

1. This directory is the canonical definition: `c8s-image.yml` builds via
   `images/node-guest/build`, which stages `worker/` into a confos checkout
   with `--profile-dir` and passes the kernel fragment and
   `c8s-ref`/`c8s-registry` sync inputs explicitly. The
   `node-guest-image lint` workflow is permanent: it carries the
   invariants that moved here from confos `bin/lint` (fragment supersets
   vs confos's gpu fragment at the `node-image` confos pin in
   `.github/build-pins.json`), plus the cloud-init disable gate.
2. The switch was gated on building the same C8s ref both ways (confos
   in-tree vs staged from here) with identical `manifest.json`
   measurements; `c8s-image-manual.yml`'s `gate=true` dispatch input reruns that
   A/B check against any confos ref.
3. Remaining cleanup, so the inherited interface doesn't become canonical
   selector.

[confidential-os-builder]: https://github.com/confidential-dot-ai/confidential-os-builder
[#264]: https://github.com/confidential-dot-ai/c8s/issues/264
[#669]: https://github.com/confidential-dot-ai/c8s/issues/669
