# Prepare installation media for a disconnected TDX site

Run preparation on a trusted, connected Ubuntu Noble amd64 machine. Use a release
built with the site's measured, offline-capable TA and worker. The current
released verifier needs public services for GPU verification. The site importer
handles Intel material only. The verifier maintainer and site operator must
qualify an offline-capable service and combined Intel/NVIDIA import before
sealing software for the eight B200s.

## Prepare the inputs

Install Python 3.11+ with PyYAML, Git, GitHub CLI, cosign 3, skopeo, apt-utils,
OpenSSL, OpenSSH and GNU tar. Fetch the selected stable release tag into this
checkout. Configure signed Noble and vendor package sources matching the target,
then run `apt-get update`. The resolver uses their package indexes and an empty
installed-package database. Record the exact target baseline and keep the
resulting dependency inventory with the build.

Prepare a site directory on the workstation. All paths below are relative to it.

| Path | Approved input |
| --- | --- |
| `target.json` | Site `id`, lowercase 12-hex `intelFMSPC`, `pckCA` (`platform` or `processor`), target kernel, firmware and driver strings in `kernel`, `firmware`, `driver`, eight assigned GPU evidence identifiers in `gpuUEIDs`, positive integers `mediaTurnaroundSeconds` and `maximumStatusAgeSeconds`, the control plane's `webhookHost`, and the worker build's `operatorImageDigest`, `meshImageDigest` and `volumedImageDigest`. Provide extra digest-pinned OCI references in `additionalImages` for any host services delivered as images. |
| `install.sh`, `packages.txt` | Reviewed host installer and its Noble root packages, one exact `package=version` per line. Include compatible QEMU, QGS/DCAP and GPU host tools. |
| `ta/disk.raw`, `worker/disk.raw`, respective `manifest.json`, `firmware.fd` | Measured disks, matching measurement manifests and the firmware used to derive the launch pins. |
| `ta.yaml`, `ta-pin.json`, `worker.yaml`, `worker-image.json` | Approved launch documents and independently derived pins. |
| `collateral/profile.json`, `collateral/active`, `collateral/snapshots/`, `collateral/objects/`, `pck-cache.json` | Verification profile, proposed selection, its signed snapshot and objects, and the target's Intel provisioning data. Activation requires a combined importer that checks vendor signatures, expiry and target coverage. |
| `k3s`, `cilium-operator-generic`, `helm`, `nginx-entry.json` | The control plane binary, Cilium operator matching the worker, Helm from the worker image build, and the reviewed workload entry for the release sample. |

List every approved regular file, including additional platform-specific boot
files or tools, in `SHA256SUMS` using GNU sha256sum format with relative paths.
Keep private keys on the workstation. Obtain the inventory digest from the
approved build record independently of the site directory. The software signer
accepts responsibility for the pairing of disks, firmware and manifests.

```sh
scripts/airgap/prepare "$TAG" site staged --site-inventory-sha256 "$APPROVED_SITE_SHA256"
```

Preparation verifies the release statement, CLI, TDX seed and component set.
The signed CLI must support site-selected TDX verification for the TA,
workloads and Genesis.
It renders the node and control-plane charts, collects the resulting images,
injected sidecars, nginx sample and sandbox image, and preserves their manifest
digests with every platform in the index. The output contains `software.tar`
and `inventory.sha256`. Inside the archive, `apt/Packages` indexes the local
packages and `oci/refs.txt` lists the original repository and digest of each
image. Seed each local registry from `dir:oci/<64-hex-digest>` using
`skopeo copy --all --preserve-digests`. Configure each original registry's
`server` in the measured guest to reach only the site mirror.
