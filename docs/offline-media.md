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

Include the additional [host inputs](offline-host.md#build-inputs), including the
QEMU topology, routes, PCK cache and k3s configuration.
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

## Qualify and seal

On a workstation with authenticated site time, the verifier maintainer and
operator exercise local, fresh verification for all eight B200s with public
egress blocked. Retain the raw verification and refresh/import observations.
The qualifier signs `review.json` only when those observations establish every
field below. A verifier that cannot identify the RIM and certificate-status
bytes used for each assigned device leaves the archive in staging. A run-wide
set of responder hashes cannot fill the per-device fields. Supply a separate
authenticated per-device trace from the qualified verifier and map the limiting
certificate or chain member to its signed snapshot selector.

| Qualification field | Evidence |
| --- | --- |
| `archiveSha256`, `inventorySha256` | SHA-256 of the exact `software.tar` and `inventory.sha256` qualified. |
| `target`, `generation`, `snapshotSha256` | Approved site identifier and the selected signed snapshot. |
| `offlineB200Verified`, `devices` | Successful disconnected verdict (`true`) and one record per distinct assigned `ueid`. Each record contains nonempty `rims` and `ocsp` objects mapping the signed snapshot selectors to the SHA-256 of the exact bytes used. Use `nvidia/rim/<id>` and `nvidia/ocsp/<certificate-DER-sha256>`. |
| `policySha256`, `maximumStatusAgeSeconds` | SHA-256 of `nvidia/policy` and the status age approved for this site. |
| `observedRefreshSeconds`, `earliestExpiryUtc`, `limitingObject` | Measured retrieval-to-import time in whole seconds, the earliest UTC deadline across signed validity, certificate expiry and approved status age, and its object selector. |

Provision separate OpenSSH allowed-signers files for the qualifier
(`c8s-qualification`) and release signer (`c8s-release`) independently.

```sh
ssh-keygen -Y sign -f "$QUALIFIER_KEY" -n c8s-b200-qualification review.json
scripts/airgap/qualify seal "$TAG" staged "$QUALIFIER_SIGNERS" review.json "$MEDIA_KEY"
```

Transfer the four files in `staged`. Sealing and receipt both require enough
remaining validity for the longer of the measured and planned refresh times.

## Verify at the site

Install OpenSSH, Python 3.11+, GNU coreutils and tar, and a trusted copy of
`scripts/airgap/qualify` at `/usr/local/bin/c8s-qualify` before exchanging
media. Copy the four sealed files to a private operator workstation directory,
establish authenticated site time and run this block in one shell. The
release signer and the expected tag come from the operator's trusted records.

```sh
set -eu
/usr/local/bin/c8s-qualify verify "$TAG" staged "$MEDIA_SIGNERS"
mkdir software
tar --no-same-owner --no-same-permissions -xf staged/software.tar -C software
(cd software && sha256sum --strict --check ../staged/inventory.sha256)
```

Keep an independent copy of the verified profile and pins on the workstation.
Verify the transfer before executing `software/site/install.sh` on the host.
The signed selection on media supplies the proposed initial import. Each
verification queries the active selection maintained by the site authority.
