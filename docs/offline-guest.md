# Stage site network settings for measured guests

An offline TA and worker need the site's DNS, time server, registry trust and
collateral authority profile before the first request. Build these settings
in the profile that both images will measure. This
profile also selects the guest's configfs quote path to the host QEMU's Unix
QGS socket. [QEMU Intel TDX](https://www.qemu.org/docs/master/system/i386/tdx.html)

The currently released verifier uses online GPU verification. The site can
build private qualification images with independently approved candidate binaries.
Production guest pins require an
offline-capable service release, its authenticated selection and verification
paths, and a successful B200 qualification. The Intel-only importer cannot
activate a snapshot containing NVIDIA collateral. The released C8s binaries cannot complete the pilot install.

## Inputs

On the trusted builder, prepare `site/target.json` with `registry` (the
private registry's host and port), `dnsIPv4` (the resolver before cluster
DNS exists) and `ntpIPv4` (a private time server for the service clock).
List eight independently enrolled evidence UEIDs in `gpuUEIDs`. The profile selects this inventory in a measured
service drop-in. The worker requires this exact set in its nonce-bound, verified GPU claims before starting
containerd. Missing GPUs, substituted identities and duplicate evidence fail
the boot. Obtain UEIDs from authenticated evidence during enrollment.
Include `site/registry-ca.pem` and the independent site's
`site/collateral/profile.json`. Use the verifier release's reviewed full
configuration as `site/attestation-api.toml`. It must configure current
signed collateral from the authenticated site authority for cold start,
requests and background refresh, including trusted time for every verdict.

Stage the Intel CPU candidate with the selected-collateral configuration below.
It invokes the measured C8s helper at startup and on CPU TDX verification.
The candidate rejects GPU evidence. A verifier for the production pilot must
add offline NVIDIA verification and demonstrate the complete guest boot.

```toml
[server]
bind = "0.0.0.0:8400"

[attestation]
platforms = ["tdx"]
tdx_quote_method = "configfs"

[verify]
warm = []

[verify.selected_tdx]
helper = "/usr/local/bin/c8s"
profile = "/etc/c8s-site/profile.json"
```

Use the literal bind line shown above so the stock image finalizer narrows
only the service listener to loopback. The site time
server supports the system clock. Each verdict uses independently authenticated
selection and time from the site authority.

## Stage the profile

On the connected builder, put the reviewed amd64 TA and GPU services at
`candidates/ta` and `candidates/worker`. Put the corresponding C8s binary at
`candidates/c8s`. It must support both the release components and
`c8s collateral selected-tdx PROFILE`. The worker must support the libnvat and
ICU ABI from the pinned Confos `attest-gpu` runtime. Obtain the executable
hashes from the site owner's independently authenticated build inventory.
Store them in `approved-verifiers.json` as a JSON object with keys `c8s`, `ta` and
`worker`, each containing the lowercase SHA-256 of the approved executable.
The site owns this approval for hardware testing.

Using the pinned Confos checkout and the usual worker module-signing inputs, run
the following on the builder with `C8S_REF` set to the reviewed published C8s ref.

```sh
scripts/airgap/guest-profile site site-offline --verifiers candidates --approval approved-verifiers.json
export C8S_SITE_PROFILE="$PWD/site-offline"
images/ta-guest/build
C8S_PLATFORM=tdx images/node-guest/build
```

The last mkosi hook verifies the deployed loopback configuration, rejects a
candidate identical to the role's connected verifier, checks the installed
executable digests and runs the C8s helper's command inside the guest root.
The site TA and worker builds emit TDX measurements. Each role's
service enters only its own disk before dm-verity and launch measurement.

The optional profile replaces the worker's baked public DNS list, drops DHCP
and router-advertised resolver information, clears fallback NTP, and configures
containerd's default registry namespace to use the site TLS server. A missing
digest then fails at the site registry. The original image references and
digests still identify the allowed workloads. [Containerd registry configuration](https://github.com/containerd/containerd/blob/v2.3.4/docs/hosts.md#setup-default-mirror-for-all-registries)

Keep the qualification outputs on the workstation. Before approving production
measurements or signing release media, verify the eight-device fresh challenge
and refresh window on the target. Authenticate each disk, firmware and
measurement manifest and record their digests in the signed build inventory.
Observe DNS and egress during the first pull, quote and background refresh.
