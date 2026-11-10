# images/cds-guest

The C8s CDS image: the trust root (attestation, mesh CA, leaf signing) in its
own confidential VM, defined in THIS repo and built by
[confidential-os-builder][confos] acting purely as a builder.

Layout:

- `cds/` — the mkosi profile (`mkosi.conf`, `mkosi.sync`, `mkosi.finalize`,
  `mkosi.extra/`). Staged into the confos build via
  `confos build --profile-dir`; the dir basename **is** the profile name, so
  it must stay `cds`.
- `build` — the canonical entrypoint. `C8S_REF` selects the published C8s
  commit or tag whose `c8s` binary the image bakes; point `CONFOS_DIR` at a
  confos checkout (default: a sibling dir).

```sh
C8S_REF=abc1234 images/cds-guest/build   # -> output/cds/ in the confos checkout
```

To build an unmerged commit locally without publishing a container, first
commit the reviewed source and compile it from a clean checkout. Keep the
binary outside that checkout so Go records `vcs.modified=false`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off \
  go build -mod=readonly -trimpath -buildvcs=true -o /tmp/cds-native-c8s ./cmd/c8s
C8S_BINARY=/tmp/cds-native-c8s \
  C8S_BINARY_SHA256=$(sha256sum /tmp/cds-native-c8s | cut -d' ' -f1) \
  C8S_SOURCE_COMMIT=$(git rev-parse HEAD) \
  CONFOS_DIR=/path/to/pinned-confos images/cds-guest/build
```

Local mode requires a fresh builder checkout at the commit in
`.github/build-pins.json`, with no modified tracked files or untracked or ignored
files. This includes local mkosi configuration, overlays, prior outputs and
caches: their presence is rejected before the builder runs. Start each local
build in a new checkout; existing confos build caches are never admitted.
It also requires an explicit binary digest and Go build metadata identifying
the clean source commit, static Linux/amd64 build and C8s main package. `C8S_GO`
can select the Go executable used to inspect that metadata. The build snapshots the binary,
checks its digest again during staging, and records the source and binary
digests in `/usr/lib/cds/build.json` and `output/cds/c8s-source.json`.
These checks establish the selected source inputs; the build host and its
toolchain remain trusted, and the checks do not independently reproduce the
binary from its source. `C8S_REF` and the local inputs are mutually exclusive.

A local build may import a previously verified kernel with
`C8S_KERNEL_REUSE_DIR=/path/to/verified-kernel` and an independently recorded
`C8S_KERNEL_MANIFEST_SHA256`. That directory must contain only regular,
non-symlink `manifest.json` and `vmlinuz` files. After checking the fresh
checkout, the entrypoint copies and verifies the manifest and kernel hashes.
The pinned builder then recomputes all kernel input fingerprints before
accepting its kernel cache; mismatched inputs trigger a rebuild. This does not
reuse initrd, package, tools or guest-image caches. Retain the original build
receipt with the two files. `C8S_SOURCE_COMMIT` identifies the binary source;
record the image recipe commit separately when building a later recipe with
that unchanged binary.

Set `C8S_GUEST_ROLE=custody` with either source selection to build
`output/cds-custody/`, an SNP-only, two-vCPU, 4 GiB image. Its extra `custody/`
profile masks `cds.service` and starts only the fixed production command:

```text
c8s cds custody serve --config=/run/confai/operator-pubkey \
  --attestation-api-url=http://127.0.0.1:8400 --listen=:8443
```

The launch disk then carries the original public `c8s-cds-custody/v1` document.
The owner authenticates custody by its image and exact launch before supplying
short-lived storage sessions over mTLS. No owner private key, AWS profile or
storage credentials belong in the image or launch disk. The ordinary CDS image
continues to run `c8s cds` with the separately completed CDS launch document.

`C8S_GUEST_ROLE=native-workload` builds a separate qualification fixture for SNP
and TDX. It accepts only a local test executable from the same clean source
commit; `C8S_REF` and production `C8S_BINARY` inputs are rejected:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off \
  go test -c -mod=readonly -trimpath -buildvcs=true \
  -o /tmp/cds-native-workload.test ./internal/cmds/cds
C8S_GUEST_ROLE=native-workload \
  C8S_NATIVE_WORKLOAD_BINARY=/tmp/cds-native-workload.test \
  C8S_NATIVE_WORKLOAD_SHA256=$(sha256sum /tmp/cds-native-workload.test | cut -d' ' -f1) \
  C8S_SOURCE_COMMIT=$(git rev-parse HEAD) \
  CONFOS_DIR=/path/to/fresh-pinned-confos images/cds-guest/build
```

The output is `output/cds-native-workload/`. Its fixed unit masks `cds.service`
and runs only `/usr/local/bin/cds-native-workload.test`
`-test.run=^TestObjectNativeWorkloadGuest$ -test.timeout=0` with
`C8S_OBJECT_NATIVE_WORKLOAD=1`. The launch document uses
`c8s-cds-native-workload/v1`; the fixture exposes its owner API on 8443 and
attested inventory on 1019. Its unit retains only `CAP_NET_BIND_SERVICE`,
and its code obtains attestation through the local attester on 8400. It powers
off on exit or after its 75-minute service lifetime and never restarts.
This image is for native qualification only and is never a production CDS role.

All variants disable systemd credential imports in the measured command line
and mask console logins, recovery shells, guest command agents and generators
that create units from host inputs. The custody unit drops Linux capabilities
and requests hardware device access restricted to its SNP guest device. Device
ACLs require kernel support: the pinned kernel disables `CONFIG_BPF_SYSCALL`,
so cgroup v2 device isolation must not be assumed from the unit settings alone.
Native enforcement remains unqualified. The image finalizer
rejects extra CA roots in both the TLS bundle and certificate directory:
download-proxy trust stays in the build tools, while S3 TLS terminates inside
the guest using distribution public roots.

The shared image finalizer sets `require_crl = true` in the measured attester's
`[certs]` table. SNP verification then rejects unavailable or unverifiable CRL
evidence. This applies to CDS, custody and the native workload fixture;
certificate prefetch and startup deadlines remain unchanged.
The current pin still lacks ASK/ASVK serial revocation and correct VLEK CRL
selection; a qualified verifier update is required before production.

Run `python3 images/cds-guest/test_inputs.py` for local source-selection and
trust-root rejection checks. These use a stub builder and never create an
image, publish an artifact, or access a cluster.

The build writes `disk.raw`, `uki.efi`, `manifest.json`, `roothash` and one
`guest-smp<N>.igvm` per vCPU count. `manifest.json` carries the SNP launch
digests and the TDX measurement block a CDS pin is derived from.

## What the image contains

confos's `base` + `attest` profiles and this profile: the `c8s` binary at
`/usr/local/bin/c8s`, `cds.service`, and the attestation API on
`127.0.0.1:8400`. Its `attestation-api` is the attestation-rs build
`.github/build-pins.json` pins for the node images, fetched by the manifest's
`attestation_api_digest` and by nothing a registry tag names on build day, so
a cluster has one verifier version. No RKE2, kubelet, container runtime or SSH server, and
cloud-init is disabled. The CDS never talks to a Kubernetes API.

Nothing platform-specific is baked, so one build measures the SNP launch
digests and the TDX block; the operator picks the TEE family at launch. The
image also holds no cluster-specific bytes: every setting that varies per
cluster arrives in the launch file below.

`.github/scripts/cds-guest-image-invariants.sh` gates all of that.

## Launch requirements

Every CDS VM needs a disk labelled `opkeydata` (an ISO, or a KubeVirt volume
with that label) whose only file is `pubkey`: the CDS config. The confos
initrd stages those exact bytes read-only at `/run/confai/operator-pubkey`
and binds them to the VM's identity — on TDX by extending their SHA-384 into
RTMR[3], on SNP by requiring HOST_DATA to equal their SHA-256 and halting
when it does not. `cds.service` runs
`c8s cds --host=auto --config=/run/confai/operator-pubkey`: CDS parses the file, takes a
fresh self-report from the attester on loopback, and exits unless that report
binds exactly the bytes it parsed. The same report names the TEE family it
attests on, so the image carries no platform setting. The service selects the
guest's primary IPv4 address for its client and replica peer listeners.

No scratch disk is needed. The config is read-only and active CDS state lives
in guest memory. An object-state CDS recovers its encrypted committed state
through custody; a configuration without object-state recovery retains its
existing in-memory bootstrap behavior.

If a CDS VM never answers on 8443, check launch-file staging and binding,
primary IPv4 assignment, and the route to AMD's or Intel's certificate
service. systemd restarts the service every 5s for as long as the VM runs.

[confos]: https://github.com/confidential-dot-ai/confidential-os-builder
