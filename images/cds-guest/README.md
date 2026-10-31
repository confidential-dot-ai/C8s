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

The build writes `disk.raw`, `uki.efi`, `manifest.json`, `roothash` and one
`guest-smp<N>.igvm` per vCPU count. `manifest.json` carries the SNP launch
digests and the TDX measurement block a CDS pin is derived from.

## What the image contains

confos's `base` + `attest` profiles and this profile: the `c8s` binary at
`/usr/local/bin/c8s`, `cds.service`, and the attestation API on
`127.0.0.1:8400`. Its `attestation-api` is the attestation-rs build
`.github/build-pins.json` pins for the node images, so a cluster has one
verifier version. No RKE2, kubelet, container runtime or SSH server, and
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

No scratch disk is needed. The config is read-only, the allowlist store lives
in the unit's runtime directory, and the mesh CA stays in memory: a restart
re-bootstraps the trust root and a reboot leaves nothing behind.

If a CDS VM never answers on 8443, check launch-file staging and binding,
primary IPv4 assignment, and the route to AMD's or Intel's certificate
service. systemd restarts the service every 5s for as long as the VM runs.

[confos]: https://github.com/confidential-dot-ai/confidential-os-builder
