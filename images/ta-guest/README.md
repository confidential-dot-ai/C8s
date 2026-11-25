# images/ta-guest

The C8s Trust Authority image: the trust root (attestation, mesh CA, leaf signing) in its
own confidential VM, defined in THIS repo and built by
[confidential-os-builder][confos] acting purely as a builder.

Layout:

- `ta/` — the mkosi profile (`mkosi.conf`, `mkosi.sync`, `mkosi.finalize`,
  `mkosi.extra/`). Staged into the confos build via
  `confos build --profile-dir`; the dir basename **is** the profile name, so
  it must stay `ta`.
- `build` — the canonical entrypoint. `C8S_REF` selects the published C8s
  commit or tag whose `c8s` binary the image bakes; point `CONFOS_DIR` at a
  confos checkout (default: a sibling dir).

```sh
C8S_REF=abc1234 images/ta-guest/build   # -> output/ta/ in the confos checkout
```

The build writes `disk.raw`, `uki.efi`, `manifest.json`, `roothash` and one
`guest-smp<N>.igvm` per vCPU count. `manifest.json` carries the SNP launch
digests and the TDX measurement block a Trust Authority pin is derived from.

## What the image contains

confos's `base` + `attest` profiles and this profile: the `c8s` binary at
`/usr/local/bin/c8s`, `ta.service`, and the attestation API on
`127.0.0.1:8400`. Its `attestation-api` is the attestation-rs build
`.github/build-pins.json` pins for the node images, fetched by the manifest's
`attestation_api_digest` and by nothing a registry tag names on build day, so
a cluster has one verifier version. No RKE2, kubelet, container runtime or SSH server, and
cloud-init is disabled. A replica can use the Kubernetes API as its untrusted
policy-log store, through the credential described below.

Nothing platform-specific is baked, so one build measures the SNP launch
digests and the TDX block; the operator picks the TEE family at launch. The
image also holds no cluster-specific bytes: every setting that varies per
cluster arrives in the launch file below.

`.github/scripts/ta-guest-image-invariants.sh` gates all of that.

## Launch requirements

Every Trust Authority VM needs a disk labelled `opkeydata` (an ISO, or a KubeVirt volume
with that label) whose only file is `pubkey`: the Trust Authority config. The confos
initrd stages those exact bytes read-only at `/run/confai/operator-pubkey`
and binds them to the VM's identity — on TDX by extending their SHA-384 into
RTMR[3], on SNP by requiring HOST_DATA to equal their SHA-256 and halting
when it does not. `ta.service` runs
`c8s ta --config=/run/confai/operator-pubkey`: Trust Authority parses the file, takes a
fresh self-report from the attester on loopback, and exits unless that report
binds exactly the bytes it parsed. On TDX it
accepts the binding in the RTMR[3] seed this initrd extends, whatever
`MRCONFIGID` holds, or, for a guest that seeds no register, in `MRCONFIGID`
beside an all-zero RTMR[3]. The same report names the TEE family it
attests on, so the image carries no platform setting.

[Kata TA deployments](../../docs/cloud-ta.md#under-a-kata-containers-runtime)
use their own guest image and configuration mount.

A replica of a set (a config with an `ha` block, docs/ta-ha.md) finds its
own endpoint among `ha.endpoints` by asking each for its status. Its
Kubernetes store credential arrives over the attested HA API
(`c8s ta ha store-credential`). An etcd store instead needs a disk labelled
`cds-store`, mounted read-only at `/run/cds-store` and not measured, holding
the etcd client file `etcd.yaml`.

For signed policy input through the Kubernetes store, generate the launch file
with `c8s ta config new --ha-input-configmap policy-input` and `--ha-endpoint`.
The optional `ha.inputConfigMap` field is bound by the launch pin; an absent or
empty field leaves consumption disabled. The guest reads it after verifying the
launch file. Changing the input name requires a new launch configuration and pin.
See [signed policy input](../../docs/ta-ha.md#signed-policy-input-from-kubernetes).

No scratch disk is needed. The config is read-only, the allowlist store lives
in the unit's runtime directory, and the mesh CA stays in memory: a restart
re-bootstraps the trust root and a reboot leaves nothing behind.

A Trust Authority VM that never answers on 8443 has one of three causes: no launch file
(the unit is skipped), a binding the initrd refused (the VM halts), or no
route to AMD's or Intel's certificate service. systemd restarts the service
every 5s for as long as the VM runs.

[confos]: https://github.com/confidential-dot-ai/confidential-os-builder
