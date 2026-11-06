# Node image lint tools

Go programs the `node-guest-image lint` workflow runs against the profile
sources in `../c8s`. Nothing here is staged into an image: `../c8s` is what
`images/node-guest/build` hands to mkosi as the profile directory, and these
live outside it so the image repro gate does not rebuild on tool-only changes.

| Tool | Holds |
|---|---|
| `containerdcheck` | Every containerd runtime handler in the baked config reaches the measured wrapper |
| `systemfloor` | Every system image in `image-policy.yaml.in` matches the digest in the pinned RKE2 bundles |
