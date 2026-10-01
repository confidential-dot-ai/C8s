# Local candidate build inputs

This feature branch includes the public module certificate and kernel snapshot
used by the current local candidate image. They are local build inputs, not
new production release inputs. Linux is 6.18.49. ConfOS source is
`e630fd13b5fca9d66c9549faa54427dd027806a4`.

The matching private module signing key was deleted after the earlier build.
It is not in this repository. Reuse only the verified signed GPU cache at
`/home/dobby/projects/wt/codex-candidate-confos-builder/output/gpu`.
The internal build script checks the cache fingerprint and kernel inputs.
A cache miss stops the build.

Rebuild the C8s binary from this branch HEAD before the node image build.
Use the unchanged core-image tag `local-candidate-61f2878e-20261001`.
The application chart needs the Unix attestation URL. This node change grants
its `cds-attest` container the read-only socket mount. Neither change has been
deployed. The existing image and encrypted disks must be retained for rollback.
