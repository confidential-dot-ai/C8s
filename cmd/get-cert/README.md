# get-cert

A CLI tool for obtaining TLS certificates through the CDS (Certificate Distribution Service) TEE attestation flow. It generates an ECDSA P-256 key pair for every certificate it requests, creates a CSR with the selected Subject Alternative Name (SAN), runs the full attestation-verification-certification flow via cds, and publishes the key and the certificate as one credential generation.

Designed to run as a native sidecar alongside the credential consumers that read that volume.

A Pod CVM instead uses `internal/cmds/getcert.RunGuest` from its measured guest
broker. It reuses generation validation and renewal with fresh Pod claims;
there is no get-cert container or node-service socket in that Pod. See
[Pod CVM issuance](../../docs/armtls.md#pod-cvm-issuance) and
[operator setup](../../docs/operator.md).

## Usage

These pod examples use the node attestation socket mounted at
`/run/c8s/workload-claims/attestation-api.sock` and a memory-backed `/tls`
volume. get-cert also needs the node inventory's socket in that directory,
unless `--no-workload-claims` says the node runs none.

Obtain a certificate with a DNS SAN:

```bash
get-cert \
  --cds-url https://cds:8443 \
  --image-policy-file cds-pin.json \
  --attestation-api-url unix:///run/c8s/workload-claims/attestation-api.sock \
  --san api.example.com \
  --cert-path /tls/cert.pem \
  --key-path /tls/key.pem \
  --ca-path /tls/ca.pem
```

The example names CDS and pins it with `cds-pin.json`, the pin
`c8s cds config new` wrote, for a pod whose node supplies neither. The node's
admission plugin mounts the CDS address at `/run/c8s/cds-address` and its pins
at `/run/c8s/cds-pins.json` into an injected sidecar. get-cert then reads each
from its mount and refuses the flag that would also supply it:
`--cds-url` for the address, `--image-policy-file` or `--image-policy-json`
for the pins. While the pins and the node's attestation-api socket are both
mounted, `--attestation-api-url` must be
`unix:///run/c8s/workload-claims/attestation-api.sock`.

`--san 10.0.0.1` requests an IP SAN instead, and `--no-san` requests none at
all — CDS then takes the subject from the verified workload identity.

## Credential generations

The leaf, key and CA are stored together under `generations/` in the directory
the three paths share. Resolve `current` once, then read all three files from
that directory for a consistent generation. The stable paths above are hard
links replaced independently, key first, then CA, then leaf; readers of those
paths can span generations during renewal. The leaf appears last so initial
readiness requires the key and CA paths too.

Every certificate request generates a fresh key. On a sidecar restart, a valid
stored generation remains available until a replacement is published. Every
response is validated first: matching key, chain to its own CA, this pod's
workload instance.

Replacing the CDS CA key requires recreating the pod. CA-watch renewal accepts
a changed CA certificate only under the pod's bound issuer key.

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cds-url` | | *(empty)* | URL of the running cds service; required unless the node hands this client a CDS endpoint, and refused in an injected sidecar |
| `--image-policy-file` | | *(empty)* | JSON pin document for the CDS endpoint, every entry bound to the launch file CDS runs on; required unless the node pins CDS |
| `--image-policy-json` | | *(empty)* | The same pin document inline; excludes `--image-policy-file` |
| `--attestation-api-url` | | *(required)* | URL of the node attestation-api; pods use its mounted Unix socket. A literal `$(NODE_IP)` is replaced by the address in `/run/c8s/node-ip` and `$(HOST_IP)` by the `HOST_IP` environment variable; startup fails when that source is missing or not an IP address |
| `--san` | | | Subject Alternative Name — IP address or hostname; one of `--san`, `--san-file` or `--no-san` is required |
| `--san-file` | | *(empty)* | Path to a file containing the certificate SAN |
| `--no-san` | | `false` | Request a certificate with no SAN, for a pod without the `confidential.ai/cw` annotation |
| `--cert-path` | | *(required)* | Path where the certificate chain PEM of the published generation is read |
| `--key-path` | | *(required)* | Path where the private key PEM is read, mode `0600` (`0640` in shared setgid directories); must be in the `--cert-path` directory, on a memory-backed filesystem |
| `--ca-path` | | *(required)* | Path where the mesh CA PEM is read; must be in the `--cert-path` directory |
| `--renew-interval` | | `0` | Re-obtain the certificate at this interval; `0` runs once and exits |
| `--renew-jitter-percent` | | `20` | Shorten each renewal delay by a random fraction of itself, up to this percent; `0` disables |
| `--ca-watch-interval` | | `1m` | With `--renew-interval`, poll CDS at this interval. Renew at once when CDS serves a renewed CA certificate under the pod's bound CA key; with a workload identity assertion, also renew after a random delay of up to half the interval when CDS serves another allowlist policy than the one the leaf was stamped under. Replacing the CA key requires pod recreation. `0` disables; otherwise at least `1s` |
| `--unnamed-renew-interval` | | `30s` | With `--renew-interval`, fast-poll renewal while the leaf carries no matched-workload stamp, starting at 2s and doubling up to this value; `0` disables |
| `--expected-workload` | | *(empty)* | Allowlist entry this pod should be stamped with; a leaf stamped otherwise stays on the fast poll. Requires `--renew-interval` and a workload identity assertion |
| `--initial-retry-timeout` | | `2m` | Retry the first certificate request for up to this long before failing; `0` tries once |
| `--initial-retry-interval` | | `2s` | Delay between those retries; a refusal (403) or rate limit (429) backs off from here, doubling with jitter up to 5m |
| `--continue-on-initial-error` | | `false` | In renewal mode, keep running when the first certificate request fails, retrying until a certificate is issued |
| `--no-workload-claims` | | `false` | Request certificates without a workload identity assertion, for a pod whose node runs no admission inventory; the leaf then names no workload instance |
| `--workload-claims-timeout` | | `5s` | Timeout for the admission inventory request |
| `--measured-policies-file` | | `/run/c8s/workload-claims/measured-policies` | The node's journal of allowlist policies extended into TDX RTMR[3]; a TDX certificate request lists the policies it holds. Empty lists none |
| `--discovery-out` | | *(empty)* | Path to write JSON discovery metadata for the issued certificate and attestation evidence |
| `--discovery-cds-cert-url` | | *(empty)* | Public URL path where the CDS certificate PEM is served |
| `--discovery-mesh-ca-url` | | *(empty)* | Public URL path where the mesh CA PEM is served |
| `--discovery-public-tls-mode` | | `cds` | Public TLS mode to report in discovery metadata: `cds`, `webpki` or `acme` |
| `--discovery-public-tls-mode-file` | | *(empty)* | File holding the public TLS mode, read at start; replaces `--discovery-public-tls-mode` |
| `--discovery-public-tls-hostnames-file` | | *(empty)* | File holding launch-selected public hostnames; discovery reports the first without changing the CDS certificate SAN |
| `--verbose` | `-v` | `false` | Enable debug logging |

## Output path validation

Before generating keys or contacting cds, get-cert verifies that the output directories exist and are writable. This prevents requesting certificates that can't be saved.

`--cert-path`, `--key-path` and `--ca-path` must name three distinct files in one directory: one pointer covers a generation only if it covers all three. That directory must sit on a memory-backed filesystem (tmpfs or ramfs), because the private key is published in it and must never reach storage the host can read. In Kubernetes the injected cert volume is already a Memory-medium emptyDir, so this holds automatically; for manual runs point the paths at a tmpfs such as `/dev/shm`.

## SAN detection

The `--san` flag accepts either an IP address or a hostname. get-cert automatically detects which:

- **IP addresses** (IPv4 or IPv6) are added to the CSR as `IPAddresses`
- **Hostnames** are added as `DNSNames`

## Certificate TTL

Certificate lifetime is set server-side by cds: `--cert-ttl` (default and cap 24h) for a leaf with no matched-workload stamp, and `--named-cert-ttl` (default and cap 6h) for a named leaf. get-cert does not set the TTL.

For long-running pods, set `--renew-interval` shorter than the server-side TTL. The workload reads each republished generation as [Credential generations](#credential-generations) describes.
