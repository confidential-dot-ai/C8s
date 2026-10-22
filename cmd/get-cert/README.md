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
  --attestation-api-url unix:///run/c8s/workload-claims/attestation-api.sock \
  --san api.example.com \
  --cert-path /tls/cert.pem \
  --key-path /tls/key.pem \
  --ca-path /tls/ca.pem
```

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
| `--cds-url` | | *(required)* | URL of the running cds service |
| `--cds-measurements` | | *(empty)* | Comma-separated SHA-384 hex launch measurements for CDS armTLS verification; empty accepts any attested CDS |
| `--attestation-api-url` | | *(required)* | URL of the node attestation-api; pods use its mounted Unix socket |
| `--san` | | | Subject Alternative Name — IP address or hostname; one of `--san`, `--san-file` or `--no-san` is required |
| `--no-san` | | `false` | Request a certificate with no SAN |
| `--cert-path` | | *(required)* | Path where the certificate chain PEM of the published generation is read |
| `--key-path` | | *(required)* | Path where the private key PEM is read, mode `0600` (`0640` in shared setgid directories); must be on a memory-backed filesystem |
| `--ca-path` | | *(required)* | Path where the mesh CA PEM is read |
| `--renew-interval` | | `0` | Re-obtain the certificate at this interval; `0` runs once and exits |
| `--ca-watch-interval` | | `1m` | With `--renew-interval`, compare CDS `/ca` against `--ca-path` and renew early for a changed certificate under the bound issuer key; also check allowlist policy unless `--no-workload-claims`. Replacing the CA key requires pod recreation. `0` disables |
| `--reload-nginx` | | `true` | SIGHUP nginx after certificate renewal or watched file changes |
| `--continue-on-initial-error` | | `false` | In renewal mode, keep running when the first certificate request fails |
| `--no-workload-claims` | | `false` | Request certificates without a workload identity assertion, for a pod whose node runs no admission inventory; the leaf then names no workload instance |
| `--verbose` | `-v` | `false` | Enable debug logging |

## Output path validation

Before generating keys or contacting cds, get-cert verifies that the output directories exist and are writable. This prevents requesting certificates that can't be saved.

`--cert-path`, `--key-path` and `--ca-path` must name three distinct files in one directory: one pointer covers a generation only if it covers all three. That directory must sit on a memory-backed filesystem (tmpfs or ramfs), because the private key is published in it and must never reach storage the host can read. In Kubernetes the injected cert volume is already a Memory-medium emptyDir, so this holds automatically; for manual runs point the paths at a tmpfs such as `/dev/shm`.

## SAN detection

The `--san` flag accepts either an IP address or a hostname. get-cert automatically detects which:

- **IP addresses** (IPv4 or IPv6) are added to the CSR as `IPAddresses`
- **Hostnames** are added as `DNSNames`

## Certificate TTL

Certificate lifetime is controlled server-side by cds's `--cert-ttl` flag (default 24h). get-cert does not set the TTL — configure it on the cds server.

For long-running pods, set `--renew-interval` shorter than the server-side TTL. When the workload is not nginx, pass `--reload-nginx=false` and have the workload reload the republished cert files using its own mechanism.
