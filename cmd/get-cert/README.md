# get-cert

A CLI tool for obtaining TLS certificates through the CDS (Certificate Distribution Service) TEE attestation flow. It generates (or loads) an ECDSA P-256 key pair, creates a CSR with a specified Subject Alternative Name (SAN), and runs the full attestation-verification-certification flow via cds.

Designed to run as a Kubernetes init container or renewal sidecar alongside a workload that uses the obtained certificate.

## Usage

These pod examples use the node attestation socket mounted at
`/run/c8s/workload-claims/attestation-api.sock` and a memory-backed `/tls` volume.

Obtain a certificate with a DNS SAN:

```bash
get-cert \
  --cds-url https://cds:8443 \
  --attestation-api-url unix:///run/c8s/workload-claims/attestation-api.sock \
  --san api.example.com \
  --out /tls/cert.pem \
  --key-out /tls/key.pem
```

Obtain a certificate with an IP SAN:

```bash
get-cert \
  --cds-url https://cds:8443 \
  --attestation-api-url unix:///run/c8s/workload-claims/attestation-api.sock \
  --san 10.0.0.1 \
  --out /tls/cert.pem \
  --key-out /tls/key.pem
```

Use an existing private key:

```bash
get-cert \
  --cds-url https://cds:8443 \
  --attestation-api-url unix:///run/c8s/workload-claims/attestation-api.sock \
  --san api.example.com \
  --key /tls/key.pem \
  --out /tls/cert.pem
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--cds-url` | | *(required)* | URL of the running cds service |
| `--cds-measurements` | | *(empty)* | Comma-separated SHA-384 hex launch measurements for CDS armTLS verification; empty accepts any attested CDS |
| `--attestation-api-url` | | *(required)* | URL of the node attestation-api; pods use its mounted Unix socket |
| `--san` | | *(required)* | Subject Alternative Name — IP address or hostname |
| `--out` | `-o` | *(stdout)* | Path to write the signed certificate chain PEM |
| `--key` | | *(ephemeral)* | Path to an existing PEM private key for the CSR |
| `--key-out` | | | Path to write the private key PEM with mode `0600` (`0640` in shared setgid directories); must be on a memory-backed filesystem |
| `--renew-interval` | | `0` | Re-obtain the certificate at this interval; `0` runs once and exits |
| `--reload-nginx` | | `true` | SIGHUP nginx after certificate renewal or watched file changes |
| `--continue-on-initial-error` | | `false` | In renewal mode, keep running when the first certificate request fails |
| `--verbose` | `-v` | `false` | Enable debug logging |

## Output path validation

Before generating keys or contacting cds, get-cert verifies that the output directories for `--out` and `--key-out` exist and are writable. This prevents requesting certificates that can't be saved.

The `--key-out` directory must additionally sit on a memory-backed filesystem (tmpfs or ramfs): the private key must never reach storage the host can read. In Kubernetes the injected cert volume is already a Memory-medium emptyDir, so this holds automatically; for manual runs point `--key-out` at a tmpfs such as `/dev/shm`. The cert and CA outputs are public and carry no such restriction.

## SAN detection

The `--san` flag accepts either an IP address or a hostname. get-cert automatically detects which:

- **IP addresses** (IPv4 or IPv6) are added to the CSR as `IPAddresses`
- **Hostnames** are added as `DNSNames`

## Certificate TTL

Certificate lifetime is controlled server-side by cds's `--cert-ttl` flag (default 24h). get-cert does not set the TTL — configure it on the cds server.

For long-running pods, set `--renew-interval` shorter than the server-side TTL. When the workload is not nginx, pass `--reload-nginx=false` and have the workload reload the refreshed cert files using its own mechanism.
