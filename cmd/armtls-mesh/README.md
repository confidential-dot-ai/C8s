# armtls-mesh

The C8s mesh endpoint of one pod: a capability-less native sidecar the
admission webhook injects into every pod it covers. A Pod CVM's measured guest
injects the same endpoint. It carries captured TCP over armTLS
(attestation-rooted TLS) with credentials from get-cert on a node, or from the
guest-owned broker on a Pod CVM, and delivers inbound mesh connections to the
destination the kernel recorded. Applications need no modification.

The pod's packet rules are the node enforcer's
(`internal/podmesh/ruleset`), installed before any container of the pod runs
and verified before each one; this process never touches them. See
[docs/armtls.md](../../docs/armtls.md) for the trust model.

For a Pod CVM, guest forwarding preserves the declared application port through
provider address translation; the endpoint refuses direct connections to its
internal capture listener. Only exact peer address-and-port tuples configured
in the signed launch document are reachable. See
[operator setup](../../docs/operator.md) for launch flags and HTTP probes.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o armtls-mesh ./cmd/armtls-mesh
```

## Usage

```bash
armtls-mesh \
  --cert-path /etc/c8s/certs/tls.crt \
  --key-path /etc/c8s/certs/tls.key \
  --ca-path /etc/c8s/certs/ca.crt
```

The capture ports default to the ones the node's measured mesh policy
redirects to (15001 outbound, 15006 inbound) and the probes answer on 15021:
`GET /startupz` once the endpoint is initialized, `GET /readyz` once it holds
usable credentials and working listeners.
