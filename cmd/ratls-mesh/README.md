# ratls-mesh

Transparent L4 TCP proxy that wraps pod-to-pod Kubernetes traffic in RA-TLS (Remote Attestation TLS). Each node runs one DaemonSet pod that intercepts TCP flows whose source and destination are known pod IPs, establishes hardware-attested mTLS to the destination node, and delivers traffic to local pods on the inbound side. Applications require zero modification.

See [DESIGN.md](DESIGN.md) for architecture, trust model, and design decisions.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ratls-mesh ./cmd/ratls-mesh
```

## Usage

### Proxy mode (default)

```bash
ratls-mesh \
  --platform sev-snp \
  --attestation-api-url http://localhost:8400 \
  --outbound-port 15001 \
  --inbound-port 15006 \
  --health-port 15021
```

Node IP is auto-detected from the `NODE_IP` environment variable (Kubernetes downward API) or set via `--node-ip`.

### Subcommands

```bash
# Watch Kubernetes pods and keep iptables/ipset routing current
ratls-mesh iptables-sync --outbound-port 15001 --uid 1337

# Remove iptables NAT rules and ipsets; with --keep-guard the fail-closed
# filter guard (cw chains + cw pod ipsets) survives: unmeshed inbound and
# non-TCP egress are still dropped; TCP to non-pod destinations was never meshed
ratls-mesh iptables-cleanup --keep-guard
```

## Routing Model

In the Helm chart, "known pod IP" means a non-hostNetwork Pod IP observed from
the Kubernetes API. `iptables-sync` maintains separate IPv4/IPv6 ipsets for all
known pods and for pods scheduled on the current node.

| Flow | Intercepted? | Why |
|------|--------------|-----|
| Same-node pod TCP to a known pod IP | Yes | Host `PREROUTING` matches source in the local-pod ipset (pods scheduled on this node) and destination in the all-pod ipset. |
| Host process TCP to a known pod IP | Yes, unless its UID is excluded | Host `OUTPUT` matches destination in the all-pod ipset and skips the mesh UID plus `--exclude-uids`. |
| Mesh proxy TCP to a destination node inbound port | No | The destination is a node IP, not a pod IP, and the mesh UID is excluded from `OUTPUT`. |
| ClusterIP Services, kube API, metadata, and public egress | No | The destination is not a pod IP when the mesh chains run, so these flows fall through without static pod CIDRs. |
| External or ingress TCP directly to a pod IP | No | The source is not in the local-pod ipset. |

The outbound listener also validates the original destination before proxying:
direct connections to the host-network listener are rejected unless the original
destination is a known pod IP. The inbound listener only forwards to local
non-hostNetwork pod IPs.

### Confidential-workload inbound guard

The flows the mesh does not intercept would otherwise reach pods in
plaintext, including confidential workloads: a ClusterIP Service selecting
cw pods hands kube-proxy a VIP the mesh never matches, and sources in
`--exclude-source-namespaces` dial pod IPs directly. With
the always-on cw inbound guard, `iptables-sync` maintains an extra ipset of
pod IPs labeled `confidential.ai/cw` and a filter-table chain (`RATLS-MESH-CW`,
jumped from `FORWARD` position 1) that drops any connection to those IPs, all
protocols (the mesh carries only TCP, so non-TCP inbound is unmeshed by
definition). Replies to cw-pod egress pass via a conntrack
`ESTABLISHED,RELATED` rule. Because some dataplanes (e.g. GKE Dataplane V2 /
Cilium) do not track a reply as `ESTABLISHED` on `FORWARD`, the guard also
RETURNs replies from a configurable source-port allowlist
(`--cw-inbound-passthrough`, chart `ratlsMesh.cwInboundEnforcement.passthrough`,
default `udp:53,tcp:53` so DNS resolves); an empty list is the strict
drop-all posture. An exemption is bounded to reply traffic: the destination
port must fall in the stock ephemeral window (32768-60999), and a TCP
exemption additionally matches only the handshake reply and segments with
SYN clear, so no TCP exemption can open a connection to a cw pod's own
listening ports. UDP has no equivalent gate, so a UDP exemption still admits
any datagram from the allowlisted source port into that window.

Every legitimate delivery path avoids `FORWARD` and is unaffected: mesh
delivery is a host-originated `OUTPUT` dial from the proxy UID, kubelet
probes and host daemons are `OUTPUT`, and meshed pod-to-pod egress is
DNAT'd to the node's outbound listener (`INPUT`) in `PREROUTING` before
`FORWARD`. Dropped packets are counted in
`ratls_mesh_iptables_cw_inbound_drops_total`, and packets admitted by an
exemption in `ratls_mesh_iptables_cw_passthrough_returns_total`.

The guard has two structural preconditions: kube-proxy must be in
iptables mode (so a Service VIP is DNAT'd to the cw pod IP *before*
`FORWARD`), and the packet must traverse the host `FORWARD` hook. Under
kube-proxy **IPVS** (or **nftables**) mode the director rewrites VIP
traffic in `LOCAL_IN`/`LOCAL_OUT` without a nat-table DNAT, so a same-node
VIP-to-cw-pod flow skips `FORWARD` and is not dropped. Verify with the e2e
check on any cluster not running iptables-mode kube-proxy.

What this defends: in-cluster plaintext bypass of confidential-workload
pods — Services selecting cw pods, direct pod-IP dials from excluded or
non-meshed sources, hostNetwork agents on other nodes. What it does not
defend: the hypervisor or cloud provider (the CVM boundary's job), host
root on the node itself (inside the node trust boundary; it delivers via
`OUTPUT`), kube-proxy IPVS/nftables mode and CNIs whose datapath bypasses
the host `FORWARD` hook (verified on iptables-mode kube-proxy with Azure
CNI and kubenet at `bridge-nf-call-iptables=1`; run the e2e check on
anything else), and L7 attacks through the legitimate mesh path.

Inbound delivery is still protected by RA-TLS on the node-to-node leg. The
only plaintext segment is the final host-to-local-pod dial on the destination
node. When the host exposes local pod-network CIDRs, `ValidateLocalDest`
cross-checks the destination Pod IP against those CIDRs and the kernel route.
On CNIs that do not expose a local pod CIDR on the host, such as AKS with
Azure CNI, the resolver falls back to the Kubernetes pod cache and only accepts
destinations whose `Pod.Status.HostIP` matches this node's `NODE_IP`.

## Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--platform` | `auto` | TEE platform: `sev-snp`, `tdx`, or `auto` (probes `/dev/{tdx_guest,sev-guest}`) |
| `--attestation-api-url` | (required) | URL of the local attestation-api (e.g. `http://localhost:8400`) |
| `--outbound-port` | `15001` | Outbound listener port (iptables redirect target) |
| `--inbound-port` | `15006` | Inbound listener port (RA-TLS from peer nodes) |
| `--node-ip` | `$NODE_IP` | This node's IP address |
| `--health-port` | `15021` | Health/metrics HTTP port |
| `--iptables-metrics-file` | `/tmp/ratls-iptables-metrics.json` | Shared file read from the `iptables-sync` sidecar for iptables/ipset counters |
| `--max-conns` | `0` | Max concurrent connections (0 = unlimited) |
| `--max-conns-per-source` | `0` | Max concurrent connections per source IP (0 = unlimited) |
| `--idle-timeout` | `0` | Close connections idle longer than this (0 = disabled) |
| `--keepalive` | `30s` | TCP keepalive interval (0 = disabled) |
| `--dial-timeout` | `5s` | Plain TCP dial timeout |
| `--tls-dial-timeout` | `10s` | RA-TLS dial timeout |
| `--dest-header-timeout` | `5s` | Inbound destination header read timeout |
| `--drain-timeout` | `30s` | Graceful shutdown drain timeout |
| `--local-cidr-boot-timeout` | `1s` | Synchronous retry budget at startup for host pod-network CIDR discovery; past this we fall through to the async refresh loop and `ValidateLocalDest` uses Kubernetes `Pod.Status.HostIP` ownership until discovery recovers |
| `--measurements` | `""` | Comma-separated hex SHA-384 launch measurements (empty = accept any TEE, warns) |
| `--cert-mode` | `self-signed` | Certificate mode: self-signed (default), cds (boots self-signed, upgrades to CDS-issued in background) |
| `--cds-url` | `""` | CDS service URL for attestation and CA bundle retrieval (required for cds mode) |
| `--cds-measurements` | `""` | Comma-separated SHA-384 hex launch measurements that CDS's RA-TLS peer cert must match. Empty = accept any (UNSAFE outside development) |
| `--ca-cert` | `""` | Path to CA certificate PEM for X.509 chain verification |
| `--ca-poll-interval` | `5m` | Interval for polling the CDS `/ca` endpoint for CA bundle updates (cds mode) |
| `--cert-ttl` | `24h` | Certificate lifetime; rotates at 50% of TTL |
| `--rotation-timeout` | `30s` | Max time for background certificate rotation |
| `--session-cache-size` | `64` | TLS session cache size per node (0 = disabled) |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### iptables sync flags

See "Routing Model" above for what `iptables-sync` watches and which flows
it intercepts. The flags below tune that loop.

| Flag | Default | Description |
|------|---------|-------------|
| `--outbound-port` | `15001` | Outbound listener port used as the REDIRECT target |
| `--uid` | `1337` | Mesh proxy UID to exclude from redirect |
| `--exclude-uids` | `0` | Comma-separated extra UIDs to skip, e.g. host root daemons |
| `--node-ip` | `$NODE_IP` | Local node IP used to maintain local pod source ipsets |
| `--resync-period` | `30s` | Periodic full ipset reconciliation interval |
| `--watchdog-period` | `2s` | Interval for re-asserting base-chain jumps at position 1 |
| `--ipset-maxelem` | `262144` | Maximum members per managed ipset |
| `--cw-inbound-passthrough` | `udp:53,tcp:53` | Comma-separated `proto:source-port` replies RETURNed before the always-on cw inbound guard's drop. Each entry matches only a destination port in 32768-60999 and, for TCP, a reply segment shape (see "Confidential-workload inbound guard"). Empty = strict drop-all; DNS is the default so get-cert can resolve |
| `--ready-file` | `""` | Path written after the first successful pod cache, ipset, and iptables sync |
| `--iptables-metrics-file` | `/tmp/ratls-iptables-metrics.json` | Shared file where `iptables-sync` publishes iptables/ipset counters for the proxy `/metrics` endpoint |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Certificate Modes

The `--cert-mode` flag controls how ratls-mesh obtains TLS certificates:

| Mode | Behavior |
|------|----------|
| `self-signed` | Default. RA-TLS self-signed certificates with attestation evidence embedded as X.509 extensions. Peers verify via hardware attestation chain. |
| `cds` | Boots with self-signed RA-TLS, then a background goroutine contacts CDS with exponential backoff (2s → 60s), obtains CA-signed certificates, and hot-swaps them. Once upgraded, stays on CA-signed certs. |

### Bootstrap flow (cds mode)

1. Proxy starts immediately with self-signed RA-TLS certificates (no CDS dependency at startup)
2. Background goroutine contacts CDS (one service): authenticate → attest → obtain leaf cert and authenticated CA bundle; CDS signs the CSR in-process
3. On success, `CertManager.SwapProvider()` hot-swaps to CA-signed certificates
4. `/ca` polling starts only after that authenticated CA bundle has seeded trust, and accepts only continuity-signed updates
5. Peer verification accepts BOTH RA-TLS attestation AND CA-chain during the transition (dual verification)
6. Once all nodes upgrade, CA-chain verification is the fast path

This design ensures zero-downtime upgrades — nodes can be upgraded from self-signed to CDS-issued certificates without service interruption.

**CA bundle wiring.** cds mode needs a CA trust root from CDS. The proxy
derives the CA bundle endpoint from `--cds-url` (the unified CDS serves
`/ca` on the same URL) and polls it every `--ca-poll-interval`.

### Dual verification

When `--ca-cert` is provided, the mesh accepts peers verified via either:
- A valid CA-signed certificate chain (fast path, standard X.509)
- A valid RA-TLS attestation extension (fallback, hardware verification)

This enables rolling upgrades where some nodes have CDS-issued certificates and others still use self-signed RA-TLS.

## Deployment

The supported chart path is `internal/helmchart/c8s/charts/ratls-mesh`, included
by the top-level `internal/helmchart/c8s` chart. The chart renders the proxy as
a DaemonSet and uses Kubernetes 1.29+ native sidecar init containers for iptables
synchronization and cleanup.

**Kubernetes version requirement.** The chart's `Chart.yaml` declares
`kubeVersion: ">=1.30.0-0"`. `iptables-cleanup` runs as a native sidecar
(`restartPolicy: Always` on an `initContainer`) so its `preStop` hook fires
last during shutdown and reliably tears down the managed chains/ipsets.
Kubernetes 1.28 exposed this behind the `SidecarContainers` feature gate, but
1.29 is the first release where the gate is enabled by default. Helm blocks the
install on older clusters via the `kubeVersion` constraint; do not bypass it.

The chart always renders `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet`; `iptables-sync` must run in the host network namespace to manage node-level pod traffic, so the value is not exposed.

Reviewer-relevant defaults:

| Value | Default | Effect |
|-------|---------|--------|
| `ports.inbound` | `15006` | Exposed as `hostPort` so peer nodes can establish RA-TLS sessions. |
| `ports.outbound` | `15001` | Container listener and REDIRECT target only; not exposed as `hostPort`. |
| `iptablesSync.resyncPeriod` | `30s` | Periodic reconciliation of pod ipsets and iptables rules. |
| `iptablesSync.ipsetMaxElem` | `262144` | Maximum size for each managed ipset. |
| `excludeUids` | `"0"` | Excludes root-owned host daemon traffic from `OUTPUT` redirect in addition to the mesh UID. |
| `ratlsMesh.measurements` | `[]` | SHA-384 hex launch digests mesh peers must present (wired to `--measurements`); empty accepts any (UNSAFE outside dev). CDS's peer cert is pinned from the parent `cds.measurements` (wired to `--cds-measurements`). |

## Observability

### Health probes

```
GET :15021/live    → 200 (always)
GET :15021/ready   → 200 (ready) / 503 (not ready or shutting down)
GET :15021/metrics → Prometheus text format
```

### Metrics

All metrics are prefixed with `ratls_mesh_`. Key metrics:

- `ratls_mesh_active_connections{direction}` — current open connections
- `ratls_mesh_connections_total{direction,result}` — total connections
- `ratls_mesh_bytes_total{direction,side}` — bytes transferred
- `ratls_mesh_tls_dial_failures_total` — RA-TLS failures
- `ratls_mesh_route_errors_total` — routing failures
- `ratls_mesh_cert_mode{mode}` — active certificate mode (label-keyed; the configured-mode value is 1)
- Go runtime metrics (`go_goroutines`, `go_memstats_*`) and process metrics are exposed via the standard prometheus client collectors

Routing-path counters and gauges worth alerting on are documented in
"Recommended alerts" below.

### Recommended alerts

The signals below govern the security-relevant routing path. The thresholds
are starting points; tune to your scrape interval and pod churn.

| Signal | What it means | Suggested rule |
|--------|---------------|----------------|
| `ratls_mesh_resolver_local_cidrs == 0` | `ValidateLocalDest` has no host pod-network CIDRs for the route cross-check, so inbound pod delivery is using Kubernetes `Pod.Status.HostIP` ownership. Expected briefly at startup and expected persistently on CNIs that expose pod IPs without a host-local pod CIDR, such as AKS with Azure CNI. | Warn after 2× `--resync-period` (default 60s) when this is unexpected for the cluster CNI. |
| `rate(ratls_mesh_iptables_ipset_overflow_total[5m]) > 0` | Pod count exceeded `--ipset-maxelem`; the reconcile rejected the restore and the live ipset is stale. New pod IPs will not be intercepted until the operator bumps `iptablesSync.ipsetMaxElem`. | Page on any non-zero rate for 5+ minutes. |
| `rate(ratls_mesh_iptables_jump_position_violations_total[5m])` | Watchdog confirmed our PREROUTING/OUTPUT jump was demoted out of position 1 — typically kube-proxy reinserting `KUBE-SERVICES` ahead of us. Occasional events are normal; a steady positive rate indicates a fight with kube-proxy. | Warn when rate > 1/min sustained for 10 min; tune `--watchdog-period` (default 2s) downward if necessary. |
| `rate(ratls_mesh_iptables_jump_position_check_errors_total[5m])` | `iptables -S` failed during a watchdog tick. Watchdog reinserts defensively, so this is environmental noise, not a kube-proxy race. | Warn at a sustained rate to flag a stuck or busy `xtables.lock`. |
| `rate(ratls_mesh_outbound_dest_rejected_total{reason="host_addr"}[5m])` | The host-network listener was reached with the node IP or loopback as the original destination — only possible by dialing `:15001` outside the iptables REDIRECT path. This is the security signal; there is no legitimate cause. | Warn on any sustained rate. |
| `rate(ratls_mesh_iptables_cw_inbound_drops_total[5m]) > 0` | The cw inbound guard dropped packets: something reached a confidential-workload pod outside the mesh. Most security-relevant first — a dial crafted from an allowlisted reply source port (53) aimed at a cw pod's listening port, an attempt to ride the passthrough exemption into the pod; a Service VIP selecting cw pods; an excluded-namespace source; a direct cross-node pod-IP dial. In all of these the workload is protected and the signal identifies the client. One benign cause exists, and only where replies depend on the exemption at all (a dataplane that does not track the reply as `ESTABLISHED`): a pod that moved `net.ipv4.ip_local_port_range` outside the exemption window blackholes its own DNS here. The `RATLSMeshCWInboundDrops` alert description carries the triage path. | Warn on a sustained rate; investigate the source. |
| `rate(ratls_mesh_outbound_dest_rejected_total{reason="unknown_pod"}[5m])` | The outbound listener saw a destination that is not in the resolver's podMap — usually informer skew during pod churn, or a kube-proxy DNAT race after jump demotion. A small steady rate is normal. | Warn only on sustained spikes correlated with pod churn or `iptables_jump_position_violations_total`. |
| `time() - ratls_mesh_iptables_metrics_file_updated_at_seconds` | Seconds since the proxy last read a fresh snapshot from the iptables-sync sidecar. The sidecar's own watchdog/violation counters cannot signal a wedge after they stop being published; this gauge does. Gauge stays at 0 until the first successful read so cold-start alerts can filter on `> 0`. | Warn when `gauge > 0 and time() - gauge > 3 * <resync-period>` (default `> 90s`). |

### Logs

JSON structured logs to stdout. Each connection gets a unique `conn` ID:

```json
{"level":"INFO","msg":"connection done","conn":42,"dir":"outbound-ratls","dst":"10.244.1.5:8080","node":"10.0.0.2:15006","fwd":1024,"rev":512,"dur":"150ms"}
```

## Testing

```bash
# Focused unit and chart tests for this routing path
go test ./internal/cmds/ratlsmesh ./internal/helmchart ./cmd/c8s

# Compile Linux-only ratls-mesh tests that exercise iptables/ipset code
GOOS=linux GOARCH=amd64 go test -c -o /tmp/ratlsmesh-linux.test ./internal/cmds/ratlsmesh
```

Tests use fake SNP attestation reports, so no AMD hardware is required. Coverage
includes proxy data flow, RA-TLS handshakes, connection limits and drain,
resolver validation, health endpoints, metrics, iptables/ipset rule generation,
and Helm rendering for `hostNetwork`, `iptables-sync`, and hostPort behavior.

## Security

- [RA-TLS](../../docs/ratls.md) — the attested handshake, what it guarantees, and what it does not
