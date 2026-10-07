# armtls-mesh Design Document

Transparent L4 proxy providing attestation-rooted TLS (armTLS) between Kubernetes nodes. One DaemonSet pod per node — all pods on a node share the same TEE identity.

## Architecture

```
Node A                                       Node B
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│  App Pod (10.244.1.5:8080)           │     │  App Pod (10.244.2.3:8080)           │
│            │                         │     │            ▲                         │
│  iptables NAT PREROUTING             │     │            │ (plaintext, local)      │
│  DNAT nodeIP:15001                   │     │            │                         │
│            │                         │     │            │                         │
│  ┌─────────▼──────────────────────┐  │     │  ┌─────────┴──────────────────────┐  │
│  │ armtls-mesh sidecar            │  │     │  │ armtls-mesh sidecar            │  │
│  │  :15001  outbound (NAT)        │  │     │  │  :15006  inbound               │  │
│  │   1. SO_ORIGINAL_DST           │  │     │  │   1. armTLS terminate          │  │
│  │   2. resolver: pod→node        │  │     │  │   2. read dest header          │  │
│  │   3. armTLS client dial ───────┼──┼─────┼──▶   3. validate local pod        │  │
│  │                                │  │     │  │   4. dial local pod            │  │
│  │  :15021  /metrics, /healthz    │  │     │  │  :15021  /metrics, /healthz    │  │
│  └────────────────────────────────┘  │     │  └────────────────────────────────┘  │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
              armTLS (TLS 1.3 rooted in TEE attestation)
```

Each sidecar runs both listeners; the diagram shows the outbound side
firing on Node A and the inbound side firing on Node B for clarity.
"Dial local pod" is the inbound→pod plaintext hop over the CNI bridge —
the only segment not protected by armTLS, bounded by the
`ValidateLocalDest` checks discussed under "Local vs remote path".

### Data flow

1. App sends TCP to `10.244.2.3:8080`
2. Host iptables NAT PREROUTING DNATs pod-to-pod TCP to this node's `nodeIP:15001` (outbound listener). OUTPUT REDIRECT covers host-originated traffic to pod IPs. Azure CNI counts a PREROUTING REDIRECT hit but never completes the redirected TCP connect; DNAT to the node-local listener follows the same path pods can reach directly.
3. Proxy reads original destination via `SO_ORIGINAL_DST`
4. Resolver maps pod IP `10.244.2.3` to node IP `10.0.0.2`
5. Outbound proxy opens armTLS to the destination node's `:15006` listener, even when the destination pod is on the same node
6. Outbound proxy sends `10.244.2.3:8080\n` as the destination header
7. Inbound listener reads header, validates the destination, dials local pod, pipes bytes
8. App receives response — unaware of the mesh

### Local vs remote path

**Resolver and armTLS path.** The resolver maps `podIP → nodeIP`; the outbound proxy always opens armTLS to that node's inbound listener, even when the destination is local. Same-node traffic dials this node's own `:15006`, and a pod connecting to its own pod IP takes the same round trip (one extra handshake, no application impact — packet captures of `:15001`/`:15006` showing self-traffic are intentional, not a routing loop). The uniform path fails closed on attestation before any application bytes move, and removes a class of bug in which a "local" routing decision could be silently wrong about where the destination actually runs.

**The plaintext leg.** Only the inbound→pod hop stays plain TCP, traversing the host's local delivery path to a local pod. It never leaves the node in the normal case — on a confidential VM, the packets stay inside SEV-SNP-protected memory and the hypervisor cannot observe them. The attack to defend is a forged `Pod.Status.HostIP` that claims a *remote* pod is local: the proxy would then dial it through the kernel routing table, the packets would exit the node via the CNI fabric, and a hypervisor-level observer could see plaintext.

When the host exposes pod-network CIDRs, `ValidateLocalDest` blocks that attack with two kernel-sourced checks independent of the apiserver hint: the destination IP must fall in a host pod-network CIDR read from `net.Interfaces()`, and the kernel's best route for that IP must leave through one of the interfaces that owned a matching CIDR. The discovery filter keeps non-loopback, up, broadcast-capable interfaces and drops three classes a forged `HostIP` could otherwise hide in: any interface carrying the node IP itself (the node fabric, including dual-stack addresses on the same NIC, not the pod bridge), point-to-point interfaces (wireguard, IPIP, GRE, VPN tunnels), and link-local or /32 host routes.

Some CNIs, notably AKS with Azure CNI, give pods fabric-routable IPs without exposing a host-local pod CIDR. On those nodes `armtls_mesh_resolver_local_cidrs` remains zero. In that degraded mode, `ValidateLocalDest` falls back to the Kubernetes pod cache: the destination must be a known Pod IP, and its `Pod.Status.HostIP` must equal this node's `NODE_IP`. The node-to-node leg is still armTLS/mTLS; the fallback only changes how the destination node authorizes the final local plaintext dial. Operators should alert on persistent `armtls_mesh_resolver_local_cidrs == 0` as "route cross-check unavailable" unless that is the expected CNI shape.

**Host compromise.** armTLS binds to the SEV-SNP/TDX attestation, not host integrity inside the TEE. A principal *outside* the CVM cannot forge an attestation report, so it cannot impersonate this node to a peer or induce a peer to leak data. It can still disrupt service — a compromised API server can misroute via a fake `HostIP`, the network can drop or RST packets, the hypervisor can pause the VM — but the inbound listener rejects forged local ownership when CIDR/route cross-checking is available. In HostIP fallback mode, Kubernetes pod placement is the locality authority for the final plaintext dial. A principal *inside* the CVM with host root is already on the wrong side of the attestation boundary: it shares TEE memory with the proxy and the local pods, so sniffing `:15001`/`:15006` is no different from reading pod memory directly, and it can rewrite routes, iptables/ipsets, or the proxy pod itself. On a *legitimately attested* node, that root can issue outbound armTLS using the node's identity — peers verify attestation, not which principal on the node initiated the traffic. The routing defenses described above (`ValidateLocalDest`, the CIDR/route cross-check when available, and the jump-position watchdog) target stale or adversarial Kubernetes metadata and CNI topology drift, not a sysadmin with kernel control. Keeping that root from existing post-boot is the launch policy's job (pin `--measurements`) and the platform's; this proxy does not defend against root inside the same TEE.

## Trust Model

Three security boundaries, layered:

### 1. Attestation-rooted TLS (armTLS)

Bootstrap certificates carry hardware attestation evidence from AMD SEV-SNP or Intel TDX. The report's `REPORTDATA` binds the TLS public key to the evidence, and peers verify that evidence against the configured measurement policy. The SEV-SNP trust chain is:

```
AMD Root Key (ARK) → AMD Signing Key (ASK) → VCEK → Attestation Report → TLS Key Binding
```

In CDS mode, CDS verifies fresh caller attestation before issuing a mesh certificate. Peers can then verify that certificate's chain against the mesh CA, relying on CDS's issuance checks. The TLS handshake proves possession of the corresponding private key in both paths.

### 2. Kubernetes resolver (routing hints)

The K8s informer watches Pod objects and caches `podIP → nodeIP` mappings. This is a routing optimization, **not a trust boundary**:

- **Compromised API server**: Can return wrong nodeIP → proxy dials wrong node → armTLS handshake fails if the target is not an attested peer. When host pod CIDRs are available, forged local ownership is also rejected by the CIDR/route cross-check. When the HostIP fallback is active because no host pod CIDR exists, Kubernetes pod placement is the locality source for the final inbound→pod dial.
- **Stale cache**: Pod deleted but IP reused → proxy dials old node → handshake fails or new pod responds → armTLS still validates
- **Unknown IP** (service VIP, external): Does not enter the proxy by default because iptables only redirects IPs in the pod ipsets

The resolver is purely advisory. armTLS is the actual trust anchor.

### 3. iptables interception

`NET_ADMIN` iptables rules in the host NAT PREROUTING chain DNAT pod-to-pod TCP traffic to this node's outbound listener (`nodeIP:15001`) when the source is a local pod IP and the destination is any known pod IP. OUTPUT REDIRECT rules cover host-originated traffic to pod IPs, where loop prevention via UID exclusion keeps mesh process traffic (UID 1337) out of the interception path. PREROUTING uses DNAT rather than REDIRECT because Azure CNI on AKS counts PREROUTING REDIRECT hits but does not complete the redirected pod TCP connect; DNAT to the node-local listener follows the same path pods can reach directly. ClusterIP Services, metadata, kube API, public egress, and direct external-to-pod traffic fall through because they are not local pod-to-pod egress flows. The outbound listener also rejects original destinations that are not known pod IPs, so direct connections to the host-network listener do not become plaintext proxy sessions.

The fall-through flows would reach pods in plaintext, which is unacceptable for confidential workloads specifically: a ClusterIP Service selecting cw pods lets kube-proxy DNAT VIP traffic straight to the pod. The always-on cw guard installs a filter-table chain (`ARMTLS-MESH-CW`, jumped from FORWARD position 1) that drops all-protocol traffic to an ipset of `confidential.ai/cw`-labeled pod IPs; a conntrack ESTABLISHED,RELATED RETURN passes replies to cw-pod egress. Because some dataplanes (e.g. GKE Dataplane V2 / Cilium) do not track a reply as ESTABLISHED on FORWARD, the chain also RETURNs replies from a source-port allowlist (`--cw-inbound-passthrough`, default `udp:53,tcp:53` so DNS resolves and get-cert works) ahead of the drop. An exemption is bounded to reply traffic: the destination port must fall in the stock ephemeral window (32768-60999), and a TCP exemption additionally matches only the handshake reply and segments with SYN clear, so no TCP exemption can open a connection to a cw pod's own listening ports. UDP has no equivalent gate, so a UDP exemption still admits any datagram from the allowlisted source port into that window. An empty list is the strict drop-all posture. Legitimate delivery never traverses FORWARD (mesh delivery and kubelet probes are host OUTPUT; meshed pod egress is DNAT'd to INPUT in PREROUTING), so the guard turns every plaintext bypass into a visible drop without touching the happy path. See the README "Confidential-workload inbound guard" section for the defended/not-defended list.

**Not protected by iptables**: UDP, raw sockets, and ICMP. DNS (UDP :53) is not intercepted. Kubernetes NetworkPolicy should complement iptables for non-TCP protocols to pods that are not cw-labeled (the cw guard above drops non-TCP inbound to cw pods). Both `iptables` (IPv4) and `ip6tables` (IPv6) rules are installed to prevent dual-stack bypass.

### Threat model

| Threat                               | Impact                                                                                                                                                                                                                                                                                                                                                                                           | Mitigation                                                                                                                                                                                                                                                                                             |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Compromised K8s API server           | Routing DoS (wrong node); attempted forged-HostIP relay is rejected before the inbound→pod plaintext dial when CIDR/route cross-checking is available. In HostIP fallback mode, Kubernetes pod placement is trusted for final-hop locality.                                                                                                                                                      | armTLS rejects non-TEE peers for the outbound→inbound leg. `ValidateLocalDest` cross-checks dst against host interface CIDRs and the kernel's best route interface when available; otherwise it only accepts known Pod IPs whose `Pod.Status.HostIP` matches the local node.                           |
| Host root / rogue node administrator | Can rewrite routing, iptables/ipsets, process credentials, or mesh pods on that node; local bypass is possible and a legitimately attested node identity may still be usable                                                                                                                                                                                                                     | Out of scope for in-guest routing controls. Treat host root as part of the node TCB; rely on node hardening, measured boot / measurement pinning, and cluster access controls. Other nodes still require armTLS attestation before accepting mesh traffic.                                             |
| Compromised pod application          | App-level data exposure                                                                                                                                                                                                                                                                                                                                                                          | Out of scope (TEE protects transport, not app logic)                                                                                                                                                                                                                                                   |
| Compromised control plane            | Can't forge attestation                                                                                                                                                                                                                                                                                                                                                                          | Hardware-rooted trust (AMD VCEK)                                                                                                                                                                                                                                                                       |
| Network attacker (MITM)              | Can't decrypt traffic                                                                                                                                                                                                                                                                                                                                                                            | TLS 1.3 + attestation binding                                                                                                                                                                                                                                                                          |
| Side-channel attacks                 | Potential data leakage                                                                                                                                                                                                                                                                                                                                                                           | SEV-SNP memory encryption (hardware limitation)                                                                                                                                                                                                                                                        |
| UID 1337 collision                   | Pod with `runAsUser: 1337` bypasses mesh entirely                                                                                                                                                                                                                                                                                                                                                | Enforce via admission webhook / OPA policy. Drop `CAP_SETUID` on application pods to prevent runtime UID switch.                                                                                                                                                                                       |
| UDP exfiltration                     | DNS, custom UDP protocols bypass mesh unencrypted                                                                                                                                                                                                                                                                                                                                                | Kubernetes NetworkPolicy restricting UDP egress                                                                                                                                                                                                                                                        |
| ICMP reconnaissance                  | Network topology mapping, covert channels                                                                                                                                                                                                                                                                                                                                                        | Kubernetes NetworkPolicy blocking ICMP egress                                                                                                                                                                                                                                                          |
| Raw socket bypass                    | Complete mesh bypass at IP layer                                                                                                                                                                                                                                                                                                                                                                 | Drop `CAP_NET_RAW` on application pods (PodSecurity or OPA)                                                                                                                                                                                                                                            |
| Inbound open relay                   | Compromised armTLS peer redirects to arbitrary local services                                                                                                                                                                                                                                                                                                                                    | Inbound destination validated against resolver cache (only known local pod IPs allowed)                                                                                                                                                                                                                |
| TLS cert reconnaissance              | Connecting client sees server attestation report (CPU model, measurements) before client auth                                                                                                                                                                                                                                                                                                    | Acceptable: attestation reports are designed to be public. The chart runs `hostNetwork: true`, so restrict port 15006 with host firewall, cloud security group, or CNI host-network policy controls if needed.                                                                                         |
| Metrics side channel                 | `/metrics` on `:15021` exposes per-direction connection counts, byte totals, and handshake/duration histograms (labels are `direction=inbound\|outbound\|outbound_same_node`, no per-peer breakdown). An off-node attacker on the same network can scrape it and infer **node-level** activity volume and timing — not pod-to-pod graph, but enough for traffic-volume correlation across nodes. | The chart runs `hostNetwork: true`, so `:15021` is reachable on the node IP. The proxy does not authenticate the endpoint by design (Prometheus scrape needs reachability). Restrict via host firewall, cloud security group, or CNI host-network policy so only the scrape source can reach the port. |
| Empty measurement policy             | Any TEE-attested binary accepted (no code identity check)                                                                                                                                                                                                                                                                                                                                        | Use `--measurements` flag to pin expected launch digests in production                                                                                                                                                                                                                                 |

## Protocol

### Destination header

When the outbound proxy dials the destination node's inbound port, the first data sent (before piping application bytes) is the destination header:

```
<host>:<port>\n
```

- Max size: 256 bytes (enforced by an `io.LimitedReader`)
- Read deadline: 5 seconds (configurable via `--dest-header-timeout`)
- Format: Standard `net.JoinHostPort` output (IPv6 addresses are bracketed: `[::1]:8080`)
- Validation: Parsed with `net.SplitHostPort` — invalid format is rejected

The header tells the inbound proxy where to deliver the traffic locally. It is sent in plaintext inside the already-encrypted TLS tunnel — no additional encryption needed.

### Buffered connection

After reading the destination header with `bufio.Reader`, any bytes already buffered (application data sent immediately after the header) must not be lost. The `bufferedConn` wrapper delegates `Read()` to the `bufio.Reader` while forwarding all other `net.Conn` methods to the underlying connection.

## Design Decisions

| Decision                               | Reasoning                                                                                                                                                                                                                                                                                                                                                               | Tradeoff                                                                                                                                                                                                                                        |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transparent L4 proxy                   | Apps need zero modification. Any TCP-based protocol (HTTP, gRPC, database protocols) works automatically.                                                                                                                                                                                                                                                               | Requires iptables redirect (Linux-only). No protocol-aware features (retries, circuit breaking).                                                                                                                                                |
| armTLS instead of Istio mTLS           | Istio trusts the control plane for identity — if istiod is compromised, all mTLS is meaningless. armTLS roots trust in AMD hardware, making control plane compromise a DoS issue, not a data leakage issue.                                                                                                                                                             | Requires AMD SEV-SNP hardware. More complex certificate handling.                                                                                                                                                                               |
| Node-level TEE boundary                | Azure CVMs run SEV-SNP at the VM level. All pods on a node share the same TEE. Per-pod TEE would require nested virtualization (not available on Azure).                                                                                                                                                                                                                | Can't distinguish between pods on the same node at the attestation level.                                                                                                                                                                       |
| K8s informer for pod→node mapping      | O(1) lookups via in-memory cache. Alternative (per-connection API call) would be too slow and create API server hotspot.                                                                                                                                                                                                                                                | Memory proportional to pod count. Watches all namespaces.                                                                                                                                                                                       |
| Pod ipsets for interception            | The chart watches Kubernetes Pods and redirects only actual non-hostNetwork pod IPs. This avoids static cluster CIDRs and adapts to new deployments and pod churn.                                                                                                                                                                                                      | Requires the `ipset` binary and kernel support; a stale watch can briefly miss a new pod IP until the next resync. The managed sets are rebuilt with `ipset restore` and an explicit `maxelem` limit.                                           |
| UID-based iptables exclusion           | Mesh process (UID 1337) must be exempt from redirect to prevent infinite loops. UID matching is the simplest Linux mechanism for this (host-side).                                                                                                                                                                                                                      | Fixed UID (must not collide with other processes).                                                                                                                                                                                              |
| `hostNetwork: true`                    | Required for iptables rules to see all pod traffic in the host network namespace. Without hostNetwork, the proxy only sees its own pod's traffic.                                                                                                                                                                                                                       | Pod uses host network stack (port conflicts possible). The outbound listener rejects non-pod original destinations; Kubernetes NetworkPolicy is not relied on for host-network ingress controls, so use host/CNI-level controls where required. |
| `hostPort` on inbound only             | Inbound port (15006) must be reachable from peer nodes. Outbound port (15001) is only accessed via iptables redirect (no external access needed).                                                                                                                                                                                                                       | Fixed port allocation per node for inbound.                                                                                                                                                                                                     |
| Channel semaphore for connection limit | Non-blocking try-send gives O(1) admission control. Rejected connections get immediate RST (fail-fast, no queuing).                                                                                                                                                                                                                                                     | Hard limit — no backpressure or queueing.                                                                                                                                                                                                       |
| `idleConn` deadline wrapper            | Per-I/O deadline reset catches zombie connections where one side stopped sending. Alternative (periodic health check per connection) would be more complex.                                                                                                                                                                                                             | Extra `SetReadDeadline`/`SetWriteDeadline` syscall per I/O operation.                                                                                                                                                                           |
| `sync.Pool` for 32KB buffers           | Reduces GC pressure under high connection churn. `*[]byte` (pointer to slice) prevents interface boxing.                                                                                                                                                                                                                                                                | Fixed buffer size. Pool may retain memory during low-traffic periods.                                                                                                                                                                           |
| Hand-written Prometheus format         | Zero external dependencies. The proxy is a single static binary with no runtime requirements beyond libc.                                                                                                                                                                                                                                                               | Must maintain format manually. No histograms (would require bucketing logic).                                                                                                                                                                   |
| Atomic counters (not histograms)       | Counters + gauges cover the essential observability needs. Histograms would add complexity without proportional value for an L4 proxy.                                                                                                                                                                                                                                  | Can't answer "what's the p99 connection duration?" from metrics alone (use logs).                                                                                                                                                               |
| `preStop` cleanup + sleep              | Runs `iptables-cleanup --keep-guard` before termination: the traffic-interception NAT rules are removed while the fail-closed filter guard stays live — unmeshed inbound and non-TCP egress are still dropped; TCP to non-pod destinations was never meshed. The 5s sleep gives K8s time to update endpoints after cleanup.                                             | Adds 5s to every pod termination.                                                                                                                                                                                                               |
| No retry logic                         | This is an L4 proxy — it doesn't understand the application protocol. Retrying at L4 would duplicate TCP streams, potentially causing data corruption. Retries belong in the application or L7 proxy.                                                                                                                                                                   | App-visible connection failures on transient network issues.                                                                                                                                                                                    |
| No connection pooling                  | Each app TCP connection maps 1:1 to a proxied connection. L4 transparency requires preserving connection boundaries.                                                                                                                                                                                                                                                    | armTLS handshake per connection (mitigated by cert caching).                                                                                                                                                                                    |
| Inbound destination validation         | Inbound handler validates destination IP against resolver cache (must be a known pod on this node). When host pod CIDRs are available, it also validates the kernel route to that IP independently of `Pod.Status.HostIP`. This prevents compromised armTLS peers from using the inbound listener as an open relay to localhost, metadata endpoints, or other services. | Bound to the k8s resolver. On CNIs with no host pod CIDR, final-hop locality relies on Kubernetes `Pod.Status.HostIP` ownership.                                                                                                                |
| Dual-stack iptables                    | Both `iptables` (IPv4) and `ip6tables` (IPv6) rules are installed. Prevents IPv6 traffic from bypassing the mesh on dual-stack clusters.                                                                                                                                                                                                                                | Requires `ip6tables` binary in container image.                                                                                                                                                                                                 |
| Measurement pinning                    | `--measurements` flag accepts expected SHA-384 launch digests. Without it, any valid TEE is accepted (logged as warning).                                                                                                                                                                                                                                               | Requires redeployment when binary changes.                                                                                                                                                                                                      |

## CDS Certificate Issuance

### Architecture

When `--cert-mode cds` is used, the mesh obtains CA-signed certificates via CDS attestation instead of self-signing:

```
Bootstrap (armtls-mesh dials CDS over its own self-signed armTLS cert):

  1. armtls-mesh                       boot with self-signed armTLS cert
                                      (provider = self-signed)

  2. armtls-mesh -> CDS                POST /authenticate
                <- CDS                challenge

  3. armtls-mesh -> attestation-svc    POST /attest (challenge nonce, pubkey)
                <- attestation-svc    SNP evidence

  4. armtls-mesh -> CDS                POST /attest (evidence + CSR)
                   CDS -> att-svc     verify(evidence)
                       <- att-svc     ok
                   CDS                signs the CSR in-process with the mesh CA
                <- CDS                leaf cert + CA bundle

  5. armtls-mesh                       SwapProvider() hot-swaps the TLS
                                      provider to the CA-signed cert

  6. armtls-mesh -> CDS                GET /ca (continuity-checked refresh)
                <- CDS                updated CA bundle
```

### CertProvider Abstraction

The `armtls.CertProvider` interface decouples certificate provisioning from the TLS stack:

```go
type CertProvider interface {
    Provision(ctx context.Context) (*tls.Certificate, time.Duration, error)
}
```

Two implementations:
- `SelfSignedProvider`: generates key, obtains hardware attestation, creates self-signed cert with attestation extension
- `cdsclient.Provider`: generates key, embeds an armTLS attestation extension in the CSR, performs CDS attestation flow, obtains a CA-signed cert and authenticated CA bundle, then uses `/ca` only for later continuity-checked bundle refreshes

The abstraction enables runtime provider swapping via `CertManager.SwapProvider()` — the old cert continues serving while the new one provisions.

### No Session Resumption

No armTLS configuration offers TLS session resumption: `crypto/tls` re-runs no peer verification on a resumed handshake (see `docs/armtls.md`, "No session resumption").

### Dual Verification

With `CACert` set on `ServerConfig` or `ClientConfig`, the `dualVerifyPeerCallback` accepts peers via two paths:

1. **CA chain** (fast path): `cert.Verify(x509.VerifyOptions{Roots: caPool})` — standard X.509 chain validation
2. **Embedded-evidence verification** (fallback): `VerifyCert(cert, policy, nonce)` — hardware attestation verification

This dual mode is essential for rolling upgrades:
- T=0: All nodes self-signed → all verify embedded evidence
- T=1: Some nodes upgraded to CA-signed → upgraded nodes verify via CA chain, others can still verify the preserved armTLS extension
- T=2: All nodes CA-signed → all verify via CA chain (fast path)

If both verification paths fail, the error includes both failure reasons for diagnostics.

### Bootstrap Design Decision

The mesh boots with self-signed armTLS first, then upgrades to CDS-issued certificates in the background. This design was chosen because:

1. **Zero startup dependency on CDS** — the mesh is immediately functional even if CDS is down or not yet deployed
2. **Rolling upgrade safety** — mixed clusters (some self-signed, some CA-signed) work correctly via dual verification
3. **Failure resilience** — if CDS upgrade fails, the mesh continues operating with self-signed armTLS
4. **No coordination needed** — each node upgrades independently on its own schedule

## iptables Rules

### Rule generation

The chart runs `iptables-sync`, which watches Pods and keeps four ipsets current:

- `ARMTLS-MESH-PODS` for IPv4 pod IPs
- `ARMTLS-MESH-PODS6` for IPv6 pod IPs
- `ARMTLS-MESH-LOCAL-PODS` for IPv4 pod IPs scheduled on this node
- `ARMTLS-MESH-LOCAL-PODS6` for IPv6 pod IPs scheduled on this node

`buildPodIPSetRules(outboundPort, uid, excludeUIDs, nodeIP)` produces NAT rules placed in dedicated `ARMTLS-MESH` and `ARMTLS-MESH-PREROUTING` chains, applied to `iptables` and `ip6tables` for dual-stack coverage:

```
-t nat -N ARMTLS-MESH                                                                    # create OUTPUT chain
-t nat -N ARMTLS-MESH-PREROUTING                                                        # create pod veth chain
-t nat -F ARMTLS-MESH                                                                    # flush stale OUTPUT rules
-t nat -F ARMTLS-MESH-PREROUTING                                                        # flush stale PREROUTING rules
-t nat -A ARMTLS-MESH -p tcp -m set --match-set ARMTLS-MESH-PODS dst -m owner ! --uid-owner 1337 --dport 1:65535 -j REDIRECT --to-port 15001
-t nat -A ARMTLS-MESH-PREROUTING -p tcp -m set --match-set ARMTLS-MESH-LOCAL-PODS src -m set --match-set ARMTLS-MESH-PODS dst --dport 1:65535 -j DNAT --to-destination <nodeIP>:15001
-t nat -I OUTPUT 1 -j ARMTLS-MESH                                                        # jump from OUTPUT before service DNAT
-t nat -I PREROUTING 1 -j ARMTLS-MESH-PREROUTING                                        # jump from pod veth path before service DNAT
```

All pod-to-pod TCP destination ports are sent through the mesh. OUTPUT uses
REDIRECT because it has local socket ownership and can exclude the mesh UID.
PREROUTING uses node-local DNAT for the node IP address family so pod-veth
traffic reaches the same listener path pods can dial directly on CNIs where
PREROUTING REDIRECT is counted but does not complete TCP connects. Loop
prevention comes from the destination pod ipsets plus mesh UID exclusion in
OUTPUT; armTLS inbound connections target node IPs, not pod IPs, so they do not
match the pod destination ipsets.

### Dedicated chain (T5 mitigation)

Rules are placed in custom chains instead of directly in OUTPUT or PREROUTING. This provides atomic stale rule cleanup: on startup, each chain is flushed (`-F`) before inserting new rules, clearing any remnants from a previous crash or version change. The jumps from OUTPUT to `ARMTLS-MESH` and PREROUTING to `ARMTLS-MESH-PREROUTING` are reinstalled at the head of the base chains so pod-IP matching runs before kube-proxy rewrites Service VIP traffic to endpoint PodIPs.

### Idempotent setup

```
for each iptables binary (iptables, ip6tables):
    create chain ARMTLS-MESH (idempotent: -N fails if exists)
    create chain ARMTLS-MESH-PREROUTING (idempotent: -N fails if exists)
    flush chain ARMTLS-MESH (clear stale rules)
    flush chain ARMTLS-MESH-PREROUTING (clear stale rules)
    add owner-aware host-originated redirect rules to ARMTLS-MESH
    add pod-to-pod PREROUTING node-DNAT rules to ARMTLS-MESH-PREROUTING
    delete stale or duplicate jump rules from OUTPUT and PREROUTING
    insert jump rules at position 1 in OUTPUT and PREROUTING
```

Running setup N times produces exactly one copy of each rule.

### Cleanup

`iptables-cleanup --keep-guard` (what the chart's preStop hook runs) removes the traffic-interception pieces — the OUTPUT and PREROUTING jumps, the nat `ARMTLS-MESH`/`ARMTLS-MESH-PREROUTING` chains, and the pod/local-pod ipsets — but **keeps the fail-closed guard**: the filter `ARMTLS-MESH-CW` and `ARMTLS-MESH-CW-EGRESS` chains, their FORWARD jumps, and the cw pod ipsets. Under the guard, unmeshed inbound and non-TCP egress are still dropped; TCP to non-pod destinations was never meshed. A full `iptables-cleanup` (no flag) additionally removes the guard. The preStop hook runs cleanup followed by a 5s sleep (separated by newline, not `&&`, so sleep always runs regardless of cleanup exit code).

The chart declares `iptables-cleanup` as the **first** native sidecar in `initContainers` so it starts before `iptables-sync` and the main proxy. The container itself runs only `trap 'exit 0' TERM; sleep 3600 & wait` — its sole purpose is to host the `preStop` hook. Because Kubernetes 1.29+ native sidecars stop in reverse init order by default, `iptables-cleanup`'s preStop fires **last** during pod termination, after the main proxy and `iptables-sync` have already exited. `iptables-sync` deliberately does **not** clean up its own rules on SIGTERM; cleanup is centralized here so a single chain-removal step runs once at the right moment in the shutdown sequence.

### Mesh-disabled window during sidecar restart

The cleanup→install boundary is a brief window in which pod-to-pod TCP on the node falls through `PREROUTING`/`OUTPUT` unintercepted. It opens when `iptables-cleanup`'s preStop removes the interception pieces, and closes when the new `iptables-sync` finishes `installIptablesRules` after `WaitForCacheSync` and `reconcilePodIPSets`. Two paths trigger it:

- **Rolling restart (normal).** Helm upgrade, image bump, or any DaemonSet rollout. The window is sub-second on a warm node but scales with image pull, scheduling delay, and informer cache sync size.
- **`--ipset-maxelem` change after an abrupt previous shutdown.** When the new sidecar starts and finds live ipsets whose `maxelem` differs from the requested value (because the previous pod exited without firing preStop), `reconcileLiveSetMaxElem` flushes the managed chains *before* destroying the stale sets, then waits for `reconcilePodIPSets` and `installIptablesRules` to repopulate everything. The rules-empty window is folded into the same startup gap and only extends it by the destroy+rebuild cost.

During the window the fail-closed guard stays live (`--keep-guard` in preStop keeps the filter chains and their ipsets installed): unmeshed inbound to a cw pod (FORWARD `ARMTLS-MESH-CW` drop) and non-TCP egress from one (`ARMTLS-MESH-CW-EGRESS` drop) are still dropped. The window therefore only affects pod-to-pod TCP that was previously DNAT-redirected, which is the mesh's soft-fail boundary for TCP — the same posture the guard has always had, now exercised over the restart boundary.

Operator implications:

- Alert on the `iptables-sync` container's restart count and startupProbe failure rate (via kube-state-metrics, e.g. `kube_pod_container_status_restarts_total`); the in-process watchdog metrics (`armtls_mesh_iptables_jump_position_*`) only fire after `installIptablesRules` completes and so cannot detect a wedged startup.
- When changing `--ipset-maxelem`, plan the upgrade as a rolling restart rather than a hot reconfigure; the destroy-then-rebuild path is intentionally cold-start-only.

### Jump-position watchdog

kube-proxy reconciles `nat/PREROUTING` periodically and reinserts `KUBE-SERVICES` at position 1. If our `ARMTLS-MESH-PREROUTING` jump is demoted below it, Service VIPs get DNAT'd to PodIPs **before** our chain runs and end up redirected through the mesh — broken Service semantics, not a security leak. iptables offers no hook priority, so true determinism is impossible; a dedicated `watchdog-period` goroutine (2s default) re-asserts the jump at position 1 and increments `armtls_mesh_iptables_jump_position_violations_total` whenever it has to act. Operators can alert on a non-zero rate to detect persistent races.

## Connection Lifecycle

### Accept → pipe → close

```
accept(conn)
├── connection limit check (semaphore try-send)
│   ├── rejected → close, increment connLimitRejected
│   └── accepted → activeConns.Add(1)
├── handler(ctx, conn)
│   ├── outbound: origDst → resolve → local/remote dial → pipe
│   └── inbound: read dest header → dial local pod → pipe
├── pipe(a, b)
│   ├── goroutine 1: io.CopyBuffer(a←b) with 32KB pool buffer
│   ├── goroutine 2: io.CopyBuffer(b←a) with 32KB pool buffer
│   └── CloseWrite on each direction when done (half-close)
├── log connection (conn ID, direction, bytes, duration, errors)
├── record metrics
└── defer: close conn, release semaphore, activeConns.Done()
```

### Idle timeout

Optional `idleConn` wrapper resets `SetReadDeadline`/`SetWriteDeadline` on every `Read`/`Write`. If no data flows for the configured duration, the OS closes the connection with a timeout error. Applied to both sides of the pipe.

### TCP keepalive

Set at listener level (`net.ListenConfig{KeepAlive: 30s}`) and dialer level (`net.Dialer{KeepAlive: 30s}`). Detects dead peers via TCP keepalive probes (OS-level, not application-level).

### Buffer pool

```go
var bufPool = sync.Pool{
    New: func() any {
        b := make([]byte, 32*1024)
        return &b  // pointer to slice avoids interface boxing
    },
}
```

Each direction of a pipe borrows a 32KB buffer from the pool. Returned after the copy completes. Under high connection churn, this prevents per-connection allocations.

## Resolver

### K8s resolver

Uses `SharedInformerFactory` to watch all Pod objects across all namespaces. The informer maintains a long-lived watch stream to the API server (single connection, not per-lookup).

```
Pod event → onPod/onDeletePod → update podMap (RWMutex-protected)
Resolve(podIP) → RLock → lookup podMap → compare hostIP to nodeIP → local/remote
```

Cache size is sampled every 10 seconds and exposed as a Prometheus gauge. The cache is bounded by the number of non-hostNetwork Pod IPs reported by the API server (entries are deleted on pod deletion events).

### Resolve logic

```
Resolve(podIP):
    ValidateOutboundDest(podIP):             → podIP in non-hostNetwork podMap and podIP ∉ {127.0.0.1, ::1, nodeIP}
    Resolve(podIP):
        if podIP ∈ {127.0.0.1, ::1, nodeIP}: → (nodeIP, local)
        if podIP in non-hostNetwork podMap:  → (hostIP, hostIP == nodeIP)
        else:                                → (podIP, remote)
```

The outbound listener first requires `ValidateOutboundDest=true`, so direct
connections to the host-network listener and non-pod destinations are rejected
before `Resolve` runs. Loopback and node IP destinations are rejected even if a
hostNetwork pod reports the node IP as its PodIP. Unknown IP fallback remains a
defensive resolver behavior but is not part of the normal chart interception
path.

### Local CIDR discovery

`ValidateLocalDest` uses host-discovered pod-network CIDRs as a route
cross-check before allowing the plaintext inbound→pod hop. When that CIDR
set is non-empty, the destination IP must fall within one of those CIDRs,
and the kernel's best route must use one of the matching interfaces. The
CIDR set comes from `net.Interfaces()` filtered to non-loopback, up,
broadcast-capable interfaces (see `selectLocalPodCIDRs` in
`resolver_k8s.go` and the discussion in §"Local vs remote path").

When no CIDRs are discovered, `ValidateLocalDest` falls back to Kubernetes
pod ownership instead of failing closed. The destination must still be a
known Pod IP, and the cached `Pod.Status.HostIP` must match this node's
`NODE_IP`. This is expected on CNIs that use fabric-routable pod IPs
without a host-local pod CIDR, such as AKS with Azure CNI. The
`ARMTLSMeshLocalCIDRRouteCheckUnavailable` alert marks this degraded route
cross-check state.

At construction, `bootstrapLocalCIDRs` polls discovery synchronously
within a deadline (`--local-cidr-boot-timeout`, default `1s`) so a CNI
bridge that comes up shortly after the pod starts does not leave
`ValidateLocalDest` in HostIP fallback until the first periodic refresh
tick (30s). The loop stops on the first non-empty result; past the
budget we fall through to the existing async refresh path. Context
cancellation short-circuits the wait so pod termination mid-startup is
not delayed.

### Informer skew between `iptables-sync` and the main proxy

The `iptables-sync` sidecar and the main proxy run independent Pod informers,
each consuming its own watch stream from the API server. When a Pod is added,
the two informers see the ADD event at slightly different times: the sidecar
may add the new pod IP to `ARMTLS-MESH-PODS` (so the kernel begins intercepting
traffic for it via OUTPUT REDIRECT and PREROUTING DNAT) a few hundred milliseconds before the proxy's resolver
updates its `podMap`. During that window, the outbound listener gets a
connection whose destination is not yet in its cache, `ValidateOutboundDest`
returns false, and the connection is rejected with `result=dest_rejected`.

This is a robustness blip, not a security gap — the failure mode is
reject-not-relay, the caller retries, and the second attempt succeeds once
the resolver has caught up. Operators should watch
`rate(armtls_mesh_outbound_dest_rejected_total{reason="unknown_pod"}[5m])`
for the skew baseline (small steady rate is normal during pod churn;
sustained spikes mean the informer is far behind) and
`rate(armtls_mesh_outbound_dest_rejected_total{reason="host_addr"}[5m])`
for the direct-dial signal (any sustained rate means something reached
`:15001` outside the iptables OUTPUT-REDIRECT / PREROUTING-DNAT path — alert on this without the
informer-skew noise). The metric is separate from `route_errors_total` so
it is not confused with origDst/parse failures.

## Observability

### Metrics

Proxy counters live in-process. `iptables-sync` publishes its sidecar counters
to `/tmp/armtls-iptables-metrics.json` in the shared emptyDir, and the proxy
folds that snapshot into the same Prometheus text output on `GET /metrics`.

| Metric                                                  | Type    | Labels                | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------- | ------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `armtls_mesh_active_connections`                        | gauge   | `direction`           | Currently open connections                                                                                                                                                                                                                                                                                                                                                                                    |
| `armtls_mesh_connections_total`                         | counter | `direction`, `result` | Total connections handled                                                                                                                                                                                                                                                                                                                                                                                     |
| `armtls_mesh_bytes_total`                               | counter | `direction`, `side`   | Bytes transferred                                                                                                                                                                                                                                                                                                                                                                                             |
| `armtls_mesh_tls_dial_failures_total`                   | counter | —                     | armTLS connection failures                                                                                                                                                                                                                                                                                                                                                                                    |
| `armtls_mesh_dial_failures_total`                       | counter | —                     | Plain TCP dial failures                                                                                                                                                                                                                                                                                                                                                                                       |
| `armtls_mesh_connection_limit_rejected_total`           | counter | —                     | Semaphore rejections                                                                                                                                                                                                                                                                                                                                                                                          |
| `armtls_mesh_route_errors_total`                        | counter | —                     | origDst/resolve/parse failures                                                                                                                                                                                                                                                                                                                                                                                |
| `armtls_mesh_dest_header_errors_total`                  | counter | `side`                | Inbound handshake (`side="handshake"`) and header read/write failures                                                                                                                                                                                                                                                                                                                                         |
| `armtls_mesh_inbound_dest_rejected_total`               | counter | —                     | Inbound destination rejected because it is not a local pod                                                                                                                                                                                                                                                                                                                                                    |
| `armtls_mesh_outbound_dest_rejected_total`              | counter | `reason`              | Outbound destination rejected: `host_addr` = direct dial outside the iptables interception path (OUTPUT REDIRECT / PREROUTING DNAT) (security signal); `unknown_pod` = informer skew baseline                                                                                                                                                                                                                 |
| `armtls_mesh_iptables_jump_position_violations_total`   | counter | —                     | Watchdog confirmed and repaired a demoted base-chain jump                                                                                                                                                                                                                                                                                                                                                     |
| `armtls_mesh_iptables_jump_position_check_errors_total` | counter | —                     | Watchdog could not read jump position and reinserted defensively                                                                                                                                                                                                                                                                                                                                              |
| `armtls_mesh_iptables_ipset_overflow_total`             | counter | —                     | Reconcile saw more pod IPs than `--ipset-maxelem` and left the set stale                                                                                                                                                                                                                                                                                                                                      |
| `armtls_mesh_iptables_pod_ipset_members`                | gauge   | —                     | Pod IPs in the interception ipset (v4+v6). Interception is membership-driven, so a fall means those pods stopped being redirected through the proxy                                                                                                                                                                                                                                                           |
| `armtls_mesh_iptables_cw_ipset_members`                 | gauge   | —                     | Confidential-workload pod IPs in the cw guard ipset (v4+v6). The guard only drops plaintext to addresses in this set, so zero is enforcement off, not a quiet node                                                                                                                                                                                                                                            |
| `armtls_mesh_iptables_cw_ipset_shrink_total`            | counter | —                     | Reconciles where the cw ipset came back smaller than the previous one. Expected on a scale-down; unexplained increments mean cw pods stopped being reported by the Kubernetes API                                                                                                                                                                                                                             |
| `armtls_mesh_iptables_cw_inbound_drops_total`           | gauge   | —                     | Packets dropped by the cw guard chain: non-mesh traffic to a confidential-workload pod. Also increments where replies depend on the exemption (untracked reply tuple) and a cw pod's `ip_local_port_range` sits outside the exemption window                                                                                                                                                                  |
| `armtls_mesh_iptables_cw_passthrough_returns_total`     | gauge   | —                     | Packets admitted by a cw guard passthrough exemption: reply traffic from an allowlisted source port that the dataplane did not track as `ESTABLISHED`                                                                                                                                                                                                                                                         |
| `armtls_mesh_iptables_metrics_file_updated_at_seconds`  | gauge   | —                     | Unix-seconds timestamp of the last sidecar metrics snapshot read by the proxy                                                                                                                                                                                                                                                                                                                                 |
| `armtls_mesh_resolver_cache_entries`                    | gauge   | —                     | Pod→node cache size                                                                                                                                                                                                                                                                                                                                                                                           |
| `armtls_mesh_resolver_local_cidrs`                      | gauge   | —                     | Host-discovered pod-network CIDRs guarding inbound local dials                                                                                                                                                                                                                                                                                                                                                |
| `armtls_mesh_resolver_last_event_timestamp_seconds`     | gauge   | —                     | Unix timestamp of the last informer event. "Informer alive", not "podMap mutated": advances on every ADD/UPDATE/DELETE including pending-phase pods with no HostIP/PodIPs. A stream of pending-state updates from a CrashLoopBackoff workload keeps this fresh while no routing state actually changes — `ARMTLSMeshResolverStale` is therefore a watch-stream liveness signal, not a cache-freshness signal. |
| `armtls_mesh_process_uptime_seconds`                    | gauge   | —                     | Seconds since start                                                                                                                                                                                                                                                                                                                                                                                           |

Go runtime and process metrics (`go_goroutines`, `go_memstats_*`, `process_resident_memory_bytes`, …) come from the standard prometheus client collectors and are exposed at the same `/metrics` endpoint.

### Health endpoints

| Endpoint       | Response                      | Purpose          |
| -------------- | ----------------------------- | ---------------- |
| `GET /live`    | Always 200                    | Liveness probe   |
| `GET /ready`   | 200 when ready, 503 otherwise | Readiness probe  |
| `GET /metrics` | Prometheus text               | Metrics scraping |

Readiness transitions:
- **False → True**: After both listeners bind and (for K8s resolver) cache sync completes
- **True → False**: Immediately on SIGTERM, before listeners close

### Structured logging

JSON to stdout via `slog.JSONHandler`. Every connection gets a monotonic `conn` ID for correlation:

```json
{"level":"DEBUG","msg":"inbound started","conn":42,"src":"10.0.0.1:54321"}
{"level":"INFO","msg":"connection done","conn":42,"dir":"inbound","dst":"10.244.1.5:8080","fwd":1024,"rev":512,"dur":"150ms"}
```

## Graceful Shutdown

```
SIGTERM received
    │
    ▼
onShutdown() → health.ready = false → /ready returns 503
    │                                  (K8s stops routing new traffic)
    ▼
Listeners close → accept loops exit
    │
    ▼
Wait for activeConns (up to --drain-timeout)
    ├── All connections drained → clean exit
    └── Timeout exceeded → warn and force exit
    │
    ▼
preStop hook (separate from Go process):
    iptables-cleanup → remove NAT rules
    sleep N          → allow endpoints to update
```

The chart's `terminationGracePeriod`, `drainTimeout`, and
`iptablesCleanup.preStopSleepSeconds` (defaults: `45s`, `30s`, `5`)
together bound the shutdown sequence. The chart fails the install when
`drainTimeout ≥ terminationGracePeriod` (zero preStop budget) or when
`preStopSleepSeconds > terminationGracePeriod - drainTimeout` (sleep
would be SIGKILL'd mid-cleanup, leaking iptables chains/ipsets across
the pod restart). Duration values use the Go single-unit form (`Ns` /
`Nm` / `Nh`) parsed by the `armtls-mesh.durationSeconds` helper so the
bound arithmetic stays exact.

## DaemonSet Deployment

### Security context

- **Pod level**: `seccompProfile: RuntimeDefault`
- **Init container**: `NET_ADMIN` capability (iptables), `readOnlyRootFilesystem`, runs as root
- **Main container**: UID 1337, `runAsNonRoot`, `readOnlyRootFilesystem`, no capabilities

### Probes

- **Startup**: `httpGet /ready` every 2s, 30 failures allowed (60s total for TLS provisioning + cache sync)
- **Readiness**: `httpGet /ready` with configurable period
- **Liveness**: `httpGet /live` with configurable period

### PodDisruptionBudget

`maxUnavailable: 1` — ensures `kubectl drain` respects `terminationGracePeriodSeconds` and at most one node loses mesh coverage during rolling upgrades.

### Prometheus scraping

Annotations on the pod template:
```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "15021"
prometheus.io/path: "/metrics"
```

## Certificate Lifecycle

Certificates are provisioned after the mesh listeners bind and cached in memory:

1. Generate ECDSA P-256 key pair
2. Compute `REPORTDATA = SHA-384(pubkey || nonce)`
3. Request attestation evidence from the attestation-api (`POST /attest` with REPORTDATA)
4. Extract raw attestation report from the structured evidence response
5. Embed attestation report in X.509 certificate extension
6. Cache certificate in `certState` (RWMutex-protected)
7. Check once per minute for renewal at 50% of TTL (default 24h → due at 12h)

Each certificate manager renews independently of traffic and retries failures through expiry. Valid cached certificates remain available during renewal. Expired certificates fail readiness, while timer-driven retries continue.

### CDS-Issued Certificates

When using `--cert-mode cds`, the lifecycle changes:

1. Initial boot: self-signed armTLS certificate (same flow as above)
2. Background goroutine contacts CDS: authenticate → attest → obtain cert and authenticated CA bundle
3. `CertManager.SwapProvider()` atomically swaps the provider:
   - Acquires lock, replaces provider, clears cert cache and rotation timer
   - Releases lock, provisions new cert synchronously
   - On success: new CA-signed cert served to all subsequent handshakes
   - On failure: old self-signed cert continues serving (error logged)
4. CA bundle polling starts only after the authenticated bundle has seeded trust, and accepts only continuity-signed updates from `/ca`
5. Rotation continues at 50% of TTL, now using the CDS provider
6. Peer verification uses `dualVerifyPeerCallback`: CA chain (fast) or embedded-evidence verification (fallback)

## Comparison to Alternatives

|                              | Istio ambient               | armtls-mesh                           | **cds-mode armtls-mesh**                    |
| ---------------------------- | --------------------------- | ------------------------------------- | ------------------------------------------- |
| **Trust root**               | istiod CA (software)        | AMD SEV-SNP (hardware)                | Mesh CA (issued after hardware attestation) |
| **Control plane compromise** | Full mTLS bypass            | DoS only (can't forge attestation)    | DoS only (CA is in-TEE sidecar)             |
| **Certificate issuance**     | Centralized CA              | Per-node self-signed with attestation | Per-node CA-signed after CDS attestation    |
| **Protocol**                 | L4/L7 (ztunnel + waypoint)  | L4 only                               | L4 only                                     |
| **Dependencies**             | istiod, ztunnel, CNI plugin | Single binary + iptables/ipset        | Single binary + iptables/ipset + CDS        |
| **Node-to-node encryption**  | HBONE (HTTP/2 tunnel)       | TLS 1.3 direct                        | TLS 1.3 direct                              |
| **Per-pod identity**         | SPIFFE identity per pod     | Node-level TEE identity               | Node-level TEE identity                     |
| **Hardware requirement**     | None                        | AMD SEV-SNP CVM                       | AMD SEV-SNP CVM + CDS infrastructure        |
