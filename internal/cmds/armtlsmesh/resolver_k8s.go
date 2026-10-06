//go:build linux

package armtlsmesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// podEntry stores the node IP and pod UID for a cache entry. The UID guards
// against stale delete events removing a newer pod's entry after IP reuse.
type podEntry struct {
	nodeIP string
	uid    types.UID
}

// localCIDRRefreshInterval bounds how stale the cached host-CIDR set can be
// when an interface comes up or changes addresses after the resolver
// started. Matches the iptables-sync resync cadence so the inbound-leg
// CIDR cross-check and the redirect ipsets converge on the same timeline.
const localCIDRRefreshInterval = 30 * time.Second

// defaultLocalCIDRBootTimeout is the fallback budget when newK8sResolver
// is given <=0. Picked to absorb a typical CNI-bridge startup race while
// staying well under the 60s startup-probe budget.
const defaultLocalCIDRBootTimeout = time.Second

// localCIDRBootInterval is the pause between bootstrap retries. var rather
// than const so tests can shrink it without burning wall-clock when they
// only want to exercise the loop's iteration logic.
var localCIDRBootInterval = 200 * time.Millisecond

// k8sResolver watches K8s Pods and maps podIP → nodeIP (hostIP).
// Trust model: the API server provides routing hints; ARmTLS attestation
// is the actual trust boundary. A compromised control plane can cause DoS
// (handshake failure to non-TEE node) but never data leakage.
type k8sResolver struct {
	nodeIP string // canonical (normalizeIP) form set in newK8sResolver
	logger *slog.Logger

	mu            sync.RWMutex
	podMap        map[string]podEntry // podIP → {hostIP, podUID}
	lastEventTime atomic.Int64        // Unix timestamp of last successful informer event

	// localCIDRs is a snapshot of this host's pod-network CIDRs and owning
	// interfaces derived from network-interface addresses (not from K8s
	// metadata). When this set is non-empty, ValidateLocalDest requires the
	// dst IP to fall within one of these CIDRs and the kernel's best route to
	// use one of the matching interfaces, so a stale or adversarial
	// Pod.Status.HostIP cannot cause the inbound listener to plaintext-dial a
	// pod that isn't actually on this node. CNIs that expose no host pod CIDR
	// use a Kubernetes HostIP fallback instead. Guarded by mu; the refresh
	// goroutine swaps the slice on transitions.
	localCIDRs []localCIDR

	// localRouteCheck is the kernel-route cross-check that gates the
	// inbound→pod plaintext hop. Always set — newK8sResolver wires
	// defaultLocalRouteCheck; tests override with a fixture. Invoked
	// without holding r.mu so /proc/net/route reads don't block other
	// resolver lookups; the function MUST NOT re-acquire r.mu or it will
	// deadlock under load.
	localRouteCheck localRouteCheckFunc

	// localCIDRSource gathers the live host CIDR snapshot. Always set —
	// newK8sResolver wires enumerateLocalPodCIDRs (hits the kernel via
	// net.Interfaces); tests override it to drive retry/refresh logic with
	// deterministic inputs.
	localCIDRSource func(string) ([]localCIDR, error)
}

var _ Resolver = (*k8sResolver)(nil)

// newK8sResolver creates a resolver backed by a K8s Pod informer. It blocks
// until the initial cache sync completes. localCIDRBootTimeout bounds the
// synchronous local-CIDR retry at startup; <=0 picks defaultLocalCIDRBootTimeout.
func newK8sResolver(ctx context.Context, clientset kubernetes.Interface, nodeIP string, localCIDRBootTimeout time.Duration, logger *slog.Logger) (*k8sResolver, error) {
	canonicalNodeIP := normalizeIP(nodeIP)
	if canonicalNodeIP == "" {
		return nil, fmt.Errorf("node IP %q must be a valid IP address", nodeIP)
	}
	r := &k8sResolver{
		nodeIP:          canonicalNodeIP,
		logger:          logger,
		podMap:          make(map[string]podEntry),
		localRouteCheck: defaultLocalRouteCheck,
		localCIDRSource: enumerateLocalPodCIDRs,
	}
	if localCIDRBootTimeout <= 0 {
		localCIDRBootTimeout = defaultLocalCIDRBootTimeout
	}
	r.bootstrapLocalCIDRs(ctx, localCIDRBootTimeout)

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { r.onPod(obj) },
		UpdateFunc: func(_, obj any) { r.onPod(obj) },
		DeleteFunc: func(obj any) { r.onDeletePod(obj) },
	}); err != nil {
		return nil, fmt.Errorf("k8s resolver: add event handler: %w", err)
	}

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return nil, fmt.Errorf("k8s resolver: cache sync failed")
	}

	r.lastEventTime.Store(time.Now().Unix())

	r.mu.RLock()
	count := len(r.podMap)
	r.mu.RUnlock()
	logger.Info("k8s resolver ready", "pods", count)

	// Re-run host-CIDR discovery periodically: a transiently-empty result at
	// startup (bridge not yet up, unusual CNI startup ordering) must not
	// permanently degrade ValidateLocalDest. The cadence is coarse — host
	// interface sets change rarely — so the cost is negligible.
	go r.runLocalCIDRRefreshLoop(ctx, localCIDRRefreshInterval)

	return r, nil
}

func (r *k8sResolver) onPod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	// lastEventTime is the "informer alive" signal, not "podMap mutated":
	// applyPod skips pods that have no HostIP / PodIPs yet (common during
	// the pending-pod phase), so gating the store on applyPod's return
	// would stall the gauge during normal churn and false-page any
	// `time() - gauge` alert.
	r.applyPod(pod)
	r.lastEventTime.Store(time.Now().Unix())
}

func (r *k8sResolver) applyPod(pod *corev1.Pod) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !podEligibleForMeshEndpoint(pod) {
		r.deletePodLocked(pod)
		return true
	}
	hostIP := normalizeIP(pod.Status.HostIP)
	if hostIP == "" {
		return false
	}
	podIPs := podStatusIPs(pod)
	if len(podIPs) == 0 {
		return false
	}
	entry := podEntry{nodeIP: hostIP, uid: pod.UID}
	for _, ip := range podIPs {
		r.podMap[ip] = entry
	}
	return true
}

func (r *k8sResolver) onDeletePod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.deletePodLocked(pod)
	r.lastEventTime.Store(time.Now().Unix())
}

// deletePodLocked removes pod's entries from the resolver's podMap.
// Caller must hold r.mu (write lock).
func (r *k8sResolver) deletePodLocked(pod *corev1.Pod) {
	// Only delete if the cached entry's UID matches this pod. A late delete
	// event must not remove a newer pod's entry after IP reuse — comparing
	// UIDs (not just hostIP) handles same-node IP reuse correctly.
	for _, ip := range podStatusIPs(pod) {
		if e, ok := r.podMap[ip]; ok && e.uid == pod.UID {
			delete(r.podMap, ip)
		}
	}
}

// normalizeIP returns the canonical net.IP.String() form of an IP literal,
// or "" if it doesn't parse. Used on both sides of the routing path — the
// resolver podMap and the ipset reconciler — so a non-canonical IPv6
// (e.g. "2001:db8:0:0:0:0:0:1") can't miss an exact-string lookup against
// the canonical form ("2001:db8::1") that SO_ORIGINAL_DST emits.
func normalizeIP(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func podStatusIPs(pod *corev1.Pod) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 1+len(pod.Status.PodIPs))
	add := func(ip string) {
		canonical := normalizeIP(ip)
		if canonical == "" {
			return
		}
		if _, ok := seen[canonical]; ok {
			return
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	add(pod.Status.PodIP)
	for _, pip := range pod.Status.PodIPs {
		add(pip.IP)
	}
	return out
}

// LastEventTime returns the Unix timestamp of the last successful informer event.
// Returns 0 if no events have been processed yet.
func (r *k8sResolver) LastEventTime() int64 {
	return r.lastEventTime.Load()
}

// CacheSize returns the number of pod→node mappings in the cache.
func (r *k8sResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.podMap)
}

// LocalCIDRCount returns the number of host-discovered pod-network CIDRs
// available for ValidateLocalDest's route cross-check. Zero means inbound
// delivery falls back to Kubernetes pod HostIP ownership until discovery
// finds a local pod-network CIDR.
func (r *k8sResolver) LocalCIDRCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.localCIDRs)
}

// Outbound reject reasons exposed as the `reason` label on
// armtls_mesh_outbound_dest_rejected_total. Two reasons exist:
//
//   - outboundRejectHostAddr: the original destination is loopback or the
//     node IP itself. The host-network listener cannot have been reached
//     via the iptables pod-IP REDIRECT path; this is the direct-dial
//     attack signal an operator should alert on.
//   - outboundRejectUnknownPod: a non-host IP that is not in the resolver
//     podMap. Expected at a low rate during pod churn (informer skew
//     between iptables-sync and the proxy), so it is a noisy baseline
//     rather than a security signal.
const (
	outboundRejectHostAddr   = "host_addr"
	outboundRejectUnknownPod = "unknown_pod"
)

// ValidateOutboundDest reports whether ip is a known pod IP and, when it is
// not, why. This keeps the host-network outbound listener from acting as a
// plaintext node service when reached directly instead of through an
// iptables REDIRECT to a pod IP, and lets the metric distinguish the
// direct-dial attack signal from the informer-skew baseline.
func (r *k8sResolver) ValidateOutboundDest(ip string) (bool, string) {
	if r.isHostAddress(ip) {
		return false, outboundRejectHostAddr
	}
	canonical := normalizeIP(ip)
	if canonical == "" {
		return false, outboundRejectUnknownPod
	}
	r.mu.RLock()
	_, found := r.podMap[canonical]
	r.mu.RUnlock()
	if !found {
		return false, outboundRejectUnknownPod
	}
	return true, ""
}

// ValidateLocalDest returns true if ip is a non-hostNetwork pod running on this
// node. Host loopback and node addresses are rejected so the host-network
// inbound listener cannot be used as a relay to host-local services. When
// host-discovered pod-network CIDRs are available, the IP must fall within one
// of them and the kernel's best route must use one of that CIDR's interfaces.
// On CNIs where pods get fabric-routable addresses and no host pod CIDR exists
// (for example Azure CNI on AKS), ValidateLocalDest falls back to the K8s
// podMap and only accepts pods whose Pod.Status.HostIP matches this node.
func (r *k8sResolver) ValidateLocalDest(ip string) bool {
	if r.isHostAddress(ip) {
		return false
	}
	canonical := normalizeIP(ip)
	if canonical == "" {
		return false
	}
	r.mu.RLock()
	hasLocalCIDRs := len(r.localCIDRs) > 0
	routeIfaces, inLocalCIDR := r.localRouteIfacesForIPLocked(canonical)
	entry, found := r.podMap[canonical]
	routeCheck := r.localRouteCheck
	r.mu.RUnlock()
	// Two distinct rejection reasons collapse to the same fail-closed outcome:
	//
	//   !found: the informer has not yet seen a pod with this IP. The CIDR
	//     check may already have proved the IP belongs to a local pod-network
	//     range; when no CIDR exists, the podMap is the only ownership signal.
	//     The conservative choice is to refuse plaintext delivery until we
	//     have an authoritative mapping.
	//
	//   found && entry.nodeIP != r.nodeIP: the apiserver places this pod on
	//     another node. Plaintext-dialing it would exit the node via the CNI
	//     overlay where the hypervisor can observe the bytes — exactly the
	//     attack the inbound listener exists to prevent.
	//
	// Log them separately so operators can tell informer lag (transient,
	// resolves on its own) from a routing/topology bug (a remote pod IP
	// being claimed as local).
	if !found {
		r.logger.Warn("inbound destination IP not in resolver cache; rejecting (informer lag or unknown pod)", "dst", canonical)
		return false
	}
	if entry.nodeIP != r.nodeIP {
		r.logger.Warn("inbound destination belongs to a remote node; rejecting", "dst", canonical, "pod_node", entry.nodeIP, "local_node", r.nodeIP)
		return false
	}
	if !hasLocalCIDRs {
		return true
	}
	if !inLocalCIDR {
		r.logger.Warn("inbound destination is outside host-discovered local pod CIDRs; rejecting", "dst", canonical)
		return false
	}
	ok, err := routeCheck(canonical, routeIfaces)
	if err != nil {
		r.logger.Warn("local route check failed; rejecting inbound destination", "dst", canonical, "error", err)
		return false
	}
	if !ok {
		r.logger.Warn("inbound destination route does not use a local pod-network interface", "dst", canonical, "allowed_ifaces", routeIfaces)
		return false
	}
	return true
}

// localRouteIfacesForIPLocked returns the local pod-network interfaces whose
// CIDRs contain ip. Caller must hold r.mu (read or write). When no CIDRs were
// discovered (e.g. unusual CNI, fabric-routable pod IPs, or the bridge has not
// come up yet), it returns false so ValidateLocalDest can decide whether to
// fall back to K8s pod ownership.
func (r *k8sResolver) localRouteIfacesForIPLocked(ip string) ([]string, bool) {
	if len(r.localCIDRs) == 0 {
		return nil, false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, false
	}
	seen := make(map[string]struct{})
	ifaces := make([]string, 0, len(r.localCIDRs))
	for _, c := range r.localCIDRs {
		if c.cidr.Contains(parsed) {
			if _, ok := seen[c.iface]; ok {
				continue
			}
			seen[c.iface] = struct{}{}
			ifaces = append(ifaces, c.iface)
		}
	}
	return ifaces, len(ifaces) > 0
}

// reconcileLocalCIDRs runs host-CIDR discovery and replaces the cached set
// if it has changed. Logs once at construction time and on every
// subsequent transition (set membership change, empty↔populated, errors).
func (r *k8sResolver) reconcileLocalCIDRs(initial bool) {
	cidrs, err := r.localCIDRSource(r.nodeIP)
	if err != nil {
		r.logger.Warn("local CIDR discovery: net.Interfaces failed; falling back to Kubernetes pod ownership for inbound pod delivery", "error", err)
		cidrs = nil
	}
	r.mu.Lock()
	prev := r.localCIDRs
	changed := !cidrSetEqual(prev, cidrs)
	if changed {
		r.localCIDRs = cidrs
	}
	r.mu.Unlock()
	if !changed && !initial {
		return
	}
	if len(cidrs) == 0 {
		r.logger.Warn("local CIDR set empty; falling back to Kubernetes pod ownership for inbound pod delivery", "previous", cidrStrings(prev))
		return
	}
	if initial {
		r.logger.Info("local CIDR discovery succeeded", "cidrs", cidrStrings(cidrs))
		return
	}
	r.logger.Info("local CIDR set updated", "cidrs", cidrStrings(cidrs), "previous", cidrStrings(prev))
}

// bootstrapLocalCIDRs runs discovery synchronously within the given budget
// so a CNI bridge that comes up shortly after the pod starts doesn't pin
// ValidateLocalDest to the K8s pod-ownership fallback until the first periodic
// refresh tick (up to 30s away). The loop stops on the first non-empty result;
// if the kernel never returns CIDRs within the budget, we fall through to the
// existing async path and the degraded-mode alert fires after 2m. ctx
// cancellation short-circuits the wait.
func (r *k8sResolver) bootstrapLocalCIDRs(ctx context.Context, budget time.Duration) {
	deadline := time.Now().Add(budget)
	initial := true
	for {
		r.reconcileLocalCIDRs(initial)
		initial = false
		if r.LocalCIDRCount() > 0 {
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		wait := min(localCIDRBootInterval, remaining)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// runLocalCIDRRefreshLoop re-runs reconcileLocalCIDRs on a ticker so a
// transiently-empty startup snapshot or a late-coming CNI bridge does not
// permanently degrade ValidateLocalDest.
func (r *k8sResolver) runLocalCIDRRefreshLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.reconcileLocalCIDRs(false)
	}
}

type localCIDR struct {
	iface string
	cidr  *net.IPNet
}

type localRouteCheckFunc func(destIP string, allowedIfaces []string) (bool, error)

func cidrSetEqual(a, b []localCIDR) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, c := range a {
		seen[localCIDRKey(c)]++
	}
	for _, c := range b {
		key := localCIDRKey(c)
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func localCIDRKey(c localCIDR) string {
	return c.iface + "=" + c.cidr.String()
}

func cidrStrings(cidrs []localCIDR) []string {
	out := make([]string, len(cidrs))
	for i, c := range cidrs {
		out[i] = localCIDRKey(c)
	}
	return out
}

// interfaceInfo decouples selectLocalPodCIDRs from net.Interface so tests
// can drive the filter with synthetic interfaces — net.Interface.Addrs()
// hits the kernel and can't be mocked from outside the stdlib.
type interfaceInfo struct {
	name  string
	flags net.Flags
	addrs []*net.IPNet
}

// enumerateLocalPodCIDRs returns the CIDRs and interface names of host
// interfaces that look like pod-network bridges (cni0/cbr0/cilium_host/
// flannel.1/etc). Pure wrapper around selectLocalPodCIDRs that gathers the
// live interface snapshot from the kernel.
func enumerateLocalPodCIDRs(nodeIP string) ([]localCIDR, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	snapshots := make([]interfaceInfo, 0, len(ifaces))
	for _, ni := range ifaces {
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		ipNets := make([]*net.IPNet, 0, len(addrs))
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				// net.Interface.Addrs() returns *net.IPNet on Linux. Any other
				// concrete type would point at a stdlib/kernel change we want
				// operators to notice.
				slog.Default().Warn("unexpected net.Addr type returned by interface; skipping", "iface", ni.Name, "addr", a.String(), "type", fmt.Sprintf("%T", a))
				continue
			}
			ipNets = append(ipNets, ipNet)
		}
		snapshots = append(snapshots, interfaceInfo{
			name:  ni.Name,
			flags: ni.Flags,
			addrs: ipNets,
		})
	}
	return selectLocalPodCIDRs(nodeIP, snapshots), nil
}

// selectLocalPodCIDRs filters a kernel interface snapshot down to subnets
// that plausibly host local pods. The main exclusions are:
//
//   - Loopback and down interfaces never carry pod traffic.
//   - Point-to-point interfaces (wireguard, IPIP, GRE, VPN tunnels) are
//     virtual links rather than bridges, so a CIDR observed on one of them
//     is not a "local-pod subnet" — a forged PodIP inside the tunnel range
//     would have passed the old check.
//   - Non-broadcast interfaces are not pod bridges; keeping only
//     broadcast-capable links avoids treating host-only tunnel/link
//     addresses as local pod-network CIDRs.
//   - Any interface that carries the node IP itself is the node fabric
//     (eth0 / ens5 / etc), not the pod bridge. Excluding the whole
//     interface prevents a dual-stack node-fabric address in the other IP
//     family from being treated as a local pod CIDR. This keeps a
//     compromised API server from claiming a node-network IP is a "local
//     pod" and getting an inbound→pod plaintext dial across the fabric.
//
// Link-local addresses and /32-or-/128 host routes are also dropped (the
// pod bridge subnet is always wider than a single host).
//
// The filter is intentionally permissive: a non-pod broadcast bridge
// (docker0 on a kind worker, podman networks, custom L2 ranges) whose
// subnet does not contain the node IP will still be kept here. That is
// safe because ValidateLocalDest gates on entry.nodeIP == r.nodeIP in
// the resolver's K8s-sourced podMap *after* this CIDR check — the podMap
// is the authoritative "is this IP a local pod" answer, and the CIDR/route
// cross-check is defense-in-depth against a stale or adversarial
// Pod.Status.HostIP. Keeping selection wider here over-accepts in a way
// the later checks then reject, rather than under-accepting and breaking on
// CNIs we haven't enumerated.
func selectLocalPodCIDRs(nodeIP string, ifaces []interfaceInfo) []localCIDR {
	node := net.ParseIP(nodeIP)
	out := make([]localCIDR, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.flags&net.FlagPointToPoint != 0 {
			continue
		}
		if iface.flags&net.FlagUp == 0 {
			continue
		}
		if iface.flags&net.FlagBroadcast == 0 {
			continue
		}
		if node != nil && interfaceContainsIP(iface, node) {
			continue
		}
		for _, ipNet := range iface.addrs {
			if ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if ones == bits {
				continue
			}
			masked := &net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask), Mask: ipNet.Mask}
			out = append(out, localCIDR{iface: iface.name, cidr: masked})
		}
	}
	return out
}

func interfaceContainsIP(iface interfaceInfo, ip net.IP) bool {
	for _, ipNet := range iface.addrs {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isHostAddress reports whether ip names this host (nodeIP or loopback).
// One net.ParseIP covers both the loopback test and canonicalization for
// the nodeIP compare, so non-canonical IPv6 forms (uppercase, expanded
// "fd00:0:0:0:0:0:0:1", IPv4-mapped "::ffff:1.2.3.4") collapse to the same
// string r.nodeIP holds from newK8sResolver's normalizeIP pass.
func (r *k8sResolver) isHostAddress(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	return parsed.String() == r.nodeIP
}

// Resolve maps a known pod IP to its node IP. Callers must gate on
// ValidateOutboundDest first; unknown IPs (service VIPs, external,
// loopback, the node IP itself) fall through as remote with the
// original IP used as the dial target.
func (r *k8sResolver) Resolve(podIP string) (string, bool) {
	canonical := normalizeIP(podIP)
	if canonical == "" {
		return podIP, false
	}
	r.mu.RLock()
	entry, found := r.podMap[canonical]
	r.mu.RUnlock()

	if !found {
		r.logger.Debug("pod IP not in cache, treating as direct", "podIP", podIP)
		return podIP, false
	}

	return entry.nodeIP, entry.nodeIP == r.nodeIP
}
