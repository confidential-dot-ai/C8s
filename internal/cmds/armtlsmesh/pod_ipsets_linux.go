//go:build linux

package armtlsmesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// ipsetOverflows counts reconcile cycles that observed more pod IPs than the
// configured --ipset-maxelem. Exposed via armtls_mesh_iptables_ipset_overflow_total
// so a silently-degrading sync is observable rather than warn-only.
var ipsetOverflows atomic.Int64

func iptablesIPSetOverflows() int64 {
	return ipsetOverflows.Load()
}

// ipsetSyncFailures counts individual set writes that failed. A set that keeps
// its previous contents is enforcement running against a stale membership,
// which no other counter distinguishes from a quiet cluster.
var ipsetSyncFailures atomic.Int64

func iptablesIPSetSyncFailures() int64 {
	return ipsetSyncFailures.Load()
}

// Membership levels for the last reconcile, plus a count of reconciles that
// shrank the cw set. Absence from these sets is what silently removes
// interception and the cw guard, so it has to be visible: a gauge alone cannot
// distinguish "no cw pods on this node" from "the cw pods stopped being
// reported", and the shrink counter separates them.
var (
	lastPodIPSetMembers atomic.Int64
	lastCWIPSetMembers  atomic.Int64
	cwIPSetShrinkages   atomic.Int64
)

func podIPSetMemberCount() int64 { return lastPodIPSetMembers.Load() }
func cwIPSetMemberCount() int64  { return lastCWIPSetMembers.Load() }
func cwIPSetShrinks() int64      { return cwIPSetShrinkages.Load() }

// recordIPSetMembership publishes this reconcile's membership levels and counts
// a cw set that came back smaller than the last one. The first reconcile has no
// predecessor, so it establishes the level rather than counting a shrink.
func recordIPSetMembership(logger *slog.Logger, podMembers, cwMembers int) {
	lastPodIPSetMembers.Store(int64(podMembers))
	prev := lastCWIPSetMembers.Swap(int64(cwMembers))
	if prev > int64(cwMembers) {
		cwIPSetShrinkages.Add(1)
		// Warn, not Info: every IP that left the set is a confidential workload
		// the guard no longer drops plaintext to. Routine on a scale-down,
		// which is why this reports rather than acts.
		logger.Warn("cw pod ipset shrank; those pods are no longer guarded",
			"previous_members", prev, "members", cwMembers)
	}
}

func runIptablesSync(ctx context.Context, cfg *iptablesSyncConfig) error {
	if err := validatePort("--outbound-port", cfg.outboundPort); err != nil {
		return err
	}
	if cfg.resyncPeriod <= 0 {
		return fmt.Errorf("resync-period must be positive")
	}
	if cfg.watchdogPeriod <= 0 {
		return fmt.Errorf("watchdog-period must be positive")
	}
	if cfg.ipsetMaxElem <= 0 {
		return fmt.Errorf("ipset-maxelem must be positive")
	}
	if len(cfg.nodeIPs) == 0 {
		if env := os.Getenv("NODE_IP"); env != "" {
			cfg.nodeIPs = []string{env}
		}
	}
	if len(cfg.nodeIPs) == 0 {
		return fmt.Errorf("node IP required: set --node-ip or NODE_IP env var")
	}
	nodeIPsByFamily, err := parseNodeIPs(cfg.nodeIPs)
	if err != nil {
		return err
	}
	// Dual-stack: the chart only passes status.hostIP (IPv4 on most nodes),
	// so pod-originated IPv6 TCP was never redirected. Auto-discover the
	// missing family's address from local interfaces; verifyNodeIPsLocal
	// already confirmed the explicitly-provided ones are local.
	discovered, err := discoverMissingFamilyNodeIPs(nodeIPsByFamily)
	if err != nil {
		return err
	}
	maps.Copy(nodeIPsByFamily, discovered)
	if err := verifyNodeIPsLocal(nodeIPsByFamily); err != nil {
		return err
	}
	cfg.nodeIPs = canonicalNodeIPs(nodeIPsByFamily)
	excludeUIDs, err := parseExcludeUIDs(cfg.excludeUIDs)
	if err != nil {
		return err
	}
	cwPassthrough, err := parseCWPassthrough(cfg.cwInboundPassthrough)
	if err != nil {
		return err
	}
	// The cw inbound and egress guards are always installed. Inbound posture
	// is the passthrough allowlist; the egress guard drops non-TCP from cw
	// pods, with the DNS carve-out and ICMPv6 essentials as the only
	// exceptions.
	rules, jumps := composeIptablesSyncRules(
		cfg.outboundPort, cfg.uid, excludeUIDs, cwPassthrough, nodeIPsByFamily,
	)

	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)
	if err := initIptablesClients(); err != nil {
		return err
	}
	configureIptablesMetricsFile(cfg.metricsFile)
	publishIptablesMetrics(logger)
	if err := resetReadyFile(cfg.readyFile); err != nil {
		return err
	}
	ready, err := serveReadiness(ctx, cfg.readyAddr, logger)
	if err != nil {
		return err
	}
	clientset, err := newKubeClientset(cfg.kubeconfig)
	if err != nil {
		return err
	}
	excludedSourceNamespaces := parseExcludedNamespaces(cfg.excludeSourceNamespaces)

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	syncCh := make(chan struct{}, 1)
	notifySync := func(any) {
		select {
		case syncCh <- struct{}{}:
		default:
		}
	}
	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    notifySync,
		UpdateFunc: func(_, obj any) { notifySync(obj) },
		DeleteFunc: notifySync,
	}); err != nil {
		return fmt.Errorf("iptables sync: add pod event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("iptables sync: pod cache sync failed")
	}
	if err := reconcileLiveSetMaxElem(logger, cfg.ipsetMaxElem); err != nil {
		return err
	}
	cwIPs, err := reconcilePodIPSets(podInformer.GetStore(), cfg.nodeIPs, excludedSourceNamespaces, cfg.ipsetMaxElem, logger)
	if err != nil {
		return err
	}
	if err := installIptablesRules(logger, rules, jumps); err != nil {
		return err
	}
	// The guard fails closed only for NEW flows; tear down conntrack for
	// existing connections to cw pods so pre-enforcement plaintext flows (and
	// any that raced the chain-flush-then-append window in installIptablesRules)
	// must re-establish through the DROP instead of being grandfathered by the
	// ESTABLISHED,RELATED RETURN rule.
	_, _ = flushCWConntrack(logger, cwIPs)
	publishIptablesMetrics(logger)
	if cfg.readyFile != "" {
		if err := os.WriteFile(cfg.readyFile, []byte("ready\n"), 0o600); err != nil {
			return fmt.Errorf("write ready file: %w", err)
		}
	}
	ready.Store(true)
	logger.Info("iptables sync ready",
		"resync_period", cfg.resyncPeriod.String(),
		"watchdog_period", cfg.watchdogPeriod.String())

	// Jump watchdog: kube-proxy can reinsert KUBE-SERVICES at PREROUTING
	// position 1 during its periodic reconciliation, demoting our jump.
	// Re-asserting at a tight interval bounds the window in which Service
	// VIP traffic could be DNAT'd before our chain runs.
	go runJumpWatchdog(ctx, logger, jumps, cfg.watchdogPeriod)

	// prevCWIPs lets each reconcile flush conntrack only for cw pod IPs that
	// newly entered the set, keeping the guard fail-closed as workloads are
	// (re)labeled without re-flushing the whole set every tick.
	prevCWIPs := stringSet(cwIPs)

	ticker := time.NewTicker(cfg.resyncPeriod)
	defer ticker.Stop()
	for {
		resync := false
		select {
		case <-ctx.Done():
			// Deliberately no teardown here. Graceful shutdown is owned by the
			// dedicated `iptables-cleanup` native sidecar's preStop hook, which
			// runs runIptablesCleanup() last (sidecars stop in reverse init
			// order) so cleanup happens after the proxy drains. Cleaning up here
			// too would be redundant and could race that sidecar; and it would
			// not cover a SIGKILL/OOM (which never reaches this branch anyway).
			// A crash without preStop is handled on restart: installIptablesRules
			// flushes the managed chains before reinstalling.
			return nil
		case <-ticker.C:
			resync = true
		case <-syncCh:
		}
		cwIPs, err := reconcilePodIPSets(podInformer.GetStore(), cfg.nodeIPs, excludedSourceNamespaces, cfg.ipsetMaxElem, logger)
		if err != nil {
			logger.Warn("pod ipset sync failed", "error", err)
			continue
		}
		curr := stringSet(cwIPs)
		_, _ = flushCWConntrack(logger, newMembers(prevCWIPs, curr))
		prevCWIPs = curr
		// Guard counters change only on packet hits, not pod events, so
		// refresh on the resync tick rather than every event-driven sync
		// (which would fork iptables and take the xtables lock during
		// churn, contending with kube-proxy and the jump watchdog).
		if resync {
			if err := refreshCWGuardCounters(); err != nil {
				logger.Warn("cw guard counter read failed", "error", err)
			}
		}
		publishIptablesMetrics(logger)
	}
}

func stringSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// newMembers returns the elements of curr not present in prev.
func newMembers(prev, curr map[string]struct{}) []string {
	var out []string
	for s := range curr {
		if _, ok := prev[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func resetReadyFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale ready file %q: %w", path, err)
	}
	return nil
}

// serveReadiness starts the startup probe's endpoint and returns the flag the
// caller sets once interception is installed. The main proxy container is
// gated on this probe (native sidecars start in order), so until it flips no
// pod traffic can leave the node unintercepted. Empty addr disables the
// endpoint and returns a flag nobody reads.
//
// It binds before the informer work so the probe answers 503 while the sync is
// still coming up, rather than failing to connect.
func readinessHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "the initial ipset and iptables sync has not completed", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	return mux
}

func serveReadiness(ctx context.Context, addr string, logger *slog.Logger) (*atomic.Bool, error) {
	var ready atomic.Bool
	if addr == "" {
		return &ready, nil
	}
	if _, err := cmdsutil.ServeInBackground(ctx, addr, readinessHandler(&ready), logger); err != nil {
		return nil, fmt.Errorf("--ready-addr: %w", err)
	}
	return &ready, nil
}

func runJumpWatchdog(ctx context.Context, logger *slog.Logger, jumps []iptablesRule, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := ensureIptablesJumps(logger, jumps); err != nil {
			logger.Warn("iptables jump watchdog failed", "error", err)
		}
	}
}

type ipSetSpec struct {
	name    string
	family  string
	members []string
	label   string
}

// reconcilePodIPSets rewrites the managed ipsets from the pod cache. The cw
// guard is always installed, so the cw sets are always computed and written.
// reconcilePodIPSets returns the cw pod IPs it wrote so the caller can flush
// their conntrack entries and keep the guard fail-closed across membership
// changes.
func reconcilePodIPSets(store cache.Store, nodeIPs []string, excludedSourceNamespaces map[string]struct{}, ipsetMaxElem int, logger *slog.Logger) ([]string, error) {
	sets := collectPodIPSetMembers(store.List(), nodeIPs, excludedSourceNamespaces)
	if sets.exceeds(ipsetMaxElem) {
		ipsetOverflows.Add(1)
		publishIptablesMetrics(logger)
	}
	// INVARIANT: the guard sets are written first, and one set's failure never
	// costs another its write. Membership is what the fail-closed guard and the
	// interception rules match on, so a set left at a previous cycle's contents
	// stops covering pods created since — plaintext reaches a cw pod, and the
	// only signal is a warning. Ordering puts the cw sets, which the guard
	// keys on, ahead of the sets that only decide interception.
	specs := []ipSetSpec{
		{cwPodIPSetName4, "inet", sets.cwIPv4, "IPv4 cw pod ipset"},
		{cwPodIPSetName6, "inet6", sets.cwIPv6, "IPv6 cw pod ipset"},
		{podIPSetName4, "inet", sets.allIPv4, "IPv4 pod ipset"},
		{podIPSetName6, "inet6", sets.allIPv6, "IPv6 pod ipset"},
		{localPodIPSetName4, "inet", sets.localIPv4, "local IPv4 pod ipset"},
		{localPodIPSetName6, "inet6", sets.localIPv6, "local IPv6 pod ipset"},
	}
	var errs []error
	for _, spec := range specs {
		if err := replaceIPSetMembers(logger, spec.name, spec.family, spec.members, ipsetMaxElem); err != nil {
			ipsetSyncFailures.Add(1)
			errs = append(errs, fmt.Errorf("sync %s: %w", spec.label, err))
		}
	}
	if len(errs) > 0 {
		publishIptablesMetrics(logger)
		return nil, errors.Join(errs...)
	}
	recordIPSetMembership(logger, len(sets.allIPv4)+len(sets.allIPv6), len(sets.cwIPv4)+len(sets.cwIPv6))
	logger.Debug("pod ipsets reconciled", "ipv4", len(sets.allIPv4), "ipv6", len(sets.allIPv6), "local_ipv4", len(sets.localIPv4), "local_ipv6", len(sets.localIPv6), "cw_ipv4", len(sets.cwIPv4), "cw_ipv6", len(sets.cwIPv6))
	return append(append([]string{}, sets.cwIPv4...), sets.cwIPv6...), nil
}

type podIPSetMembers struct {
	allIPv4   []string
	allIPv6   []string
	localIPv4 []string
	localIPv6 []string
	cwIPv4    []string
	cwIPv6    []string
}

func (m podIPSetMembers) exceeds(maxElem int) bool {
	return len(m.allIPv4) > maxElem ||
		len(m.allIPv6) > maxElem ||
		len(m.localIPv4) > maxElem ||
		len(m.localIPv6) > maxElem ||
		len(m.cwIPv4) > maxElem ||
		len(m.cwIPv6) > maxElem
}

func collectPodIPSetMembers(objs []any, nodeIPs []string, excludedSourceNamespaces map[string]struct{}) podIPSetMembers {
	ourNodeIPs := make(map[string]struct{}, len(nodeIPs))
	for _, ip := range nodeIPs {
		if canon := normalizeIP(ip); canon != "" {
			ourNodeIPs[canon] = struct{}{}
		}
	}
	v4Set := make(map[string]struct{})
	v6Set := make(map[string]struct{})
	localV4Set := make(map[string]struct{})
	localV6Set := make(map[string]struct{})
	cwV4Set := make(map[string]struct{})
	cwV6Set := make(map[string]struct{})
	add := func(value string, v4Target, v6Target map[string]struct{}) {
		ip := net.ParseIP(value)
		if ip == nil {
			return
		}
		if ip.To4() != nil {
			v4Target[ip.String()] = struct{}{}
			return
		}
		v6Target[ip.String()] = struct{}{}
	}

	for _, obj := range objs {
		pod, ok := obj.(*corev1.Pod)
		if !ok || !podEligibleForMeshEndpoint(pod) {
			continue
		}
		// Excluded namespaces (kube-system) are out of the mesh entirely — not
		// source, destination, nor cw endpoint — so all three sets agree on scope.
		if _, nsExcluded := excludedSourceNamespaces[pod.Namespace]; nsExcluded {
			continue
		}
		localSource := podIsLocal(pod, ourNodeIPs) && podEligibleForMeshSource(pod, excludedSourceNamespaces)
		// cw membership is cluster-wide, mirroring the all-pods sets: the
		// FORWARD guard then also drops at the source node when a Service
		// VIP is DNAT'd toward a cw pod on another node.
		cw := podIsConfidentialWorkload(pod)
		for _, ip := range podStatusIPs(pod) {
			add(ip, v4Set, v6Set)
			if localSource {
				add(ip, localV4Set, localV6Set)
			}
			if cw {
				add(ip, cwV4Set, cwV6Set)
			}
		}
	}

	return podIPSetMembers{
		allIPv4:   sortedKeys(v4Set),
		allIPv6:   sortedKeys(v6Set),
		localIPv4: sortedKeys(localV4Set),
		localIPv6: sortedKeys(localV6Set),
		cwIPv4:    sortedKeys(cwV4Set),
		cwIPv6:    sortedKeys(cwV6Set),
	}
}

// podIsLocal reports whether pod is scheduled on a node whose IP is in
// ourNodeIPs. Prefers Status.HostIPs (dual-stack list, k8s 1.27+) and falls
// back to Status.HostIP for older API objects. ourNodeIPs is keyed by the
// canonical net.IP.String() form so callers must pre-normalize.
func podIsLocal(pod *corev1.Pod, ourNodeIPs map[string]struct{}) bool {
	if len(ourNodeIPs) == 0 {
		return false
	}
	for _, h := range pod.Status.HostIPs {
		if _, ok := ourNodeIPs[normalizeIP(h.IP)]; ok {
			return true
		}
	}
	if pod.Status.HostIP != "" {
		if _, ok := ourNodeIPs[normalizeIP(pod.Status.HostIP)]; ok {
			return true
		}
	}
	return false
}

// parseNodeIPs validates raw --node-ip values and groups them by family.
// Rejects: empty input, invalid literals, unspecified (0.0.0.0 / ::),
// loopback (DNAT to loopback needs route_localnet=1 which we don't set),
// zone-scoped IPv6 (`fe80::1%eth0` — DNAT has no defined target for a
// zone-scoped address), IPv4-in-IPv6 literals in any RFC 4291 form
// (IPv4-mapped `::ffff:10.0.0.1` and its hex/expanded/mixed-case variants
// caught by netip.Addr.Is4In6, plus the deprecated IPv4-compatible
// `::1.2.3.4` caught by the dot-in-IPv6 heuristic — both ambiguous family;
// operator should pass the IPv4 form directly), and more than one address
// per family (the DNAT rule takes a single --to-destination per family).
func parseNodeIPs(raw []string) (map[iptablesFamily]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("at least one --node-ip required")
	}
	out := make(map[iptablesFamily]string, 2)
	for i, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("--node-ip[%d]: empty value", i)
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--node-ip[%d] %q: not a valid IP address", i, s)
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("--node-ip[%d] %q: zone-scoped IPv6 is not supported; pass a global-scope address", i, s)
		}
		// Is4In6 covers RFC 4291 §2.5.5.2 IPv4-mapped in every notation
		// (dotted, hex-only, expanded, mixed-case). The dot-in-IPv6 check
		// catches the deprecated §2.5.5.1 IPv4-compatible form (`::1.2.3.4`),
		// which has no 0xff/0xff prefix so Is4In6 returns false.
		if addr.Is4In6() || (addr.Is6() && strings.ContainsRune(s, '.')) {
			return nil, fmt.Errorf("--node-ip[%d] %q: IPv4-in-IPv6 literal is ambiguous; pass the IPv4 form", i, s)
		}
		if addr.IsUnspecified() {
			return nil, fmt.Errorf("--node-ip[%d] %q: unspecified address (not a routable target for DNAT)", i, s)
		}
		if addr.IsLoopback() {
			return nil, fmt.Errorf("--node-ip[%d] %q: loopback address (DNAT to loopback requires route_localnet=1 on the input interface, which is not enabled)", i, s)
		}
		var family iptablesFamily
		if addr.Is4() {
			family = iptablesFamilyIPv4
		} else {
			family = iptablesFamilyIPv6
		}
		canonical := addr.String()
		if existing, dup := out[family]; dup {
			return nil, fmt.Errorf("--node-ip: multiple %s addresses (%s and %s); pass at most one per family", family, existing, canonical)
		}
		out[family] = canonical
	}
	return out, nil
}

// composeIptablesSyncRules assembles the NAT interception rules and the
// always-on fail-closed guard rules plus their FORWARD jumps for one sync
// cycle. It is a pure function over already-validated inputs so the rule/jump
// composition is unit-testable without a live kube; a rule dropped here is
// caught the same way a rule-shaped regression is.
func composeIptablesSyncRules(outboundPort, uid int, excludeUIDs []uint32, cwPassthrough []cwPassthrough, nodeIPsByFamily map[iptablesFamily]string) ([]iptablesRule, []iptablesRule) {
	rules := buildPodIPSetRules(outboundPort, uid, excludeUIDs, nodeIPsByFamily)
	rules = append(rules, buildCWGuardRules(cwPassthrough)...)
	rules = append(rules, buildCWEgressGuardRules()...)
	jumps := append(jumpRules(), cwJumpRule(), cwEgressJumpRule())
	return rules, jumps
}

// ifaceAddrSet groups the addresses bound to one interface.
type ifaceAddrSet struct {
	name  string
	addrs []ifaceAddr
}

type ifaceAddr struct {
	ip   net.IP
	mask net.IPMask
}

// collectInterfaceAddresses enumerates the local interfaces and their
// addresses for dual-stack node-IP discovery. Split from
// discoverMissingFamilyNodeIPs so the selection logic can be unit-tested
// against injected interface groups.
func collectInterfaceAddresses() ([]ifaceAddrSet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate local interfaces for dual-stack discovery: %w", err)
	}
	var out []ifaceAddrSet
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("enumerate addresses on interface %s: %w", ifc.Name, err)
		}
		set := ifaceAddrSet{name: ifc.Name}
		seen := map[string]bool{}
		for _, a := range addrs {
			var ipnet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(len(v.IP)*8, len(v.IP)*8)}
			}
			if ipnet == nil {
				continue
			}
			ip := ipnet.IP.String()
			if seen[ip] {
				continue
			}
			seen[ip] = true
			set.addrs = append(set.addrs, ifaceAddr{ip: ipnet.IP, mask: ipnet.Mask})
		}
		out = append(out, set)
	}
	return out, nil
}

// discoverMissingFamilyNodeIPs returns one address for any family absent
// from byFamily, so a dual-stack node whose chart only passed the IPv4
// status.hostIP still gets the IPv6 PREROUTING DNAT. It prefers a host-usable
// unicast address on the interface carrying the provided node IP (the egress
// interface); if one exists only on a non-primary interface it returns an
// error rather than install a misrouted DNAT, and a genuinely single-stack
// node yields no entry.
func discoverMissingFamilyNodeIPs(byFamily map[iptablesFamily]string) (map[iptablesFamily]string, error) {
	needed := make(map[iptablesFamily]bool)
	if _, ok := byFamily[iptablesFamilyIPv4]; !ok {
		needed[iptablesFamilyIPv4] = true
	}
	if _, ok := byFamily[iptablesFamilyIPv6]; !ok {
		needed[iptablesFamilyIPv6] = true
	}
	if len(needed) == 0 {
		return nil, nil
	}
	sets, err := collectInterfaceAddresses()
	if err != nil {
		return nil, err
	}
	return selectMissingFamilyNodeIPs(byFamily, needed, sets)
}

// selectMissingFamilyNodeIPs is the pure selection half of
// discoverMissingFamilyNodeIPs. For each missing family it picks a usable
// non-loopback address bound to the interface that also carries a provided
// node IP (the node's primary/egress interface); among those it prefers a
// host-style (larger) prefix. If the missing family's address exists only on
// non-primary interfaces it returns an error so the DNAT is never silently
// installed on an overlay/management listener; a genuinely single-stack node
// yields no entry and no error.
func selectMissingFamilyNodeIPs(byFamily map[iptablesFamily]string, needed map[iptablesFamily]bool, sets []ifaceAddrSet) (map[iptablesFamily]string, error) {
	out := make(map[iptablesFamily]string, 2)
	for fam, present := range needed {
		if !present {
			continue
		}
		type candidate struct {
			ip     net.IP
			ones   int
			iface  string
			onSame bool
		}
		var cands []candidate
		for si := range sets {
			set := sets[si]
			// The interface carries a provided node IP literal. That IP names
			// the egress interface (kubelet's primary NIC), not an overlay.
			carriesProvided := false
			for _, a := range set.addrs {
				for _, p := range byFamily {
					if p == a.ip.String() {
						carriesProvided = true
					}
				}
			}
			for _, a := range set.addrs {
				ip := a.ip
				if (fam == iptablesFamilyIPv4) != (ip.To4() != nil) {
					continue
				}
				if isExcludedNodeAddress(ip) {
					continue
				}
				ones, _ := a.mask.Size()
				if fam == iptablesFamilyIPv6 && !isHostUsableIPv6(ip, ones) {
					continue // a network aggregate (e.g. a /56 prefix), not a host address.
				}
				cands = append(cands, candidate{ip: ip, ones: ones, iface: set.name, onSame: carriesProvided})
			}
		}
		if len(cands) == 0 {
			continue // genuinely no address of this family: single-stack node.
		}
		best := cands[0]
		bestSame := best.onSame
		for _, c := range cands[1:] {
			// Same-carrier outranks prefix and interface name; within the
			// same precedence prefer a larger prefix, then a stable name tie.
			if c.onSame != bestSame {
				if c.onSame {
					best, bestSame = c, true
				}
				continue
			}
			hasLongerPrefix := c.ones > best.ones
			winsInterfaceNameTie := c.ones == best.ones && c.iface < best.iface
			if hasLongerPrefix || winsInterfaceNameTie {
				best = c
			}
		}
		if !bestSame {
			return nil, fmt.Errorf("cannot confidently choose a %s node IP: only non-primary-interface addresses exist; pass --node-ip explicitly", fam)
		}
		out[fam] = best.ip.String()
	}
	return out, nil
}

func isExcludedNodeAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast()
}

// isHostUsableIPv6 reports whether ip (prefix length ones) is a host-style
// address suitable as a DNAT target, ruling out a pure network aggregate: a
// prefix shorter than /64 whose interface (low 64) bits are all zero is the
// network/aggregate address, not a host address.
func isHostUsableIPv6(ip net.IP, ones int) bool {
	if ones >= 64 {
		return true // host or host-style SLAAC /64, static /128, etc.
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	for i := 8; i < 16; i++ {
		if v6[i] != 0 {
			return true
		}
	}
	return false
}

// verifyNodeIPsLocal confirms each parsed nodeIP is bound to a local
// interface. DNAT to a non-local IP silently misroutes traffic off-node;
// REDIRECT's prior self-healing property (always retargeted the receive
// interface) is gone with DNAT, so we must catch a misconfigured --node-ip
// at startup rather than at first packet.
func verifyNodeIPsLocal(byFamily map[iptablesFamily]string) error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("enumerate local interface addresses: %w", err)
	}
	return nodeIPsAreLocal(byFamily, addrs)
}

// nodeIPsAreLocal is the pure half of verifyNodeIPsLocal: given the parsed
// node IPs and a pre-fetched list of local interface addresses, return an
// error if any node IP is not bound locally. Extracted so the comparison
// can be unit-tested without manipulating real interfaces.
//
// byFamily values are assumed canonical (parseNodeIPs invariant) and
// net.IP.String() returns canonical form, so the two sides match directly
// without an extra normalize pass.
func nodeIPsAreLocal(byFamily map[iptablesFamily]string, localAddrs []net.Addr) error {
	local := make(map[string]struct{}, len(localAddrs))
	for _, a := range localAddrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if len(ip) > 0 {
			local[ip.String()] = struct{}{}
		}
	}
	for family, ip := range byFamily {
		if _, ok := local[ip]; !ok {
			return fmt.Errorf("--node-ip %s (%s) is not bound to any local interface; DNAT would misroute traffic off-node", ip, family)
		}
	}
	return nil
}

// canonicalNodeIPs returns the validated, family-grouped node IPs as a flat
// slice in deterministic order (IPv4 first, then IPv6). Used to repopulate
// cfg.nodeIPs with canonical forms after validation.
func canonicalNodeIPs(byFamily map[iptablesFamily]string) []string {
	out := make([]string, 0, len(byFamily))
	for _, f := range []iptablesFamily{iptablesFamilyIPv4, iptablesFamilyIPv6} {
		if ip, ok := byFamily[f]; ok {
			out = append(out, ip)
		}
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// reconcileLiveSetMaxElem destroys any pre-existing managed ipset whose
// maxelem differs from what we want to write. The restore script uses
// `create … -exist` which silently succeeds only when params match; on a
// Helm upgrade that changes --ipset-maxelem after the prior pod exited
// abruptly (i.e. preStop never ran and the managed sets were never
// destroyed), the stale live set would otherwise block every reconcile.
//
// The destroy fails if any iptables rule still references the set, so we
// flush our managed chains between the probe and the destroy. The function
// returns early when no maxelem changed; installIptablesRules handles
// chain flushing on every other path.
func reconcileLiveSetMaxElem(logger *slog.Logger, desiredMaxElem int) error {
	names := managedIPSetNames
	mismatched := make([]string, 0, len(names))
	priorMaxElem := make(map[string]int, len(names))
	for _, name := range names {
		actual, exists, err := readIPSetMaxElem(name)
		if err != nil {
			return fmt.Errorf("inspect ipset %s: %w", name, err)
		}
		if !exists || actual == desiredMaxElem {
			continue
		}
		logger.Info("ipset maxelem changed since last run", "set", name, "old_maxelem", actual, "new_maxelem", desiredMaxElem)
		mismatched = append(mismatched, name)
		priorMaxElem[name] = actual
	}
	if len(mismatched) == 0 {
		return nil
	}
	if err := flushManagedIptablesChains(logger); err != nil {
		return fmt.Errorf("pre-flush iptables chains for ipset rebuild: %w", err)
	}
	for _, name := range mismatched {
		if stderr, err := runIPSetCmdQuiet([]string{"destroy", name}); err != nil {
			return fmt.Errorf("destroy ipset %s for maxelem rebuild: %w (stderr=%q)", name, err, strings.TrimSpace(stderr))
		}
		logger.Info("destroyed live ipset to apply new maxelem", "set", name, "old_maxelem", priorMaxElem[name], "new_maxelem", desiredMaxElem)
	}
	return nil
}

// readIPSetMaxElem parses the `maxelem` field from `ipset list -t <name>`.
// Returns (0, false, nil) when the set does not exist; that's the common
// case on a clean start.
func readIPSetMaxElem(name string) (int, bool, error) {
	stdout, stderr, err := runIPSetCmdCapture([]string{"list", "-t", name})
	if err != nil {
		if strings.Contains(stderr, "does not exist") {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("ipset list -t %s: %w (stderr=%q)", name, err, strings.TrimSpace(stderr))
	}
	v, perr := parseIPSetMaxElemHeader(stdout)
	if perr != nil {
		return 0, true, fmt.Errorf("ipset %s: %w", name, perr)
	}
	return v, true, nil
}

// parseIPSetMaxElemHeader pulls `maxelem N` out of `ipset list -t` output.
// Header line shape is: `Header: family inet hashsize 1024 maxelem 262144 …`
// across ipset 6.x/7.x; field order is stable but the surrounding fields
// vary (e.g. comment, counters, skbinfo), so scan rather than hardcoding
// positions.
func parseIPSetMaxElemHeader(out string) (int, error) {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Header:") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "maxelem" && i+1 < len(fields) {
				v, err := strconv.Atoi(fields[i+1])
				if err != nil {
					return 0, fmt.Errorf("parse maxelem %q: %w", fields[i+1], err)
				}
				return v, nil
			}
		}
		return 0, fmt.Errorf("header missing maxelem field: %q", line)
	}
	return 0, fmt.Errorf("no header line in ipset output")
}

func replaceIPSetMembers(logger *slog.Logger, name, family string, ips []string, maxElem int) error {
	tmpName := name + ipSetTmpSuffix
	restoreScript, err := buildIPSetRestoreScript(name, family, ips, maxElem)
	if err != nil {
		return err
	}
	// A tmp set left behind by a crash may have been created with an older
	// maxelem. Destroy it first so the restore creates it with the requested
	// capacity. "Doesn't exist" is the common case and intentionally silent;
	// anything else is a real ipset error worth surfacing so a stuck pre-destroy
	// is not hidden behind the subsequent restore failure. A successful destroy
	// means a TMP set actually existed — log at Info so a prior crash leaves a
	// trace the operator can correlate, instead of vanishing into the silent path.
	switch stderr, err := runIPSetCmdQuiet([]string{"destroy", tmpName}); {
	case err == nil:
		logger.Info("destroyed stale ipset TMP from prior reconcile", "set", tmpName)
	case strings.Contains(stderr, "does not exist"):
		// expected on a clean reconcile; nothing to log
	default:
		logger.Warn("pre-destroy of stale ipset TMP failed", "set", tmpName, "error", err, "stderr", strings.TrimSpace(stderr))
	}
	return runIPSetRestore(restoreScript)
}

func buildIPSetRestoreScript(name, family string, ips []string, maxElem int) (string, error) {
	if maxElem <= 0 {
		return "", fmt.Errorf("ipset maxelem must be positive")
	}
	if len(ips) > maxElem {
		return "", fmt.Errorf("ipset %s has %d members, exceeds maxelem %d", name, len(ips), maxElem)
	}
	tmpName := name + ipSetTmpSuffix
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "create %s hash:ip family %s maxelem %d -exist\n", name, family, maxElem)
	fmt.Fprintf(&buf, "create %s hash:ip family %s maxelem %d\n", tmpName, family, maxElem)
	fmt.Fprintf(&buf, "flush %s\n", tmpName)
	for _, ip := range ips {
		fmt.Fprintf(&buf, "add %s %s -exist\n", tmpName, ip)
	}
	fmt.Fprintf(&buf, "swap %s %s\n", tmpName, name)
	fmt.Fprintf(&buf, "destroy %s\n", tmpName)
	return buf.String(), nil
}

// cleanupPodIPSetsForNames destroys the named ipsets plus their -TMP swap
// variants. runIptablesCleanup passes either the full list or, under
// --keep-guard, the interception-only subset (keeping the cw pod sets the
// fail-closed guard references).
func cleanupPodIPSetsForNames(logger *slog.Logger, names []string) {
	for _, name := range names {
		for _, n := range []string{name, name + ipSetTmpSuffix} {
			if err := runIPSetCmd([]string{"destroy", n}); err != nil {
				logger.Warn("delete ipset failed (may not exist)", "set", n, "error", err)
			} else {
				logger.Info("ipset removed", "set", n)
			}
		}
	}
}

// runIPSetCmd runs `ipset <args>` and folds captured stderr into the error
// so callers logging "error" get the underlying ipset diagnostic rather than
// just the exit status. stdout is irrelevant for the destroy/create calls
// that flow through this helper.
func runIPSetCmd(args []string) error {
	_, stderr, err := runIPSetCmdCapture(args)
	if err != nil {
		return ipsetError(strings.Join(args, " "), stderr, err)
	}
	return nil
}

// runIPSetCmdCapture runs ipset with both streams captured. Used wherever
// the caller needs to inspect output (e.g. parse the maxelem header) instead
// of just classifying the error.
func runIPSetCmdCapture(args []string) (stdout, stderr string, err error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command("ipset", args...)
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err = cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// runIPSetCmdQuiet is a thin wrapper around runIPSetCmdCapture for callers
// that only need to distinguish "set does not exist" (expected) from a real
// failure via stderr; stdout is dropped.
func runIPSetCmdQuiet(args []string) (string, error) {
	_, stderr, err := runIPSetCmdCapture(args)
	return stderr, err
}

func runIPSetRestore(script string) error {
	var stderrBuf bytes.Buffer
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = bytes.NewBufferString(script)
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		return ipsetError("restore", stderrBuf.String(), err)
	}
	return nil
}

func ipsetError(op, stderr string, err error) error {
	trimmed := strings.TrimSpace(stderr)
	if trimmed == "" {
		return fmt.Errorf("ipset %s: %w", op, err)
	}
	return fmt.Errorf("ipset %s: %w (stderr=%q)", op, err, trimmed)
}
