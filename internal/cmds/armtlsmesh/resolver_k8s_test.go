//go:build linux

package armtlsmesh

import (
	"context"
	"maps"
	"net"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func testLocalCIDRs(cidrs ...*net.IPNet) []localCIDR {
	out := make([]localCIDR, len(cidrs))
	for i, cidr := range cidrs {
		out[i] = localCIDR{iface: "cni0", cidr: cidr}
	}
	return out
}

// passthroughLocalRouteCheck always reports the destination route uses one
// of the allowed interfaces. Used in tests that exercise ValidateLocalDest
// without wanting to mock /proc/net/route — the kernel-route layer isn't
// what the test pins.
func passthroughLocalRouteCheck(string, []string) (bool, error) { return true, nil }

func TestK8sResolverLocal(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"},  // local pod
			"10.244.1.5": {nodeIP: "10.0.0.2", uid: "uid-remote"}, // remote pod
		},
	}

	tests := []struct {
		podIP     string
		wantNode  string
		wantLocal bool
	}{
		{"10.244.0.5", "10.0.0.1", true},  // local pod from cache
		{"10.244.1.5", "10.0.0.2", false}, // remote pod from cache
		{"10.99.0.1", "10.99.0.1", false}, // unknown = direct fallthrough
	}

	for _, tt := range tests {
		nodeIP, local := r.Resolve(tt.podIP)
		if nodeIP != tt.wantNode || local != tt.wantLocal {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)",
				tt.podIP, nodeIP, local, tt.wantNode, tt.wantLocal)
		}
	}
}

func TestK8sResolverValidateOutboundDestRequiresKnownPod(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"},
			"10.244.1.5": {nodeIP: "10.0.0.2", uid: "uid-remote"},
			"10.0.0.1":   {nodeIP: "10.0.0.1", uid: "uid-hostnetwork"},
		},
	}

	for _, ip := range []string{"10.244.0.5", "10.244.1.5"} {
		if ok, reason := r.ValidateOutboundDest(ip); !ok {
			t.Fatalf("ValidateOutboundDest(%q) = (false, %q), want (true, \"\")", ip, reason)
		}
	}
	// host_addr is the security signal (direct dial outside REDIRECT path);
	// unknown_pod is the informer-skew baseline. The reasons must classify
	// distinctly so alerts can target only host_addr.
	rejectCases := map[string]string{
		"10.0.0.1":  outboundRejectHostAddr, // node IP cached as hostNetwork pod
		"127.0.0.1": outboundRejectHostAddr,
		"::1":       outboundRejectHostAddr,
		"10.96.0.1": outboundRejectUnknownPod, // unknown IP (e.g. service VIP)
	}
	for ip, wantReason := range rejectCases {
		ok, reason := r.ValidateOutboundDest(ip)
		if ok {
			t.Errorf("ValidateOutboundDest(%q) = (true, _), want (false, %q)", ip, wantReason)
			continue
		}
		if reason != wantReason {
			t.Errorf("ValidateOutboundDest(%q) reason = %q, want %q", ip, reason, wantReason)
		}
	}
}

func TestK8sResolverValidateLocalDest(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("10.244.0.0/24")
	withCIDR := func(rc localRouteCheckFunc, pods map[string]podEntry) *k8sResolver {
		return &k8sResolver{
			nodeIP:          "10.0.0.1",
			logger:          testLogger(),
			localCIDRs:      testLocalCIDRs(podCIDR),
			localRouteCheck: rc,
			podMap:          pods,
		}
	}
	withoutCIDR := func(pods map[string]podEntry) *k8sResolver {
		return &k8sResolver{
			nodeIP: "10.0.0.1",
			logger: testLogger(),
			podMap: pods,
			localRouteCheck: func(string, []string) (bool, error) {
				t.Fatal("route check must not run when there are no local CIDRs")
				return true, nil
			},
		}
	}
	localPod := map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"}}

	for _, tc := range []struct {
		name     string
		resolver *k8sResolver
		dest     string
		want     bool
	}{
		{
			name:     "local pod accepted",
			resolver: withCIDR(passthroughLocalRouteCheck, localPod),
			dest:     "10.244.0.5",
			want:     true,
		},
		{
			name: "remote pod rejected",
			resolver: withCIDR(passthroughLocalRouteCheck, map[string]podEntry{
				"10.244.1.5": {nodeIP: "10.0.0.2", uid: "uid-remote"},
			}),
			dest: "10.244.1.5",
			want: false,
		},
		{
			name: "hostNetwork pod cached as own IP rejected as host address",
			resolver: withCIDR(passthroughLocalRouteCheck, map[string]podEntry{
				"10.0.0.1": {nodeIP: "10.0.0.1", uid: "uid-hostnetwork"},
			}),
			dest: "10.0.0.1",
			want: false,
		},
		{name: "IPv4 loopback rejected", resolver: withCIDR(passthroughLocalRouteCheck, nil), dest: "127.0.0.1", want: false},
		{name: "IPv6 loopback rejected", resolver: withCIDR(passthroughLocalRouteCheck, nil), dest: "::1", want: false},
		{
			name: "pod inside cached but outside discovered CIDR rejected",
			resolver: withCIDR(passthroughLocalRouteCheck, map[string]podEntry{
				"10.244.99.5": {nodeIP: "10.0.0.1", uid: "uid-out-of-cidr"},
			}),
			dest: "10.244.99.5",
			want: false,
		},
		{
			name:     "no local CIDRs accepts local pod via Kubernetes ownership",
			resolver: withoutCIDR(localPod),
			dest:     "10.244.0.5",
			want:     true,
		},
		{
			name: "no local CIDRs rejects remote pod",
			resolver: withoutCIDR(map[string]podEntry{
				"10.244.1.5": {nodeIP: "10.0.0.2", uid: "uid-remote"},
			}),
			dest: "10.244.1.5",
			want: false,
		},
		{
			name:     "no local CIDRs rejects unknown pod",
			resolver: withoutCIDR(nil),
			dest:     "10.244.0.99",
			want:     false,
		},
		{
			name:     "route check returns true → accept",
			resolver: withCIDR(func(string, []string) (bool, error) { return true, nil }, localPod),
			dest:     "10.244.0.5",
			want:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.resolver.ValidateLocalDest(tc.dest); got != tc.want {
				t.Fatalf("ValidateLocalDest(%q) = %v, want %v", tc.dest, got, tc.want)
			}
		})
	}
}

// Pins host-address rejection against non-canonical IPv6 forms — without
// canonicalization a peer-supplied "::ffff:10.0.0.1" or expanded IPv6 in
// the inbound header would slip past the host-address check.
func TestK8sResolverIsHostAddressCanonicalizesInput(t *testing.T) {
	cases := []struct {
		nodeIP string
		input  string
	}{
		{"10.0.0.1", "::ffff:10.0.0.1"},
		{"fd00::10", "FD00:0:0:0:0:0:0:10"},
		{"fd00::10", "fd00:0000:0000:0000:0000:0000:0000:0010"},
	}
	for _, tc := range cases {
		r := &k8sResolver{nodeIP: tc.nodeIP, logger: testLogger()}
		if !r.isHostAddress(tc.input) {
			t.Errorf("isHostAddress(nodeIP=%q, input=%q) = false, want true", tc.nodeIP, tc.input)
		}
	}
}

func TestSelectLocalPodCIDRsExcludesNodeFabricAndTunnels(t *testing.T) {
	_, podBridge, _ := net.ParseCIDR("10.244.1.0/24")
	_, nodeVLAN, _ := net.ParseCIDR("10.0.0.0/16")
	_, nodeVLAN6, _ := net.ParseCIDR("fd00:10::/64")
	_, tunSubnet, _ := net.ParseCIDR("172.20.0.0/16")
	_, linkLocal, _ := net.ParseCIDR("169.254.0.0/16")

	ifaces := []interfaceInfo{
		// eth0: node fabric, contains nodeIP 10.0.0.5 — the whole
		// interface must be excluded, including a dual-stack IPv6 subnet
		// that would not contain the configured IPv4 nodeIP by itself.
		{name: "eth0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.0.0.5"), Mask: nodeVLAN.Mask},
			{IP: net.ParseIP("fd00:10::5"), Mask: nodeVLAN6.Mask},
		}},
		// cni0: pod-network bridge — must be kept.
		{name: "cni0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.244.1.1"), Mask: podBridge.Mask},
		}},
		// wg0: point-to-point VPN — must be excluded even though it carries a
		// non-trivial subnet, because pod traffic does not originate on a
		// p2p iface and a forged PodIP inside the tunnel range would have
		// passed the previous, looser check.
		{name: "wg0", flags: net.FlagUp | net.FlagPointToPoint, addrs: []*net.IPNet{
			{IP: net.ParseIP("172.20.0.7"), Mask: tunSubnet.Mask},
		}},
		// down: skipped because !FlagUp.
		{name: "ens6", flags: net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.244.2.1"), Mask: podBridge.Mask},
		}},
		// lo: loopback — excluded.
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []*net.IPNet{
			{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}},
		// link-local on otherwise-OK iface: address dropped.
		{name: "veth-ll", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("169.254.1.1"), Mask: linkLocal.Mask},
		}},
		// /32 host route — dropped (pod bridges are wider than a single host).
		{name: "dummy0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.244.9.9"), Mask: net.CIDRMask(32, 32)},
		}},
		// Up but not broadcast-capable — not a pod bridge.
		{name: "nobroadcast0", flags: net.FlagUp, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.244.3.1"), Mask: podBridge.Mask},
		}},
	}

	got := selectLocalPodCIDRs("10.0.0.5", ifaces)

	want := []string{"10.244.1.0/24"}
	if len(got) != len(want) || got[0].cidr.String() != want[0] {
		gotStrs := make([]string, len(got))
		for i, c := range got {
			gotStrs[i] = c.cidr.String()
		}
		t.Fatalf("selectLocalPodCIDRs = %v, want %v", gotStrs, want)
	}
	if got[0].iface != "cni0" {
		t.Fatalf("selectLocalPodCIDRs iface = %q, want cni0", got[0].iface)
	}
}

// Pins the documented safety argument: selectLocalPodCIDRs over-accepts a
// docker0-shaped bridge, and ValidateLocalDest's podMap check is the gate
// that filters those over-accepted IPs. A reorder or removal of the
// podMap check trips this test instead of silently widening the
// inbound-plaintext-dial boundary.
func TestValidateLocalDestFiltersOverAcceptedCIDRs(t *testing.T) {
	_, podBridge, _ := net.ParseCIDR("10.244.1.0/24")
	_, dockerBridge, _ := net.ParseCIDR("172.17.0.0/16")
	nodeIP := "10.0.0.5"

	// Half 1: selectLocalPodCIDRs over-accepts a docker0-shaped bridge.
	ifaces := []interfaceInfo{
		{name: "cni0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("10.244.1.1"), Mask: podBridge.Mask},
		}},
		{name: "docker0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{
			{IP: net.ParseIP("172.17.0.1"), Mask: dockerBridge.Mask},
		}},
	}
	got := selectLocalPodCIDRs(nodeIP, ifaces)
	var sawDocker bool
	for _, c := range got {
		if c.iface == "docker0" {
			sawDocker = true
			break
		}
	}
	if !sawDocker {
		t.Fatalf("selectLocalPodCIDRs no longer over-accepts a docker-shaped bridge that does not contain the node IP; the safety argument here assumes that over-acceptance and a downstream podMap filter — review ValidateLocalDest accordingly. got=%v", got)
	}

	// Half 2: ValidateLocalDest rejects an IP inside the over-accepted CIDR
	// when no pod owns it, and accepts the same IP once a pod claims it.
	r := &k8sResolver{
		nodeIP:          nodeIP,
		logger:          testLogger(),
		localCIDRs:      got,
		localRouteCheck: passthroughLocalRouteCheck,
		podMap:          map[string]podEntry{},
	}

	const dockerIP = "172.17.0.5"
	if r.ValidateLocalDest(dockerIP) {
		t.Fatal("ValidateLocalDest accepted an IP inside the over-accepted docker0 CIDR with no podMap entry; the podMap safety gate has regressed")
	}

	r.podMap[dockerIP] = podEntry{nodeIP: nodeIP, uid: types.UID("over-accept-test")}
	if !r.ValidateLocalDest(dockerIP) {
		t.Fatal("ValidateLocalDest rejected an over-accepted-CIDR IP that has a matching local podMap entry; the CIDR filter is now over-constraining")
	}
}

func TestPodStatusIPsCanonicalizesNonStandardIPv6(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			PodIP: "2001:db8:0:0:0:0:0:1",
			PodIPs: []corev1.PodIP{
				// Same address in canonical form — must dedupe.
				{IP: "2001:db8::1"},
				// Different address in uppercase — must lower-case to match
				// SO_ORIGINAL_DST / ipset side.
				{IP: "FD00::ABCD"},
				// IPv4-mapped — net.ParseIP returns 4-in-6; .String() collapses.
				{IP: "10.244.0.5"},
			},
		},
	}
	got := podStatusIPs(pod)
	want := []string{"2001:db8::1", "fd00::abcd", "10.244.0.5"}
	if len(got) != len(want) {
		t.Fatalf("podStatusIPs = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("podStatusIPs[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// Shrink the inter-retry pause so the three bootstrap tests don't burn the
// production 200ms cadence every iteration. The budget itself is passed per
// test, so this only affects how long each test sleeps between attempts.
func init() {
	localCIDRBootInterval = time.Millisecond
}

// bootstrapTimingSlack is the wall-clock tolerance the bootstrap tests
// allow on top of their declared budget or "immediate return" contract.
// Generous enough that scheduler stalls under -race on stressed CI don't
// flake the assertion, tight enough that a real regression (the loop
// failing to honour ctx.Done() or the deadline) still trips it.
const bootstrapTimingSlack = 500 * time.Millisecond

// On a transiently-empty first sample, bootstrap must keep polling within
// the budget so a CNI bridge coming up after the proxy starts doesn't pin
// ValidateLocalDest in the K8s pod-ownership fallback until the 30s refresh tick.
func TestBootstrapLocalCIDRsRetriesUntilPopulated(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("10.244.0.0/24")
	var calls int
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
		localCIDRSource: func(string) ([]localCIDR, error) {
			calls++
			if calls < 3 {
				return nil, nil
			}
			return testLocalCIDRs(podCIDR), nil
		},
	}

	r.bootstrapLocalCIDRs(context.Background(), time.Second)

	if calls != 3 {
		t.Errorf("expected bootstrap to poll until non-empty (3 calls), got %d", calls)
	}
	if r.LocalCIDRCount() != 1 {
		t.Errorf("LocalCIDRCount = %d after bootstrap, want 1", r.LocalCIDRCount())
	}
}

// When the kernel never returns CIDRs, bootstrap must give up within
// ~budget so startup isn't blocked indefinitely; the async refresh loop
// picks up later. Assert on elapsed time, not attempt count (the last
// sleep gets clipped at the deadline).
func TestBootstrapLocalCIDRsGivesUpAfterBudget(t *testing.T) {
	var calls int
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
		localCIDRSource: func(string) ([]localCIDR, error) {
			calls++
			return nil, nil
		},
	}

	budget := 10 * localCIDRBootInterval
	start := time.Now()
	r.bootstrapLocalCIDRs(context.Background(), budget)
	elapsed := time.Since(start)

	if elapsed > budget+bootstrapTimingSlack {
		t.Errorf("bootstrap took %v, want ≤ %v + %v slack", elapsed, budget, bootstrapTimingSlack)
	}
	if calls < 2 {
		t.Errorf("expected at least one retry, got %d call(s)", calls)
	}
	if r.LocalCIDRCount() != 0 {
		t.Errorf("LocalCIDRCount = %d after exhausted bootstrap, want 0 (fallback active)", r.LocalCIDRCount())
	}
}

// ctx cancellation during the boot sleep must short-circuit so a pod
// terminating mid-startup doesn't wait out the full retry budget.
func TestBootstrapLocalCIDRsHonoursContextCancel(t *testing.T) {
	var calls int
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
		localCIDRSource: func(string) ([]localCIDR, error) {
			calls++
			return nil, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	r.bootstrapLocalCIDRs(ctx, time.Hour)
	if elapsed := time.Since(start); elapsed > bootstrapTimingSlack {
		t.Errorf("bootstrap waited %v after ctx cancel; want ≤ %v", elapsed, bootstrapTimingSlack)
	}
	if calls > 1 {
		t.Errorf("expected at most 1 source call after immediate cancel, got %d", calls)
	}
}

// Refresh goroutine relies on reconcile being idempotent and safe to call
// from any goroutine with no setup. enumerateLocalPodCIDRs hits the real
// kernel, so this can't pin a CIDR set — it just enforces that contract.
func TestReconcileLocalCIDRsIsIdempotent(t *testing.T) {
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		podMap:          make(map[string]podEntry),
		localCIDRSource: enumerateLocalPodCIDRs,
	}

	r.reconcileLocalCIDRs(true)
	r.reconcileLocalCIDRs(false)
	r.reconcileLocalCIDRs(false)
}

func TestCIDRSetEqualTreatsDuplicatesAsDistinct(t *testing.T) {
	_, cidrA, _ := net.ParseCIDR("10.244.0.0/24")
	_, cidrB, _ := net.ParseCIDR("10.244.1.0/24")

	if cidrSetEqual(testLocalCIDRs(cidrA, cidrB), testLocalCIDRs(cidrA, cidrA)) {
		t.Fatal("cidrSetEqual considered duplicate replacement equal to distinct CIDRs")
	}
	if !cidrSetEqual(testLocalCIDRs(cidrA, cidrA, cidrB), testLocalCIDRs(cidrB, cidrA, cidrA)) {
		t.Fatal("cidrSetEqual should ignore order while preserving duplicate counts")
	}
}

func TestK8sResolverCanonicalizesHostIPForLocalChecks(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("fd00:1::/64")
	r := &k8sResolver{
		nodeIP:          "fd00::10",
		logger:          testLogger(),
		localCIDRs:      testLocalCIDRs(podCIDR),
		localRouteCheck: passthroughLocalRouteCheck,
		podMap:          make(map[string]podEntry),
	}

	r.onPod(&corev1.Pod{
		UID: "uid-v6",
		Status: corev1.PodStatus{
			HostIP: "FD00:0:0:0:0:0:0:10",
			PodIP:  "fd00:1::5",
		},
	})

	if !r.ValidateLocalDest("fd00:1::5") {
		t.Fatal("local pod with equivalent non-canonical HostIP should be accepted")
	}
	nodeIP, local := r.Resolve("fd00:1::5")
	if nodeIP != "fd00::10" || !local {
		t.Fatalf("Resolve returned (%q, %v), want (fd00::10, true)", nodeIP, local)
	}
}

// Writes canonicalize via podStatusIPs; the validators and Resolve must canonicalize
// reads too, so a peer that hands us a non-canonical IPv6 in the destination header
// (or any caller emitting `[2001:db8:0:0:0:0:0:1]:8080`) still hits the cached entry
// instead of silently falling through as unknown.
func TestK8sResolverLookupsCanonicalizeNonStandardIPv6(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("fd00::/64")
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		localCIDRs:      testLocalCIDRs(podCIDR),
		localRouteCheck: passthroughLocalRouteCheck,
		podMap: map[string]podEntry{
			"fd00::1": {nodeIP: "10.0.0.1", uid: "uid-1"},
		},
	}

	for _, variant := range []string{"fd00::1", "FD00::1", "fd00:0:0:0:0:0:0:1"} {
		if ok, reason := r.ValidateOutboundDest(variant); !ok {
			t.Errorf("ValidateOutboundDest(%q) = (false, %q), want (true, \"\")", variant, reason)
		}
		if !r.ValidateLocalDest(variant) {
			t.Errorf("ValidateLocalDest(%q): want true", variant)
		}
		nodeIP, local := r.Resolve(variant)
		if nodeIP != "10.0.0.1" || !local {
			t.Errorf("Resolve(%q) = (%q, %v); want (10.0.0.1, true)", variant, nodeIP, local)
		}
	}
}

func TestK8sResolverValidateLocalDestRejectsOffInterfaceRoute(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("10.244.0.0/24")
	var gotDest string
	var gotIfaces []string
	r := &k8sResolver{
		nodeIP:     "10.0.0.1",
		logger:     testLogger(),
		localCIDRs: testLocalCIDRs(podCIDR),
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"},
		},
		localRouteCheck: func(dest string, allowedIfaces []string) (bool, error) {
			gotDest = dest
			gotIfaces = append([]string(nil), allowedIfaces...)
			return false, nil
		},
	}

	if r.ValidateLocalDest("10.244.0.5") {
		t.Fatal("local pod must be rejected when the kernel route leaves via another interface")
	}
	if gotDest != "10.244.0.5" {
		t.Fatalf("route check dest = %q, want 10.244.0.5", gotDest)
	}
	if len(gotIfaces) != 1 || gotIfaces[0] != "cni0" {
		t.Fatalf("route check allowedIfaces = %v, want [cni0]", gotIfaces)
	}
}

// ValidateLocalDest takes an RLock across the CIDR-membership check and the
// podMap lookup, and reconcileLocalCIDRs swaps the cached slice under a write
// lock. Run both concurrently under -race to lock in that the readers either
// see the pre-swap CIDR set or the post-swap set — never a torn slice — and
// no panic / data race surfaces. The pod IP is in both CIDR sets so the
// "consistent across the swap" assertion can be a simple equality check.
func TestK8sResolverValidateLocalDestVsCIDRRefresh(t *testing.T) {
	_, cidrA, _ := net.ParseCIDR("10.244.0.0/24")
	_, cidrB, _ := net.ParseCIDR("10.244.0.0/16")
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		localCIDRs:      testLocalCIDRs(cidrA),
		localRouteCheck: passthroughLocalRouteCheck,
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-local"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	const readers = 8
	done := make(chan struct{})
	for range readers {
		go func() {
			defer func() { done <- struct{}{} }()
			for ctx.Err() == nil {
				if !r.ValidateLocalDest("10.244.0.5") {
					t.Errorf("ValidateLocalDest must stay true: the pod IP belongs to both CIDR sets the writer alternates between")
					return
				}
			}
		}()
	}

	go func() {
		defer func() { done <- struct{}{} }()
		toggle := false
		for ctx.Err() == nil {
			r.mu.Lock()
			if toggle {
				r.localCIDRs = testLocalCIDRs(cidrA)
			} else {
				r.localCIDRs = testLocalCIDRs(cidrB)
			}
			toggle = !toggle
			r.mu.Unlock()
		}
	}()

	for range readers + 1 {
		<-done
	}
}

func TestK8sResolverPodEvents(t *testing.T) {
	dualStack := &corev1.Pod{
		UID: "uid-1",
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00::5"}},
		},
	}
	hostNetwork := &corev1.Pod{
		UID:  "uid-host",
		Spec: corev1.PodSpec{HostNetwork: true},
		Status: corev1.PodStatus{
			PodIP:  "10.0.0.1",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}},
		},
	}
	pending := &corev1.Pod{Status: corev1.PodStatus{PodIP: "10.244.0.5"}}
	succeeded := &corev1.Pod{
		UID: "uid-1",
		Status: corev1.PodStatus{
			Phase:  corev1.PodSucceeded,
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00::5"}},
		},
	}
	failed := &corev1.Pod{
		UID: "uid-1",
		Status: corev1.PodStatus{
			Phase:  corev1.PodFailed,
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	tombstone := cache.DeletedFinalStateUnknown{
		Obj: &corev1.Pod{
			UID: "uid-tomb",
			Status: corev1.PodStatus{
				PodIP:  "10.244.0.5",
				HostIP: "10.0.0.1",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
			},
		},
	}

	cases := []struct {
		name    string
		seed    map[string]podEntry
		event   func(r *k8sResolver)
		wantIn  []string // keys that must be present after the event
		wantOut []string // keys that must NOT be present after the event
	}{
		{
			name:   "add dual-stack pod caches both families",
			event:  func(r *k8sResolver) { r.onPod(dualStack) },
			wantIn: []string{"10.244.0.5", "fd00::5"},
		},
		{
			name:    "delete pod removes every cached IP family",
			seed:    map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-1"}, "fd00::5": {nodeIP: "10.0.0.1", uid: "uid-1"}},
			event:   func(r *k8sResolver) { r.onDeletePod(dualStack) },
			wantOut: []string{"10.244.0.5", "fd00::5"},
		},
		{
			name:    "tombstone delete still removes",
			seed:    map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-tomb"}},
			event:   func(r *k8sResolver) { r.onDeletePod(tombstone) },
			wantOut: []string{"10.244.0.5"},
		},
		{
			name:    "hostNetwork pod not cached",
			event:   func(r *k8sResolver) { r.onPod(hostNetwork) },
			wantOut: []string{"10.0.0.1"},
		},
		{
			name:    "pending pod without HostIP not cached",
			event:   func(r *k8sResolver) { r.onPod(pending) },
			wantOut: []string{"10.244.0.5"},
		},
		{
			name:    "succeeded pod evicted from cache",
			seed:    map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-1"}, "fd00::5": {nodeIP: "10.0.0.1", uid: "uid-1"}},
			event:   func(r *k8sResolver) { r.onPod(succeeded) },
			wantOut: []string{"10.244.0.5", "fd00::5"},
		},
		{
			name:    "failed pod evicted from cache",
			seed:    map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-1"}},
			event:   func(r *k8sResolver) { r.onPod(failed) },
			wantOut: []string{"10.244.0.5"},
		},
		{
			// IP reuse: the cache already holds the successor pod under a
			// different UID. A late terminal update for the prior owner must
			// not evict the new entry.
			name:   "succeeded update after IP reuse preserves successor",
			seed:   map[string]podEntry{"10.244.0.5": {nodeIP: "10.0.0.1", uid: "uid-successor"}},
			event:  func(r *k8sResolver) { r.onPod(succeeded) },
			wantIn: []string{"10.244.0.5"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed := make(map[string]podEntry, len(tc.seed))
			maps.Copy(seed, tc.seed)
			r := &k8sResolver{nodeIP: "10.0.0.1", logger: testLogger(), podMap: seed}
			tc.event(r)
			for _, k := range tc.wantIn {
				if got, ok := r.podMap[k]; !ok || got.nodeIP != "10.0.0.1" {
					t.Errorf("podMap[%q] = %+v, want present with nodeIP 10.0.0.1", k, got)
				}
			}
			for _, k := range tc.wantOut {
				if _, ok := r.podMap[k]; ok {
					t.Errorf("podMap[%q] should be absent", k)
				}
			}
		})
	}
}

func TestK8sResolverInformer(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			Name: "pod-a", Namespace: "default", UID: "uid-a",
			Status: corev1.PodStatus{
				PodIP:  "10.244.0.10",
				HostIP: "10.0.0.1",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}},
			},
		},
		&corev1.Pod{
			Name: "pod-b", Namespace: "default", UID: "uid-b",
			Status: corev1.PodStatus{
				PodIP:  "10.244.1.10",
				HostIP: "10.0.0.2",
				PodIPs: []corev1.PodIP{{IP: "10.244.1.10"}},
			},
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, err := newK8sResolver(ctx, clientset, "10.0.0.1", 0, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// pod-a is on our node → local.
	nodeIP, local := r.Resolve("10.244.0.10")
	if nodeIP != "10.0.0.1" || !local {
		t.Errorf("pod-a: got (%q, %v), want (10.0.0.1, true)", nodeIP, local)
	}

	// pod-b is on a different node → remote.
	nodeIP, local = r.Resolve("10.244.1.10")
	if nodeIP != "10.0.0.2" || local {
		t.Errorf("pod-b: got (%q, %v), want (10.0.0.2, false)", nodeIP, local)
	}
}

// LastEventTime must advance on EVERY informer event, even pending pods whose
// HostIP/PodIPs aren't set yet — alerts that read it as "informer alive"
// false-page during a burst of pending-phase churn if the gauge only
// advances on cache-mutating events.
func TestK8sResolverLastEventTime(t *testing.T) {
	full := &corev1.Pod{
		UID: "uid-evt",
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	pending := &corev1.Pod{UID: "uid-pending", Status: corev1.PodStatus{}}

	for _, tc := range []struct {
		name  string
		event func(r *k8sResolver)
	}{
		{name: "onPod with full status", event: func(r *k8sResolver) { r.onPod(full) }},
		{name: "onDeletePod", event: func(r *k8sResolver) { r.onDeletePod(full) }},
		{name: "onPod with pending-phase status (no HostIP)", event: func(r *k8sResolver) { r.onPod(pending) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &k8sResolver{nodeIP: "10.0.0.1", logger: testLogger(), podMap: make(map[string]podEntry)}
			if got := r.LastEventTime(); got != 0 {
				t.Errorf("initial LastEventTime = %d, want 0", got)
			}
			tc.event(r)
			if got := r.LastEventTime(); got <= 0 {
				t.Errorf("LastEventTime after event = %d, want > 0", got)
			}
		})
	}
}

func TestK8sResolverDeleteGuardsIPReuse(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: make(map[string]podEntry),
	}

	// Pod A gets IP 10.244.0.5.
	podA := &corev1.Pod{
		UID: "uid-a",
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	r.onPod(podA)

	// Pod B gets the same IP (reuse) on the same node.
	podB := &corev1.Pod{
		UID: "uid-b",
		Status: corev1.PodStatus{
			PodIP:  "10.244.0.5",
			HostIP: "10.0.0.1",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	r.onPod(podB)

	// Late delete for Pod A arrives — must NOT remove Pod B's entry.
	r.onDeletePod(podA)

	entry, ok := r.podMap["10.244.0.5"]
	if !ok {
		t.Fatal("late delete for Pod A incorrectly removed Pod B's cache entry")
	}
	if entry.uid != types.UID("uid-b") {
		t.Errorf("entry.uid = %q, want uid-b", entry.uid)
	}

	// Delete for Pod B should remove it.
	r.onDeletePod(podB)
	if _, ok := r.podMap["10.244.0.5"]; ok {
		t.Error("delete for Pod B should have removed the entry")
	}
}
