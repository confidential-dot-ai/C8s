//go:build linux

package armtlsmesh

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// reconcileLocalCIDRs must log the degraded (empty) and healthy (populated)
// outcomes with the right messages: operators alert on the empty-set warning.
func TestReconcileLocalCIDRsLogsOutcome(t *testing.T) {
	_, podCIDR, _ := net.ParseCIDR("10.244.0.0/24")
	run := func(cidrs []localCIDR) []logRecord {
		var buf syncBuffer
		r := &k8sResolver{
			nodeIP:          "10.0.0.1",
			logger:          slog.New(slog.NewJSONHandler(&buf, nil)),
			podMap:          map[string]podEntry{},
			localRouteCheck: passthroughLocalRouteCheck,
			localCIDRSource: func(string) ([]localCIDR, error) { return cidrs, nil },
		}
		r.reconcileLocalCIDRs(true)
		return decodeLogRecords(buf.String())
	}

	empty := run(nil)
	if !hasMsg(empty, "local CIDR set empty; falling back to Kubernetes pod ownership for inbound pod delivery") {
		t.Errorf("empty discovery did not warn; logs: %+v", empty)
	}
	if hasMsg(empty, "local CIDR discovery succeeded") {
		t.Errorf("empty discovery logged success; logs: %+v", empty)
	}

	populated := run(testLocalCIDRs(podCIDR))
	if !hasMsg(populated, "local CIDR discovery succeeded") {
		t.Errorf("populated discovery did not log success; logs: %+v", populated)
	}
	if hasMsg(populated, "local CIDR set empty; falling back to Kubernetes pod ownership for inbound pod delivery") {
		t.Errorf("populated discovery warned empty; logs: %+v", populated)
	}
}

// enumerateLocalPodCIDRs against a node IP that is not bound locally must
// return the real broadcast-interface subnets, not an empty set.
func TestEnumerateLocalPodCIDRsFindsBroadcastInterfaces(t *testing.T) {
	// Ensure at least one up, broadcast, non-loopback interface exists.
	found := false
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagBroadcast != 0 && ifc.Flags&net.FlagLoopback == 0 {
			if addrs, err := ifc.Addrs(); err == nil && len(addrs) > 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Skip("no up broadcast interface with addresses on this host")
	}

	cidrs, err := enumerateLocalPodCIDRs("203.0.113.199")
	if err != nil {
		t.Fatalf("enumerateLocalPodCIDRs: %v", err)
	}
	if len(cidrs) == 0 {
		t.Error("expected at least one local CIDR from a live broadcast interface")
	}
}

// newK8sResolver's boot budget: an explicit positive budget is used verbatim;
// a non-positive one falls back to the 1s default. Discovery is forced empty
// by passing the host's own IP (its interface is excluded as node fabric), so
// the bootstrap loop runs the full budget.
func TestNewK8sResolverBootTimeoutBudget(t *testing.T) {
	own := localIPv4(t)

	elapsedFor := func(budget time.Duration) time.Duration {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		start := time.Now()
		r, err := newK8sResolver(ctx, k8sfake.NewSimpleClientset(), own, budget, testLogger())
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("newK8sResolver: %v", err)
		}
		if r.LocalCIDRCount() != 0 {
			t.Skipf("host CIDR discovery unexpectedly non-empty for own IP %s", own)
		}
		return elapsed
	}

	if elapsed := elapsedFor(150 * time.Millisecond); elapsed >= 700*time.Millisecond {
		t.Errorf("explicit 150ms budget took %v; the default must not override a positive budget", elapsed)
	}
	if elapsed := elapsedFor(0); elapsed < 700*time.Millisecond {
		t.Errorf("zero budget took only %v; want the 1s default budget to apply", elapsed)
	}
}

func TestRunLocalCIDRRefreshLoop(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.244.0.0/24")
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		podMap:          map[string]podEntry{},
		localRouteCheck: passthroughLocalRouteCheck,
		localCIDRSource: func(string) ([]localCIDR, error) {
			return testLocalCIDRs(cidr), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.runLocalCIDRRefreshLoop(ctx, 5*time.Millisecond)
		close(done)
	}()
	assertEventually(t, 5*time.Second, func() bool { return r.LocalCIDRCount() == 1 }, "refresh loop never reconciled")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop did not stop on cancel")
	}
}
