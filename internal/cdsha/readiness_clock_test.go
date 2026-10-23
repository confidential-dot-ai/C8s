package cdsha

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// Seat readiness must retain monotonic time and expire independently of a
// fresh read certificate. This is a cache-response fixture, not a test of
// physical seat availability: status replies are controlled, while four real
// Raft nodes, the read worker, and the Serving/Ready paths remain live.
func TestReadinessSeatReportMonotonicExpiry(t *testing.T) {
	c := newCluster(t, 3)
	// Each token permits exactly one successful status reply. All other
	// fetches fail without changing the cache. Observing the resulting cache
	// write drains that one successful reply before we inject cache ages;
	// merely switching a response mode would leave old replies in flight.
	seatReports := make(chan bool, 1)
	var reportPeer atomic.Pointer[[48]byte]
	c.startWithControl("n0", "m1", func(next controlHandler) controlHandler {
		return func(peer Claims, req controlRequest) controlResponse {
			resp := next(peer, req)
			if req.Op == ctlStatus {
				if target := reportPeer.Load(); target == nil || peer.ReportData != *target {
					return controlResponse{Err: "test: seat status unavailable"}
				}
				select {
				case filled := <-seatReports:
					if resp.Status != nil {
						resp.Status.SeatsFilled = filled
					}
				default:
					return controlResponse{Err: "test: seat status unavailable"}
				}
			}
			return resp
		}
	})
	c.start("n1", "m1")
	c.start("n2", "m1")
	c.start("n3", "m1")
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis", func() bool { s, ok := c.decrees.get(g); return ok && s.AppliedEpoch != nil })
	c.settled(15 * time.Second)
	if !c.nodes["n0"].node.leading() {
		t.Fatal("bootstrap leader changed")
	}
	var nv *Node
	nonvoters := c.nodes["n0"].node.Status().NonVoters
	for _, r := range c.live() {
		if slices.Contains(nonvoters, r.node.ID()) {
			nv = r.node
			break
		}
	}
	if nv == nil {
		t.Fatal("no nonvoter")
	}
	assertCachePath := func() {
		t.Helper()
		if !c.nodes["n0"].node.leading() || nv.leaderHostPort() != c.nodes["n0"].node.cfg.Advertise || nv.isVoter() || nv.leading() {
			t.Fatalf("seat-cache fixture role changed: bootstrapLeader=%v targetLeader=%q targetVoter=%v targetLeading=%v", c.nodes["n0"].node.leading(), nv.leaderHostPort(), nv.isVoter(), nv.leading())
		}
		if !nv.Serving() {
			t.Fatal("seat-cache assertion lacks a fresh quorum read")
		}
	}
	assertCachePath()
	// Bind tokens to this replica: another member may still be finishing a
	// refresh started before its local configuration reflected promotion.
	leaf := nv.cert.Load().Leaf
	binding := PeerBinding(nv.cfg.ClusterID, leaf.RawSubjectPublicKeyInfo, leaf.NotAfter)
	reportPeer.Store(&binding)
	seatReports <- true
	nv.refreshSeats()
	// The automatic membership loop may consume the token first. Wait for
	// its completed cache write, not just for the server to send the reply.
	eventually(t, 3*time.Second, "positive seat report recorded", func() bool { return nv.seatsOKAt.Load() != nil })
	recorded := nv.seatsOKAt.Load()
	if recorded == nil {
		t.Fatal("no positive seat report recorded")
	}
	// Compare representation: Time.Equal ignores whether monotonic data was retained.
	if *recorded == recorded.Round(0) { //nolint:staticcheck // QF1009 would erase the property under test.
		t.Fatal("seat report discarded monotonic clock")
	}
	assertCachePath()
	if !nv.Ready() {
		t.Fatal("positive seat report refused")
	}
	// A failed status fetch retains a still-young report: do not turn a
	// transient status failure into a stricter rollout policy.
	nv.refreshSeats()
	if nv.seatsOKAt.Load() != recorded || !nv.Ready() {
		t.Fatal("transient status failure discarded a fresh report")
	}
	ttl := 3*nv.cfg.Timing.Tick + time.Second
	for _, step := range []time.Duration{ttl / 2, time.Minute} {
		now := time.Now()
		expired := now.Add(-ttl - time.Millisecond)
		// A wall-only cache would consider this old report young after either
		// a small or a large backwards step. The stored monotonic timestamp
		// must instead expire through the actual nonvoter Ready path.
		wallAge := now.Round(0).Add(-step).Sub(expired.Round(0))
		if wallAge >= ttl {
			t.Fatal("wall-step schedule did not extend old cache")
		}
		nv.seatsOKAt.Store(&expired)
		assertCachePath()
		if nv.Ready() {
			t.Fatal("expired monotonic seat report admitted rollout")
		}
	}
	future := time.Now().Add(time.Minute)
	nv.seatsOKAt.Store(&future)
	assertCachePath()
	if nv.Ready() {
		t.Fatal("future monotonic timestamp admitted rollout")
	}
	// A future monotonic timestamp above is a defensive boundary check, not
	// a physical clock-step simulation. Real report preservation is asserted
	// against refreshSeats above.
	expired := time.Now().Add(-ttl - time.Millisecond)
	nv.seatsOKAt.Store(&expired)
	nv.jumpAt.Store(time.Now().Add(-time.Millisecond).UnixMilli())
	if nv.Serving() {
		t.Fatal("clock observation did not close admission")
	}
	eventually(t, 3*time.Second, "fresh quorum read clears clock observation", func() bool { return nv.jumpAt.Load() == 0 && nv.Serving() })
	assertCachePath()
	if nv.Ready() {
		t.Fatal("fresh quorum barrier revived expired seat report")
	}
	fresh := time.Now()
	nv.seatsOKAt.Store(&fresh)
	if !nv.Ready() {
		t.Fatal("fresh seat report refused")
	}
	assertCachePath()
	seatReports <- false
	nv.refreshSeats()
	eventually(t, 3*time.Second, "negative seat report invalidates cache", func() bool { return nv.seatsOKAt.Load() == nil })
	assertCachePath()
	if nv.seatsOKAt.Load() != nil || nv.Ready() {
		t.Fatal("explicit incomplete-seat report retained cached readiness")
	}
}
