package cdsha

import (
	"sync/atomic"
	"testing"
	"time"
)

// Seat readiness must retain monotonic time and expire independently of a
// fresh read certificate. Clock observations are synthetic; the status fetch,
// read worker, and Ready path run against four actual Raft nodes.
func TestReadinessSeatReportMonotonicExpiry(t *testing.T) {
	c := newCluster(t, 3)
	var seatStatus atomic.Int32
	c.startWithControl("n0", "m1", func(next controlHandler) controlHandler {
		return func(peer Claims, req controlRequest) controlResponse {
			resp := next(peer, req)
			if req.Op == ctlStatus {
				switch seatStatus.Load() {
				case 1:
					return controlResponse{Err: "test: seat status unavailable"}
				case 2:
					if resp.Status != nil {
						resp.Status.SeatsFilled = false
					}
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
	for _, r := range c.live() {
		if !r.node.isVoter() {
			nv = r.node
			break
		}
	}
	if nv == nil {
		t.Fatal("no nonvoter")
	}
	eventually(t, 3*time.Second, "nonvoter initially ready", nv.Ready)
	nv.refreshSeats()
	recorded := nv.seatsOKAt.Load()
	// Compare representation: Time.Equal ignores whether monotonic data was retained.
	if recorded == nil || *recorded == recorded.Round(0) { //nolint:staticcheck // QF1009 would erase the property under test.
		t.Fatal("seat report discarded monotonic clock")
	}
	// A failed status fetch retains a still-young report: do not turn a
	// transient status failure into a stricter rollout policy.
	seatStatus.Store(1)
	nv.refreshSeats()
	if !nv.Ready() {
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
		if nv.Ready() {
			t.Fatal("expired monotonic seat report admitted rollout")
		}
	}
	future := time.Now().Add(time.Minute)
	nv.seatsOKAt.Store(&future)
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
	if nv.Ready() {
		t.Fatal("fresh quorum barrier revived expired seat report")
	}
	fresh := time.Now()
	nv.seatsOKAt.Store(&fresh)
	if !nv.Ready() {
		t.Fatal("fresh seat report refused")
	}
	seatStatus.Store(2)
	nv.refreshSeats()
	if nv.seatsOKAt.Load() != nil || nv.Ready() {
		t.Fatal("explicit incomplete-seat report retained cached readiness")
	}
}
