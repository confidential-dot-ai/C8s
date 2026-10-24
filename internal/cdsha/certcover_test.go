package cdsha

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// F2 (chaos soak 23:51): a follower with a slow disk served an allowlist
// entry older than one acknowledged 5 s before the read, while the leader's
// disk was slow too and it handed leadership over. Every write acknowledged
// before a read certificate's start is committed before that certificate's
// barrier, so a read the follower admits under it must see the write; and no
// value it serves may go back.
func TestSlowFollowerReadsCoverItsCertificate(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	f := c.start("n3", "m1")
	c.settled(15 * time.Second)
	rs := c.live()

	type ack struct {
		seq int
		end time.Time
	}
	var mu sync.Mutex
	acks := map[string][]ack{} // workload name -> acks in order
	var violations []string
	done := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			gen, seq := 0, 0
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				seq++
				name := fmt.Sprintf("it-w%dg%d", w, gen)
				if err := rs[(w+i)%len(rs)].al.PutWorkload(name, mkWorkload(t, seq)); err != nil {
					gen++ // maybe committed: a fresh key keeps values increasing in log order
					continue
				}
				end := time.Now()
				mu.Lock()
				acks[name] = append(acks[name], ack{seq, end})
				mu.Unlock()
			}
		}(w)
	}
	stopWriters := func() { close(done); wg.Wait() }

	stopWatch, watched := make(chan struct{}), make(chan struct{})
	reads := 0
	go func() {
		defer close(watched)
		served := map[string]int{}
		for {
			select {
			case <-stopWatch:
				return
			case <-time.After(3 * time.Millisecond):
			}
			cert := f.node.readCert.Load()
			if !f.node.Serving() || f.node.readCert.Load() != cert || cert == nil {
				continue
			}
			doc, _, err := f.al.LoadAll()
			if err != nil {
				continue
			}
			got := map[string]int{}
			for name, wl := range doc.Workloads {
				if !strings.HasPrefix(name, "it-") || len(wl.Containers) == 0 {
					continue
				}
				v, err := strconv.ParseInt(strings.TrimPrefix(wl.Containers[0].Digest.String(), "sha256:"), 16, 64)
				if err == nil {
					got[name] = int(v) - 1 // mkWorkload digests are seq+1
				}
			}
			mu.Lock()
			reads++
			for name, as := range acks {
				want := 0
				for _, a := range as {
					if a.end.Before(cert.at) {
						want = max(want, a.seq)
					}
				}
				if want > 0 && got[name] < want {
					violations = append(violations, fmt.Sprintf("%s: %s = %d under a certificate from %s, acked %d before it",
						f.name, name, got[name], cert.at.Format("15:04:05.000"), want))
				}
			}
			for name, v := range got {
				if prev := served[name]; v < prev {
					violations = append(violations, fmt.Sprintf("%s: %s went %d -> %d", f.name, name, prev, v))
				}
				served[name] = max(served[name], v)
			}
			mu.Unlock()
		}
	}()
	defer func() { close(stopWatch); <-watched }()

	time.Sleep(time.Second)
	old := c.leader()
	if old == nil {
		t.Fatal("no leader")
	}
	slowApply(t, 150*time.Millisecond, f)
	slowApply(t, 2*testTiming.Lease, old)
	eventually(t, 20*time.Second, "the slow leader hands over", func() bool {
		l := c.leader()
		return l != nil && l != old
	})
	// Keep the slow follower reading behind its own backlog for a while,
	// then let it catch up and serve again.
	time.Sleep(4 * time.Second)
	f.node.fsm.applyDelay.Store(0)
	eventually(t, 20*time.Second, "the follower serves again", f.node.Serving)
	time.Sleep(time.Second)
	stopWriters()

	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, as := range acks {
		n += len(as)
	}
	t.Logf("acked writes %d, certified reads checked on %s: %d", n, f.name, reads)
	if len(violations) > 10 {
		violations = append(violations[:10], fmt.Sprintf("... and %d more", len(violations)-10))
	}
	for _, v := range violations {
		t.Error(v)
	}
	if reads == 0 || n == 0 {
		t.Fatal("no certified read or no acknowledged write: the test did not exercise the case")
	}
}
