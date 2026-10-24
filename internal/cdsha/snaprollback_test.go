package cdsha

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// F2 (chaos soak): a lagging non-voter served an allowlist entry older than
// one it had applied and acknowledged itself. Candidate: a snapshot install
// while its state machine lags, with a slow leader handing over. Raft is
// tuned to compact its log quickly, so a non-voter cut off for a moment is
// sent a snapshot; its disk and the leader's are slow. No replica may serve
// a value of a key that is older than one it served before, and no applied
// index may go back.
func TestLaggingNonVoterNeverRollsBack(t *testing.T) {
	installed := countLogs(t, "Installed remote snapshot")
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	lag := c.start("n3", "m1")
	c.settled(15 * time.Second)
	rs := c.live()
	for _, r := range rs {
		rc := r.node.r().ReloadableConfig()
		rc.TrailingLogs, rc.SnapshotThreshold, rc.SnapshotInterval = 8, 16, 100*time.Millisecond
		if err := r.node.r().ReloadConfig(rc); err != nil {
			t.Fatal(err)
		}
	}

	// One sequential writer per key, through any replica. After a write
	// that may or may not have committed it moves to a fresh key, so on
	// every key the committed values increase in log order.
	done := make(chan struct{})
	var wg sync.WaitGroup
	var acked atomic.Int64
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
				r := rs[(w+i)%len(rs)]
				if err := r.al.PutWorkload(fmt.Sprintf("it-w%dg%d", w, gen), mkWorkload(t, seq)); err != nil {
					gen++
				} else {
					acked.Add(1)
				}
			}
		}(w)
	}
	stopWriters := func() { close(done); wg.Wait() }

	// Watch every replica: the applied index, and each key's value while
	// it serves, never go back.
	var mu sync.Mutex
	var violations []string
	stopWatch := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		applied := map[string]uint64{}
		served := map[string]map[string]int{}
		for {
			select {
			case <-stopWatch:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, r := range rs {
				a := r.node.fsm.AppliedIndex()
				mu.Lock()
				if prev := applied[r.name]; a < prev {
					violations = append(violations, fmt.Sprintf("%s applied index %d -> %d", r.name, prev, a))
				}
				applied[r.name] = max(applied[r.name], a)
				mu.Unlock()
				if !r.node.Serving() {
					continue
				}
				doc, _, err := r.al.LoadAll()
				if err != nil {
					continue
				}
				mu.Lock()
				seen := served[r.name]
				if seen == nil {
					seen = map[string]int{}
					served[r.name] = seen
				}
				for name, wl := range doc.Workloads {
					if !strings.HasPrefix(name, "it-") || len(wl.Containers) == 0 {
						continue
					}
					v, err := strconv.ParseInt(strings.TrimPrefix(wl.Containers[0].Digest.String(), "sha256:"), 16, 64)
					if err != nil {
						continue
					}
					if prev, had := seen[name]; had && int(v) < prev {
						violations = append(violations, fmt.Sprintf("%s served %s = %d after %d", r.name, name, v, prev))
					}
					seen[name] = max(seen[name], int(v))
				}
				mu.Unlock()
			}
		}
	}()
	defer func() { close(stopWatch); <-watched }()

	time.Sleep(time.Second)
	old := c.leader()
	if old == nil {
		t.Fatal("no leader")
	}
	slowApply(t, 20*time.Millisecond, lag)
	slowApply(t, 2*testTiming.Lease, old)
	eventually(t, 20*time.Second, "the slow leader hands over", func() bool {
		l := c.leader()
		return l != nil && l != old
	})
	for round := 0; round < 4; round++ {
		// Shorter than DeadAfter: the non-voter stays a member, falls
		// behind the compacted log, and is sent a snapshot.
		c.partition(lag.name, true)
		time.Sleep(testTiming.DeadAfter * 2 / 3)
		c.partition(lag.name, false)
		time.Sleep(1500 * time.Millisecond)
	}
	eventually(t, 20*time.Second, "the lagging replica serves again", lag.node.Serving)
	stopWriters()

	mu.Lock()
	defer mu.Unlock()
	installs := installed.Load()
	t.Logf("acked writes %d, snapshots installed: %d", acked.Load(), installs)
	for _, v := range violations {
		t.Error(v)
	}
	if installs == 0 {
		t.Fatal("the lagging replica was never sent a snapshot: the test did not exercise the candidate")
	}
	if acked.Load() == 0 {
		t.Fatal("no write was acknowledged")
	}
}

// countLogs counts the log records, from every replica of the test, whose
// message contains msg (Raft's lines arrive through the default logger).
func countLogs(t *testing.T, msg string) *atomic.Int64 {
	var n atomic.Int64
	prev := slog.Default()
	// Not prev.Handler(): the initial default writes through package log,
	// which SetDefault points back at the new default.
	slog.SetDefault(slog.New(countingHandler{Handler: slog.NewTextHandler(os.Stderr, nil), msg: msg, n: &n}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &n
}

type countingHandler struct {
	slog.Handler
	msg string
	n   *atomic.Int64
}

func (h countingHandler) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.msg) {
		h.n.Add(1)
	}
	return h.Handler.Handle(ctx, r)
}

func (h countingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return countingHandler{Handler: h.Handler.WithAttrs(as), msg: h.msg, n: h.n}
}

func (h countingHandler) WithGroup(g string) slog.Handler {
	return countingHandler{Handler: h.Handler.WithGroup(g), msg: h.msg, n: h.n}
}
