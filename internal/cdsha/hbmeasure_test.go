//go:build hbmeasure

package cdsha

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Heartbeat-path measurement (not a regression test): leader stability with
// production timing under a write storm, a slow state machine and 300 ms
// round trips. Run it on this tree and on 0e39637 (which keeps Raft's
// heartbeat fast path) and compare:
//
//	go test -tags hbmeasure -run TestMeasureHeartbeats -v -timeout 30m .
//
// HBMEASURE_SECONDS sets each window (default 30).

// delayProxy forwards ip:port to ip:port+1, delaying each direction by d
// without capping throughput.
func delayProxy(t *testing.T, ip string, port int, d time.Duration) {
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
			out, err := dialer.Dial("tcp", net.JoinHostPort(ip, fmt.Sprint(port+1)))
			if err != nil {
				in.Close()
				continue
			}
			go pipeDelayed(in, out, d)
			go pipeDelayed(out, in, d)
		}
	}()
}

func pipeDelayed(src, dst net.Conn, d time.Duration) {
	type chunk struct {
		at time.Time
		b  []byte
	}
	q := make(chan chunk, 4096)
	go func() {
		defer close(q)
		for {
			buf := make([]byte, 64<<10)
			n, err := src.Read(buf)
			if n > 0 {
				q <- chunk{time.Now().Add(d), buf[:n]}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range q {
		time.Sleep(time.Until(c.at))
		if _, err := dst.Write(c.b); err != nil {
			break
		}
	}
	src.Close()
	dst.Close()
	_, _ = io.Copy(io.Discard, src)
}

// startDelayed is cluster.start with every peer address behind a delay
// proxy: the replica binds port+1, peers know it at port.
func (c *cluster) startDelayed(name string, oneWay time.Duration) *replica {
	c.t.Helper()
	c.mu.Lock()
	ip := fmt.Sprintf("127.%d.0.%d", c.block, c.nextIP)
	c.nextIP++
	c.ipOf[name] = ip
	c.meas[name] = "m1"
	c.mu.Unlock()
	delayProxy(c.t, ip, c.port, oneWay)
	al, err := allowlist.OpenInMemory()
	if err != nil {
		c.t.Fatal(err)
	}
	mem := secrets.NewMemoryStore(64, 8, 4096)
	led := sandboxledger.New(time.Hour, 100)
	n, err := NewNode(Config{
		ClusterID: testCluster, NodeName: name, Bind: fmt.Sprintf("%s:%d", ip, c.port+1), Advertise: fmt.Sprintf("%s:%d", ip, c.port),
		Attestor: MockAttestor{"m1"}, BakedPins: []string{"m1"}, OperatorPubKey: c.opPub,
		Seats: c.seats, MaxNonVoters: 8, Peers: c.peers(ip), Decrees: c.decrees, Timing: c.timingOr(),
		RecoveryKey: mustPKIX(c.t, &c.recKey.PublicKey), Backups: c.backups,
		Allowlist: &al, Secrets: mem, Ledger: led,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	n.blocked = c.blocked(ip)
	al.SetReplicator(n)
	led.SetReplicator(n)
	if err := n.Start(); err != nil {
		c.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &replica{name: name, ip: ip, node: n, al: &al, sec: secrets.ReplicatedStore{MemoryStore: mem, Repl: n}, led: led, cancel: cancel, done: make(chan struct{})}
	go func() { defer close(r.done); _ = n.Run(ctx) }()
	c.mu.Lock()
	c.nodes[name] = r
	c.mu.Unlock()
	return r
}

type hbResult struct {
	scenario                  string
	termGrowth, leaderChanges int
	maxContactMS              int64
	writes, failed            int64
	p50, p99                  time.Duration
}

func TestMeasureHeartbeats(t *testing.T) {
	window := 30 * time.Second
	if s := os.Getenv("HBMEASURE_SECONDS"); s != "" {
		var n int
		fmt.Sscan(s, &n)
		window = time.Duration(n) * time.Second
	}
	timing := DefaultTiming
	for _, sc := range []struct {
		name     string
		oneWay   time.Duration
		writers  int
		docSize  int // workloads in the document
		leaderMS int64
		followMS int64
	}{
		{name: "idle", writers: 0, docSize: 10},
		{name: "write-storm", writers: 16, docSize: 2000},
		{name: "slow-fsm-leader-200ms", writers: 4, docSize: 200, leaderMS: 200},
		{name: "slow-fsm-follower-200ms", writers: 4, docSize: 200, followMS: 200},
		{name: "rtt-300ms", oneWay: 150 * time.Millisecond, writers: 4, docSize: 200},
	} {
		t.Run(sc.name, func(t *testing.T) {
			c := newCluster(t, 3)
			c.timing = &timing
			names := []string{"n0", "n1", "n2"}
			for _, n := range names {
				if sc.oneWay > 0 {
					c.startDelayed(n, sc.oneWay)
				} else {
					c.start(n, "m1")
				}
			}
			g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
			eventually(t, 60*time.Second, "genesis applied", func() bool { st, ok := c.decrees.get(g); return ok && st.AppliedEpoch != nil })
			c.settled(90 * time.Second)
			l := c.leader()
			seed := map[string]pkgallowlist.Workload{}
			for i := range sc.docSize {
				seed[fmt.Sprintf("w%05d", i)] = mkWorkload(t, 100+i)
			}
			if _, _, err := l.al.SeedWorkloads(seed); err != nil {
				t.Fatal(err)
			}
			for _, r := range c.live() {
				if r != l {
					r.node.fsm.applyDelay.Store(int64(sc.followMS) * int64(time.Millisecond))
				} else {
					r.node.fsm.applyDelay.Store(int64(sc.leaderMS) * int64(time.Millisecond))
				}
			}
			startTerm := l.node.r().CurrentTerm()
			ctx, cancel := context.WithTimeout(context.Background(), window)
			defer cancel()
			var writes, failed atomic.Int64
			var latMu sync.Mutex
			var lats []time.Duration
			var wg sync.WaitGroup
			for w := range sc.writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rs := c.live()
					r := rs[w%len(rs)]
					for i := 0; ctx.Err() == nil; i++ {
						s := time.Now()
						if err := r.al.PutWorkload(fmt.Sprintf("w%05d", (w*7919+i)%sc.docSize), mkWorkload(t, 100000+w*100000+i)); err != nil {
							if failed.Add(1) <= 3 {
								t.Logf("write failed: %.160v", err)
							}
							time.Sleep(50 * time.Millisecond)
							continue
						}
						writes.Add(1)
						latMu.Lock()
						lats = append(lats, time.Since(s))
						latMu.Unlock()
					}
				}()
			}
			var maxContact int64
			changes := 0
			lastLeader := l.name
			tick := time.NewTicker(50 * time.Millisecond)
			for ctx.Err() == nil {
				<-tick.C
				cur := ""
				for _, r := range c.live() {
					st := r.node.Status()
					if st.State == raft.Leader.String() {
						cur = r.name
					} else if st.LastContactMS > maxContact {
						maxContact = st.LastContactMS
					}
				}
				if cur != "" && cur != lastLeader {
					changes++
					lastLeader = cur
				}
			}
			tick.Stop()
			wg.Wait()
			for _, r := range c.live() {
				r.node.fsm.applyDelay.Store(0)
			}
			endTerm := uint64(0)
			for _, r := range c.live() {
				endTerm = max(endTerm, r.node.r().CurrentTerm())
			}
			slices.Sort(lats)
			res := hbResult{scenario: sc.name, termGrowth: int(endTerm - startTerm), leaderChanges: changes, maxContactMS: maxContact, writes: writes.Load(), failed: failed.Load()}
			if len(lats) > 0 {
				res.p50, res.p99 = lats[len(lats)/2], lats[len(lats)*99/100]
			}
			t.Logf("RESULT %s: term+%d leader-changes=%d max-follower-last-contact=%dms writes=%d failed=%d p50=%s p99=%s",
				res.scenario, res.termGrowth, res.leaderChanges, res.maxContactMS, res.writes, res.failed, res.p50.Round(time.Millisecond), res.p99.Round(time.Millisecond))
		})
	}
}
