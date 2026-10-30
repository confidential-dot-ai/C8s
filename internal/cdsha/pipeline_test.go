package cdsha

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
)

// fakePeer is a Raft voter that grants every vote and acknowledges every
// append on a real network transport. It can refuse appends for a while
// (a log that does not match), or stall: keep its connections open and
// never answer again, as a process that stopped running does.
type fakePeer struct {
	trans  *raft.NetworkTransport
	stall  atomic.Bool
	reject atomic.Bool // answer appends with Success false (a log that does not match)
	stop   chan struct{}
}

func newFakePeer(t *testing.T) *fakePeer {
	t.Helper()
	tr, err := raft.NewTCPTransport("127.0.0.1:0", nil, 3, time.Second, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePeer{trans: tr, stop: make(chan struct{})}
	go p.serve()
	t.Cleanup(func() { close(p.stop); _ = tr.Close() })
	return p
}

func (p *fakePeer) serve() {
	for {
		var rpc raft.RPC
		select {
		case <-p.stop:
			return
		case rpc = <-p.trans.Consumer():
		}
		if p.stall.Load() {
			continue // never answered: the sender's connection stays open, unread
		}
		switch req := rpc.Command.(type) {
		case *raft.RequestVoteRequest:
			rpc.Respond(&raft.RequestVoteResponse{Term: req.Term, Granted: true}, nil)
		case *raft.RequestPreVoteRequest:
			rpc.Respond(&raft.RequestPreVoteResponse{Term: req.Term, Granted: true}, nil)
		case *raft.AppendEntriesRequest:
			last := req.PrevLogEntry
			if n := len(req.Entries); n > 0 {
				last = req.Entries[n-1].Index
			}
			if p.reject.Load() {
				// Late, as a busy peer answers: the leader's next append is
				// on the wire by then.
				time.Sleep(50 * time.Millisecond)
				rpc.Respond(&raft.AppendEntriesResponse{Term: req.Term, LastLog: req.PrevLogEntry, Success: false}, nil)
				continue
			}
			rpc.Respond(&raft.AppendEntriesResponse{Term: req.Term, LastLog: last, Success: true}, nil)
		case *raft.InstallSnapshotRequest:
			_, _ = io.Copy(io.Discard, rpc.Reader)
			rpc.Respond(&raft.InstallSnapshotResponse{Term: req.Term, Success: true}, nil)
		case *raft.TimeoutNowRequest:
			rpc.Respond(&raft.TimeoutNowResponse{}, nil)
		}
	}
}

type nopFSM struct{}

func (nopFSM) Apply(*raft.Log) any                 { return nil }
func (nopFSM) Snapshot() (raft.FSMSnapshot, error) { return nopSnapshot{}, nil }
func (nopFSM) Restore(rc io.ReadCloser) error      { return rc.Close() }

type nopSnapshot struct{}

func (nopSnapshot) Persist(s raft.SnapshotSink) error { return s.Close() }
func (nopSnapshot) Release()                          {}

// stalledLeader leads two fake voters over a transport configured by cfg,
// writes steadily, and stalls one voter once replication to it runs
// (pipelined, if cfg allows it). The other keeps the leader's majority.
func stalledLeader(t *testing.T, cfg *raft.NetworkTransportConfig) *raft.Raft {
	t.Helper()
	logs := &syncBuffer{}
	logger := hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Info, Output: logs})
	cfg.Logger, cfg.Timeout = logger, 300*time.Millisecond
	trans, err := raft.NewTCPTransportWithConfig("127.0.0.1:0", nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rc := raft.DefaultConfig()
	rc.LocalID = "leader"
	rc.HeartbeatTimeout, rc.ElectionTimeout, rc.LeaderLeaseTimeout = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	rc.CommitTimeout = 5 * time.Millisecond
	rc.Logger = logger
	store := raft.NewInmemStore()
	r, err := raft.NewRaft(rc, nopFSM{}, store, store, raft.NewInmemSnapshotStore(), trans)
	if err != nil {
		t.Fatal(err)
	}
	good, bad := newFakePeer(t), newFakePeer(t)
	if err := r.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
		{ID: "leader", Address: trans.LocalAddr()},
		{ID: "good", Address: good.trans.LocalAddr()},
		{ID: "bad", Address: bad.trans.LocalAddr()},
	}}).Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the test raft leads", func() bool { return r.State() == raft.Leader })
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			r.Apply([]byte("x"), 50*time.Millisecond)
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() { close(done); wg.Wait() })
	if cfg.MaxRPCsInFlight != 1 {
		eventually(t, 10*time.Second, "pipelined replication to the voter", func() bool {
			return strings.Contains(logs.String(), "pipelining replication") && strings.Contains(logs.String(), string(bad.trans.LocalAddr()))
		})
	} else {
		time.Sleep(500 * time.Millisecond)
	}
	// A refused append ends raft's pipeline decoder while answers to
	// appends already sent keep coming: raft then either leaves the
	// pipeline cleanly or deadlocks in it. Each recovery lets it pipeline
	// again. Then the voter stalls for good.
	for range stallCycles {
		bad.reject.Store(true)
		time.Sleep(200 * time.Millisecond)
		bad.reject.Store(false)
		time.Sleep(300 * time.Millisecond)
	}
	bad.stall.Store(true)
	time.Sleep(time.Second)
	return r
}

// stallCycles is how often stalledLeader stalls and revives the voter.
const stallCycles = 15

func shutdownWaiter(apply time.Duration) *Node {
	return &Node{cfg: Config{Timing: Timing{Apply: apply}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// Raft v1.8's pipelined replication deadlocks against a voter that stops
// answering, and Raft then never shuts down (soak F7: a leader ignored
// SIGTERM). With the transport configuration replicas use, pipelining is
// off and Raft shuts down. awaitShutdown bounds the wait either way and
// keeps reporting a shutdown that never finished.
func TestRaftShutdownWithAStalledVoter(t *testing.T) {
	const bound = 3 * time.Second
	t.Run("pipelined", func(t *testing.T) {
		// The deadlock needs the sender to race the decoder; it shows up
		// within a few tries.
		for try := 1; try <= 6; try++ {
			r := stalledLeader(t, &raft.NetworkTransportConfig{MaxPool: 3, MaxRPCsInFlight: raft.DefaultMaxRPCsInFlight})
			n := shutdownWaiter(bound)
			n.stopRaftMu.Lock()
			err := n.awaitShutdown(r)
			if errors.Is(err, errShutdownTimeout) {
				// A second wait must not take Raft's immediate answer to a
				// second Shutdown for a finished one.
				start := time.Now()
				if err := n.awaitShutdown(r); !errors.Is(err, errShutdownTimeout) || time.Since(start) < bound/2 {
					t.Fatalf("second wait on a hung shutdown: %v after %s", err, time.Since(start))
				}
				n.stopRaftMu.Unlock()
				t.Logf("raft shutdown hung on try %d, as raft v1.8's pipeline deadlock predicts", try)
				return
			}
			n.stopRaftMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Skip("the pipeline deadlock did not occur in 6 tries")
	})
	t.Run("replica transport", func(t *testing.T) {
		for try := 1; try <= 3; try++ {
			r := stalledLeader(t, raftTransportConfig(nil, nil))
			n := shutdownWaiter(bound)
			n.stopRaftMu.Lock()
			err := n.awaitShutdown(r)
			n.stopRaftMu.Unlock()
			if err != nil {
				t.Fatalf("try %d: raft did not shut down with pipelining off: %v", try, err)
			}
		}
	})
}

// The replica transport refuses pipelining and keeps everything else Raft
// looks for: pre-vote in particular.
func TestReplicaTransportKeepsPreVote(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stream := &tcpStream{l}
	var tr raft.Transport = raft.NewNetworkTransportWithConfig(raftTransportConfig(stream, nil))
	defer tr.(raft.WithClose).Close()
	if _, err := tr.AppendEntriesPipeline("x", "127.0.0.1:1"); !errors.Is(err, raft.ErrPipelineReplicationNotSupported) {
		t.Fatalf("pipeline: %v, want ErrPipelineReplicationNotSupported", err)
	}
	if _, ok := tr.(raft.WithPreVote); !ok {
		t.Fatal("replica transport lost pre-vote")
	}
}

type tcpStream struct{ net.Listener }

func (s *tcpStream) Dial(a raft.ServerAddress, d time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", string(a), d)
}

// With pre-vote, a follower cut off past the election timeout does not
// raise the term on its return and unseat the leader.
func TestPartitionedFollowerDoesNotUnseatTheLeader(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	term := l.node.r().CurrentTerm()
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
			break
		}
	}
	c.partition(f.name, true)
	time.Sleep(testTiming.DeadAfter * 2 / 3) // several election timeouts, short of removal
	c.partition(f.name, false)
	eventually(t, 10*time.Second, "the follower serves again", f.node.Serving)
	time.Sleep(time.Second)
	if now := c.leader(); now != l || l.node.r().CurrentTerm() != term {
		t.Fatalf("leader changed %v, term %d -> %d after a follower's partition: pre-vote is off", now != l, term, l.node.r().CurrentTerm())
	}
}

// delayStream delivers every write after delay, keeping order and
// throughput: half a round trip of an injected network latency.
type delayStream struct {
	net.Listener
	delay time.Duration
}

func (s *delayStream) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newDelayConn(c, s.delay), nil
}

func (s *delayStream) Dial(a raft.ServerAddress, d time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", string(a), d)
	if err != nil {
		return nil, err
	}
	return newDelayConn(c, s.delay), nil
}

type delayConn struct {
	net.Conn
	q    chan delayed
	once sync.Once
	done chan struct{}
}

type delayed struct {
	at time.Time
	b  []byte
}

func newDelayConn(c net.Conn, d time.Duration) net.Conn {
	if d == 0 {
		return c
	}
	dc := &delayConn{Conn: c, q: make(chan delayed, 4096), done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-dc.done:
				return
			case w := <-dc.q:
				time.Sleep(time.Until(w.at.Add(d)))
				if _, err := c.Write(w.b); err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
	return dc
}

func (c *delayConn) Write(b []byte) (int, error) {
	select {
	case c.q <- delayed{time.Now(), slices.Clone(b)}:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *delayConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// The cost of pipelining off: writes/s and p99 commit latency of a
// three-voter Raft at loopback and with 100 ms injected round trips.
// Set CDSHA_PIPELINE_BENCH=1 to run it.
func TestRaftReplicationThroughput(t *testing.T) {
	if os.Getenv("CDSHA_PIPELINE_BENCH") == "" {
		t.Skip("set CDSHA_PIPELINE_BENCH=1")
	}
	for _, rtt := range []time.Duration{0, 100 * time.Millisecond} {
		for _, inflight := range []int{1, 2} {
			w, p99 := raftThroughput(t, rtt/2, inflight, 64, 4*time.Second)
			t.Logf("rtt %s MaxRPCsInFlight %d: %.0f writes/s, p99 commit %s", rtt, inflight, w, p99)
		}
	}
}

func raftThroughput(t *testing.T, half time.Duration, inflight, writers int, d time.Duration) (float64, time.Duration) {
	var rafts []*raft.Raft
	var servers []raft.Server
	for i := range 3 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cfg := raftTransportConfig(&delayStream{Listener: l, delay: half}, hclog.NewNullLogger())
		cfg.MaxRPCsInFlight = inflight
		trans := raft.NewNetworkTransportWithConfig(cfg)
		rc := raft.DefaultConfig()
		rc.LocalID = raft.ServerID(fmt.Sprint(i))
		rc.Logger = hclog.NewNullLogger()
		rc.HeartbeatTimeout, rc.ElectionTimeout, rc.LeaderLeaseTimeout = time.Second, time.Second, 500*time.Millisecond
		store := raft.NewInmemStore()
		r, err := raft.NewRaft(rc, nopFSM{}, store, store, raft.NewInmemSnapshotStore(), trans)
		if err != nil {
			t.Fatal(err)
		}
		rafts = append(rafts, r)
		servers = append(servers, raft.Server{ID: rc.LocalID, Address: trans.LocalAddr()})
	}
	defer func() {
		for _, r := range rafts {
			_ = r.Shutdown().Error()
		}
	}()
	if err := rafts[0].BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil {
		t.Fatal(err)
	}
	var leader *raft.Raft
	eventually(t, 20*time.Second, "a leader", func() bool {
		for _, r := range rafts {
			if r.State() == raft.Leader {
				leader = r
				return true
			}
		}
		return false
	})
	var mu sync.Mutex
	var lat []time.Duration
	stop := time.Now().Add(d)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				start := time.Now()
				if leader.Apply(make([]byte, 256), 10*time.Second).Error() != nil {
					continue
				}
				mu.Lock()
				lat = append(lat, time.Since(start))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	slices.Sort(lat)
	if len(lat) == 0 {
		t.Fatal("no write committed")
	}
	return float64(len(lat)) / d.Seconds(), lat[len(lat)*99/100]
}
