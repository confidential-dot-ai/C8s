package cdsha

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// DecreeSource is where operator decrees arrive (Kubernetes objects). Its
// contents are untrusted: every decree is checked against the operator key.
type DecreeSource interface {
	PendingDecrees(ctx context.Context) ([]PendingDecree, error)
	SetDecreeStatus(ctx context.Context, name string, st DecreeStatus) error
}

// BackupSink stores sealed backups (Kubernetes objects); they open only
// with the operator's offline recovery key.
type BackupSink interface {
	PutBackup(ctx context.Context, b Backup) error
}

// Timing are the replica timers.
type Timing struct {
	// Heartbeat and Election are Raft's heartbeat and election timeouts.
	Heartbeat time.Duration
	Election  time.Duration
	// Lease bounds the age of quorum-confirmed, locally applied read state.
	// Past it, a replica stops issuing and releasing,
	// so it cannot keep admitting what a decree just evicted.
	Lease time.Duration
	// DeadAfter is how long a member fails heartbeats before the leader
	// removes it and frees its seat.
	DeadAfter time.Duration
	// Stabilize is how long a non-voter must stay healthy before it is
	// promoted into a free seat.
	Stabilize time.Duration
	// Apply bounds one replicated write.
	Apply time.Duration
	// Tick is the period of the membership and decree loop.
	Tick time.Duration
	// Backup is how often the leader writes a sealed state backup, when the
	// state changed since the last one.
	Backup time.Duration
}

// DefaultTiming suits replicas on one site.
var DefaultTiming = Timing{
	Heartbeat: time.Second, Election: time.Second, Lease: 5 * time.Second,
	DeadAfter: 20 * time.Second, Stabilize: 3 * time.Second, Apply: 10 * time.Second, Tick: time.Second,
	Backup: time.Minute,
}

// Config configures a replica.
type Config struct {
	ClusterID string
	NodeName  string // the node this replica runs on: its seat identity
	Bind      string // peer listener, e.g. ":9443"
	Advertise string // ip:port peers dial
	Attestor  Attestor
	// BakedPins are the measurements this replica's launch configuration
	// pins; the Genesis replica makes them the first pin set.
	BakedPins      []string
	OperatorPubKey []byte // PKIX DER
	// Seats is the voter count, from the signed launch configuration. More
	// replicas than seats join as non-voters: they serve reads, issuance and
	// release, and take a seat when one frees up.
	Seats        int
	MaxNonVoters int
	Peers        func(ctx context.Context) ([]string, error) // other replicas' ip:port
	Decrees      DecreeSource
	// RecoveryKey (PKIX DER, P-256) and Backups enable sealed backups: the
	// leader seals the state to the operator's recovery key and stores it
	// with Backups. Without them there is no recovery from total loss.
	RecoveryKey  []byte
	Backups      BackupSink
	Timing       Timing
	CACommonName string
	CAValidity   time.Duration

	Allowlist *allowlist.Store
	Secrets   *secrets.MemoryStore
	Ledger    *sandboxledger.Ledger
	Logger    *slog.Logger

	// Format overrides the newest encoding format this replica reads (0:
	// the package's Format). Tests use it to run an older release.
	Format uint32

	// HistoryVersions bounds the allowlist history the cluster keeps: the
	// leader prunes it to the newest HistoryVersions entries through the
	// log. 0 keeps every entry.
	HistoryVersions int
	// HistoryBytes, if set, also bounds the history by the size of the
	// documents it keeps: a large allowlist document makes a version count
	// alone fill the store.
	HistoryBytes int64
}

// Node is one CDS replica.
type Node struct {
	// Lock order: eligibilityMu -> membershipMu -> stopRaftMu. Never hold mu
	// across blocking network/Raft waits or observer join. Membership decisions and
	// generation replacement share membershipMu; observer bookkeeping does not.
	eligibilityMu sync.Mutex         // serialize fresh-node join/bootstrap and Restore
	membershipMu  sync.Mutex         // serialize local configuration decisions and replacement
	observer      *heartbeatObserver // protected by stopRaftMu
	cfg           Config
	id            raft.ServerID
	fsm           *FSM
	rft           atomic.Pointer[raft.Raft]
	mux           atomic.Pointer[mux] // replaced by a recovery
	rcfg          *raft.Config
	logs          *memLog
	stable        *raft.InmemStore
	snaps         *snapStore
	noLeader      time.Time    // since when a member has seen no leader
	lastMember    atomic.Int64 // Unix ms a reachable peer last reported membership (or this start)
	lastLoner     atomic.Int64 // Unix ms a reachable peer last answered that it holds no cluster either
	joinLogged    bool
	cert          atomic.Pointer[tls.Certificate] // the peer certificate; renewPeerCert replaces it
	tls           *tls.Config
	verifier      peerVerifier
	measurement   string
	log           *slog.Logger

	jumpAt        atomic.Int64 // Unix ms of the last clock jump not yet cleared by fresh contact
	readCert      atomic.Pointer[readCertificate]
	barrierGate   chan struct{}             // one pending Barrier, including timed-out callers
	stoppingReads atomic.Pointer[raft.Raft] // admission closes before draining this instance
	stopRaftMu    sync.Mutex                // serialize shutdowns, including stale instance callers

	shutdownPending *pendingShutdown // protected by stopRaftMu

	seatsOKAt atomic.Pointer[time.Time] // monotonic time of the last full-seat report (non-voters)

	readOK    atomic.Pointer[barrierMark] // leader: the last read barrier that succeeded
	barrierMS atomic.Int64                // leader: how long the last successful read barrier took
	slow      slowLeader                  // leader: slow-leader check state; protected by mu

	// blocked, in tests only, refuses connections to and from addresses as a
	// network partition would.
	blocked func(addr string) bool

	mu       sync.Mutex
	failing  map[raft.ServerID]time.Time // leader: when a member's heartbeats started failing
	joinedAt map[raft.ServerID]time.Time // leader: when a member was added
	addedAt  map[raft.ServerID]time.Time // leader: when this leader added a member (handleJoin)
	reads    map[raft.ServerID]uint32    // leader: the newest format each member reads

	joinRefusedLog *cache.LRUExpireCache // peer + reason
	retireLog      *cache.LRUExpireCache // retiring voter + what it waits for
	retiring       []raft.ServerID       // leader: voters waiting to retire (reconcile); protected by mu

	backupAt    time.Time    // leader: last backup attempt
	pruneAt     time.Time    // leader: last history prune check
	prunes      atomic.Int64 // history prune entries this replica proposed (for tests)
	renewAt     time.Time    // leader: last mesh CA renewal attempt
	backupIndex uint64       // leader: applied index of the last stored backup
	// backupFails counts consecutive backups that failed on a size bound;
	// the next waits backupDelay. backupErr is the last one, for Status.
	backupFails int
	backupSince time.Time
	backupErr   atomic.Pointer[string]
	recovery    *ecdsa.PublicKey
}

// snapshotInterval is Raft's snapshot check period; a var so tests can
// shorten it.
var snapshotInterval = 30 * time.Second

// Status is a replica's view, served at /ha/status.
type Status struct {
	ClusterID     string   `json:"cluster_id"`
	NodeName      string   `json:"node_name"`
	ID            string   `json:"id"`
	State         string   `json:"state"`
	Leader        string   `json:"leader,omitempty"`
	Serving       bool     `json:"serving"`
	Joined        bool     `json:"joined"`
	Epoch         uint64   `json:"epoch"`
	CAFingerprint string   `json:"ca_fingerprint,omitempty"`
	Measurement   string   `json:"measurement"`
	Voters        []string `json:"voters,omitempty"`
	NonVoters     []string `json:"non_voters,omitempty"`
	AppliedIndex  uint64   `json:"applied_index"`
	LastContactMS int64    `json:"last_contact_ms,omitempty"`
	// SeatsFilled (leader only): every voter seat is held by a member whose
	// heartbeats succeed. Seats is the voter seat count in force.
	SeatsFilled bool `json:"seats_filled,omitempty"`
	Seats       int  `json:"seats,omitempty"`
	// RetiringVoters (leader): dead or replaced voters that keep their vote
	// until their replacement is a voter that every staying voter reports.
	RetiringVoters []string `json:"retiring_voters,omitempty"`
	// Format is the cluster's agreed encoding format; Reads the newest this
	// replica reads. Stuck says why it stopped following the log.
	Format uint32 `json:"format,omitempty"`
	Reads  uint32 `json:"reads,omitempty"`
	Stuck  string `json:"stuck,omitempty"`
	// Term is this replica's current Raft term: election churn shows as it
	// climbing.
	Term uint64 `json:"term,omitempty"`
	// ApplyLag is how far this replica's applied index trails the commit
	// index it knows (read barriers in flight count too); ReadBarrierMS
	// (leader) is how long its last successful read barrier took.
	ApplyLag      uint64 `json:"apply_lag,omitempty"`
	ReadBarrierMS int64  `json:"read_barrier_ms,omitempty"`

	// BackupError (leader) says backups are failing because the state is
	// over a snapshot size bound: no backup is stored until it shrinks.
	BackupError string `json:"backup_error,omitempty"`
	// LogEntries and LogBytes are the in-memory Raft log: entries kept
	// until a snapshot compacts them, and the bytes they hold.
	LogEntries uint64 `json:"log_entries,omitempty"`
	LogBytes   int64  `json:"log_bytes,omitempty"`
	// SnapshotIndex, SnapshotBytes and SnapshotAtMS are the latest Raft
	// snapshot this replica holds (taken or installed).
	SnapshotIndex uint64 `json:"snapshot_index,omitempty"`
	SnapshotBytes int64  `json:"snapshot_bytes,omitempty"`
	SnapshotAtMS  int64  `json:"snapshot_at_ms,omitempty"`
}

// NewNode prepares a replica. Every start is a new Raft member: the log
// lives in memory, so a restarted replica has forgotten its votes and must
// not vote under its old identity. The leader replaces the old member.
func NewNode(cfg Config) (*Node, error) {
	switch {
	case cfg.ClusterID == "" || cfg.NodeName == "":
		return nil, errors.New("cds-ha: cluster id and node name are required")
	case cfg.Seats < 1:
		return nil, errors.New("cds-ha: at least one seat")
	case cfg.Attestor == nil || cfg.Allowlist == nil || cfg.Secrets == nil || cfg.Ledger == nil:
		return nil, errors.New("cds-ha: attestor and stores are required")
	case strings.Contains(cfg.NodeName, "/"):
		return nil, errors.New("cds-ha: node name must not contain '/'")
	}
	t, def := &cfg.Timing, DefaultTiming
	for _, f := range [][2]*time.Duration{{&t.Heartbeat, &def.Heartbeat}, {&t.Election, &def.Election},
		{&t.Lease, &def.Lease}, {&t.DeadAfter, &def.DeadAfter}, {&t.Stabilize, &def.Stabilize},
		{&t.Apply, &def.Apply}, {&t.Tick, &def.Tick}, {&t.Backup, &def.Backup}} {
		if *f[0] <= 0 {
			*f[0] = *f[1]
		}
	}
	cfg.Logger = cmp.Or(cfg.Logger, slog.Default())
	cfg.CACommonName = cmp.Or(cfg.CACommonName, issuer.DefaultCACommonName)
	if cfg.CAValidity <= 0 {
		cfg.CAValidity = issuer.DefaultCAValidity
	}
	ev, err := cfg.Attestor.Evidence([48]byte{})
	if err != nil {
		return nil, fmt.Errorf("own evidence: %w", err)
	}
	own, err := cfg.Attestor.Verify(ev) // our measurement and launch-key anchor
	if err != nil {
		return nil, fmt.Errorf("own evidence does not verify: %w", err)
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	n := &Node{
		cfg:            cfg,
		barrierGate:    make(chan struct{}, 1),
		id:             raft.ServerID(cfg.NodeName + "/" + strconv.FormatInt(time.Now().UnixMilli(), 10) + "-" + hex.EncodeToString(rnd[:])),
		measurement:    own.Measurement,
		log:            cfg.Logger.With("component", "cds-ha"),
		failing:        map[raft.ServerID]time.Time{},
		joinedAt:       map[raft.ServerID]time.Time{},
		addedAt:        map[raft.ServerID]time.Time{},
		reads:          map[raft.ServerID]uint32{},
		joinRefusedLog: newLogOnce(),
		retireLog:      newLogOnce(),
	}
	if len(cfg.RecoveryKey) > 0 {
		k, err := x509.ParsePKIXPublicKey(cfg.RecoveryKey)
		pub, ok := k.(*ecdsa.PublicKey)
		if err != nil || !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("cds-ha: recovery key must be an ECDSA P-256 public key")
		}
		n.recovery = pub
	}
	n.fsm = NewFSM(PreGenesis(cfg.ClusterID, cfg.OperatorPubKey), cfg.Allowlist, cfg.Secrets, cfg.Ledger)
	if cfg.Format != 0 {
		n.fsm.readable = cfg.Format
	}
	n.lastMember.Store(time.Now().UnixMilli())
	cert, err := newPeerCert(cfg.ClusterID, cfg.Attestor, time.Now().Add(peerCertLife))
	if err != nil {
		return nil, err
	}
	n.cert.Store(&cert)
	n.verifier = peerVerifier{clusterID: cfg.ClusterID, att: cfg.Attestor, anchor: own.Anchor, pins: n.peerPins}
	n.tls = peerTLSConfig(n.cert.Load)
	return n, nil
}

// peerCertLife is how long a peer certificate lasts; renewPeerCert
// replaces it after a quarter of that.
const peerCertLife = 24 * time.Hour

// renewPeerCert replaces an aging peer certificate with fresh evidence over
// a new key. A failure is retried on the next tick.
func (n *Node) renewPeerCert() {
	if time.Since(n.cert.Load().Leaf.NotBefore) < peerCertLife/4 {
		return
	}
	c, err := newPeerCert(n.cfg.ClusterID, n.cfg.Attestor, time.Now().Add(peerCertLife))
	if err != nil {
		n.log.Warn("renew peer certificate", "err", err)
		return
	}
	n.cert.Store(&c)
}

// peerPins is the pin set peers are checked against: the agreed one once
// the cluster exists. Before that (a replica that has not joined yet) any
// measurement passes the TLS layer with our launch-key anchor; what a
// joiner then accepts is decided by the leader of a real majority.
func (n *Node) peerPins() []string {
	c := n.fsm.Core()
	if !c.Joined() {
		return nil
	}
	return c.Measurements
}

// r is the current Raft instance (replaced by a recovery).
func (n *Node) r() *raft.Raft { return n.rft.Load() }

// solo is the one-voter configuration of this member.
func (n *Node) solo() raft.Configuration {
	return raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: n.id, Address: n.raftAddress()}}}
}

// raftAddress is where peers reach this member's Raft, with its member ID.
func (n *Node) raftAddress() raft.ServerAddress {
	return raft.ServerAddress(n.cfg.Advertise + "#" + string(n.id))
}

// ID is this replica's Raft member ID.
func (n *Node) ID() string { return string(n.id) }

// Start opens the peer port and starts Raft. Run drives it.
func (n *Node) Start() error {
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	n.logs, n.stable, n.snaps = newMemLog(), raft.NewInmemStore(), &snapStore{}
	rc := raft.DefaultConfig()
	rc.LocalID = n.id
	rc.HeartbeatTimeout = n.cfg.Timing.Heartbeat
	rc.ElectionTimeout = n.cfg.Timing.Election
	rc.LeaderLeaseTimeout = n.cfg.Timing.Heartbeat / 2
	rc.CommitTimeout = 20 * time.Millisecond
	rc.SnapshotThreshold = 512
	rc.TrailingLogs = 256
	// The log is in memory until a snapshot compacts it, and Raft checks
	// the threshold only every SnapshotInterval (a random 1-2x of it). The
	// leader also compacts at each backup; a follower only here. At Raft's
	// default 120 s a follower under large-document writes held over 2,500
	// entries (190 MiB) between checks; 30 s keeps it to about
	// threshold + trailing + rate x 60 s. Snapshots still need 512 new
	// entries, so an idle cluster takes none.
	rc.SnapshotInterval = snapshotInterval
	rc.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Info, DisableTime: true,
		Output: slog.NewLogLogger(n.log.Handler(), slog.LevelWarn).Writer(), Exclude: raftQuiet})
	n.rcfg = rc
	return n.startRaft()
}

// raftSnapshotInfo are the Raft info lines kept: a snapshot sent to or
// installed on a replica replaces its state, which an operator must be able
// to see. Raft's other info lines stay out of the log.
var raftSnapshotInfo = []string{"installing snapshot on", "copied to local snapshot", "Installed remote snapshot", "restored user snapshot"}

func raftQuiet(level hclog.Level, msg string, _ ...any) bool {
	return level < hclog.Warn && !slices.Contains(raftSnapshotInfo, msg)
}

// startRaft opens the transport and starts Raft on the node's stores.
func (n *Node) startRaft() error {
	n.stopRaftMu.Lock()
	defer n.stopRaftMu.Unlock()
	trans, err := n.transport()
	if err != nil {
		return err
	}
	r, err := raft.NewRaft(n.rcfg, n.fsm, n.logs, n.stable, n.snaps, trans)
	if err != nil {
		_ = trans.Close()
		return err
	}
	n.rft.Store(r)
	obs := make(chan raft.Observation, 256)
	observer := raft.NewObserver(obs, false, func(o *raft.Observation) bool {
		switch o.Data.(type) {
		case raft.FailedHeartbeatObservation, raft.ResumedHeartbeatObservation:
			return true
		}
		return false
	})
	ctx, cancel := context.WithCancel(context.Background())
	worker := &heartbeatObserver{raft: r, observer: observer, cancel: cancel, done: make(chan struct{})}
	n.observer = worker
	r.RegisterObserver(observer)
	go func() { defer close(worker.done); n.observe(ctx, r, obs) }()
	return nil
}

func (n *Node) transport() (*raft.NetworkTransport, error) {
	m, err := newMux(n.cfg.Bind, n.cfg.Advertise, string(n.id), n.tls, n.verifier, n.handleControl, n.blocked)
	if err != nil {
		return nil, err
	}
	n.mux.Store(m)
	return raft.NewNetworkTransportWithConfig(raftTransportConfig(m, n.rcfg.Logger)), nil
}

// raftTransportConfig is the peer transport's configuration. Pipelining is
// off (MaxRPCsInFlight 1, Raft's documented switch: AppendEntriesPipeline
// then reports ErrPipelineReplicationNotSupported and replication sends one
// AppendEntries at a time). Raft v1.8's pipeline deadlocks once a follower
// stops answering: its response decoder quits on the first failure while the
// transport still hands it results, the sender then waits on the transport
// forever, and Raft can never shut down.
func raftTransportConfig(stream raft.StreamLayer, logger hclog.Logger) *raft.NetworkTransportConfig {
	return &raft.NetworkTransportConfig{Stream: stream, MaxPool: 3, Timeout: 10 * time.Second, Logger: logger, MaxRPCsInFlight: 1}
}

// Run drives the replica until ctx ends: join or bootstrap, then as leader
// keep the seats filled and apply decrees.
func (n *Node) Run(ctx context.Context) error {
	if n.r() == nil {
		if err := n.Start(); err != nil {
			return err
		}
	}
	defer n.shutdown()
	workerCtx, stopWorkers := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); n.watchClock(workerCtx) }()
	go func() { defer workers.Done(); n.refreshReads(workerCtx) }()
	go func() { defer workers.Done(); n.watchSlowLeader(workerCtx) }()
	// Stop and join read/clock/slow-leader workers before shutdown and caller store close.
	defer func() { stopWorkers(); workers.Wait() }()
	t := time.NewTicker(n.cfg.Timing.Tick)
	defer t.Stop()
	var lastEpoch uint64
	var stuckAt time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if reason := n.fsm.Stuck(); reason != "" {
			// A stuck replica serves nothing, and only a restart, which
			// replays the log from the cluster, brings it back. A transient
			// fault (a disk that filled and was freed, descriptors exhausted
			// for a moment) must not take it out for good, and its peer
			// port stays open, so no TCP liveness check notices. A leader
			// first hands off leadership (reconcile); return once it has,
			// or after DeadAfter, so the process exits and is restarted.
			if stuckAt.IsZero() {
				stuckAt = time.Now()
			}
			if since := time.Since(stuckAt); (!n.leading() && since >= n.cfg.Timing.Lease) || since >= n.cfg.Timing.DeadAfter {
				return fmt.Errorf("%w: %s", ErrStuck, reason)
			}
		}
		n.renewPeerCert()
		if !n.member() {
			n.joinOrBootstrap(ctx)
			continue
		}
		if e := n.fsm.Core().Epoch; e != lastEpoch {
			lastEpoch = e
			n.mux.Load().recheck() // the pin set may have changed
		}
		switch addr, _ := n.r().LeaderWithID(); {
		case n.leading():
			n.noLeader = time.Time{}
			n.reconcile()
			n.applyDecrees(ctx)
			n.maybeBackup(ctx)
			n.maybePruneHistory()
			n.maybeRenewCA()
		case addr != "":
			n.noLeader = time.Time{}
			n.refreshSeats()
		case n.noLeader.IsZero():
			n.noLeader = time.Now()
		case time.Since(n.noLeader) > n.cfg.Timing.DeadAfter:
			// No majority for a while: an operator Recover decree naming us
			// makes us the only voter; otherwise the cluster may have been
			// recovered around us, so ask to be added again.
			if p, ok := n.pendingDecree(ctx, Recover); ok {
				n.recover(ctx, p)
				n.noLeader = time.Time{}
			} else {
				n.rejoin(ctx)
			}
		}
	}
}

// stopRaft drains the one genuine read future while Raft can still resolve it.
// Raft v1.8 Barrier futures have no shutdown channel; shutting down first can
// strand a committed future in the FSM queue. Keep the gate through shutdown.
// As with Raft shutdown itself, a permanently blocked FSM must be released.
func (n *Node) stopRaft(r *raft.Raft) error {
	if r == nil {
		return nil
	}
	n.stopRaftMu.Lock()
	defer n.stopRaftMu.Unlock()
	if r == n.r() {
		n.stoppingReads.Store(r)
		n.readCert.Store(nil)
	}
	n.barrierGate <- struct{}{}
	defer func() { <-n.barrierGate }()
	// Never close the observation channel: Raft owns sends. Deregister,
	// cancel and join before stores or generation bookkeeping can be retired.
	if worker := n.observer; worker != nil && worker.raft == r {
		r.DeregisterObserver(worker.observer)
		worker.cancel()
		<-worker.done
		n.observer = nil
	}
	return n.awaitShutdown(r)
}

// errShutdownTimeout: Raft did not shut down within Timing.Apply; its
// goroutines may still run. Nothing may start a new Raft generation over it.
var errShutdownTimeout = errors.New("cds-ha: raft did not shut down in time")

// pendingShutdown is a Raft instance's shutdown, which may outlive one wait.
type pendingShutdown struct {
	raft *raft.Raft
	done chan struct{}
	err  error
}

// awaitShutdown shuts r down and waits for it, at most Timing.Apply, so a
// Raft goroutine that never returns cannot keep the process from exiting.
// Callers hold stopRaftMu. A later call for the same instance waits on the
// same shutdown again: Raft answers a second Shutdown at once, whether or
// not the first finished.
func (n *Node) awaitShutdown(r *raft.Raft) error {
	p := n.shutdownPending
	if p == nil || p.raft != r {
		p = &pendingShutdown{raft: r, done: make(chan struct{})}
		n.shutdownPending = p
		go func() { p.err = r.Shutdown().Error(); close(p.done) }()
	}
	t := time.NewTimer(n.cfg.Timing.Apply)
	defer t.Stop()
	select {
	case <-p.done:
		return p.err
	case <-t.C:
		n.log.Error("raft did not shut down; its goroutines are left running", "waited", n.cfg.Timing.Apply)
		return errShutdownTimeout
	}
}

func (n *Node) shutdown() {
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	if r := n.r(); r != nil {
		_ = n.stopRaft(r)
	}
	if m := n.mux.Load(); m != nil {
		_ = m.Close()
	}
}

func (n *Node) call(addr string, timeout time.Duration, req controlRequest) (controlResponse, error) {
	if n.blocked != nil && n.blocked(addr) {
		return controlResponse{}, errors.New("partitioned")
	}
	var local net.Addr
	if m := n.mux.Load(); m != nil {
		local = m.advert.tcp
	}
	return callControl(addr, n.tls, n.verifier, timeout, req, local)
}

// handleControl answers a control request from an attested peer.
func (n *Node) handleControl(peer Claims, req controlRequest) controlResponse {
	member := n.member()
	switch req.Op {
	case ctlStatus:
		st := n.Status()
		return controlResponse{Member: member, Status: &st}
	case ctlJoin, ctlApply, ctlReadBarrier:
	default:
		return controlResponse{Err: "unknown control op"}
	}
	if !n.leading() {
		if hp := n.leaderHostPort(); hp != "" {
			return controlResponse{Member: member, Leader: hp, Err: "not the leader"}
		}
		return controlResponse{Member: member, Err: "no leader"}
	}
	core := n.fsm.Core()
	if !core.Joined() {
		return controlResponse{Member: true, Err: "cluster has no mesh CA yet"}
	}
	if !core.Pins(peer.Measurement) {
		// TLS already checks this; the join is where it matters most.
		return controlResponse{Member: true, Err: "peer measurement is not pinned"}
	}
	if req.Op == ctlReadBarrier {
		idx, err := n.readBarrier(n.r(), min(n.cfg.Timing.Apply, n.cfg.Timing.Lease))
		if err != nil {
			return controlResponse{Member: true, Err: err.Error()}
		}
		return controlResponse{Member: true, Index: idx}
	}
	if req.Op == ctlJoin {
		return n.handleJoin(req)
	}
	// The forwarding replica checked the cap against its own copy; the
	// leader's check is the one that holds for every proposer.
	if err := n.fsm.admitRaw(req.Entry); err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	idx, resp, err := n.applyLocal(req.Entry)
	var body json.RawMessage
	if err == nil {
		body, err = json.Marshal(resp)
	}
	if err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	return controlResponse{Member: true, Index: idx, Response: body}
}

// applyEntry commits e through this replica, which must lead, and returns
// the FSM's answer.
func (n *Node) applyEntry(e Entry) (any, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	_, resp, err := n.applyLocal(raw)
	return resp, err
}

// applyLocal commits raw through this replica, which must lead.
func (n *Node) applyLocal(raw json.RawMessage) (uint64, any, error) {
	f := n.r().Apply(raw, n.cfg.Timing.Apply)
	if err := f.Error(); err != nil {
		return 0, nil, err
	}
	resp := f.Response()
	if err, ok := resp.(error); ok {
		return 0, nil, err
	}
	return f.Index(), resp, nil
}

// propose commits an entry through the leader, wherever it is, and returns
// once this replica has applied it too, so its own reads see the write.
func (n *Node) propose(e Entry) (json.RawMessage, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if !n.fsm.Core().Joined() {
		return nil, errors.New("cds-ha: this replica has not joined the cluster")
	}
	if err := n.fsm.admit(e, len(raw), n.leading()); err != nil {
		return nil, err
	}
	if n.leading() {
		_, resp, err := n.applyLocal(raw)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)
	}
	hp := n.leaderHostPort()
	if hp == "" {
		return nil, errors.New("cds-ha: no leader (fewer than a majority of replicas reachable)")
	}
	resp, err := n.call(hp, n.cfg.Timing.Apply, controlRequest{Op: ctlApply, Entry: raw})
	if err != nil {
		return nil, err
	}
	if resp.Err != "" {
		if err := capacityErr(resp.Err); err != nil {
			return nil, err
		}
		return nil, errors.New("cds-ha: " + resp.Err)
	}
	if !n.waitFor(n.cfg.Timing.Apply, func() bool { return n.fsm.AppliedIndex() >= resp.Index }) {
		return nil, errors.New("cds-ha: write committed but not yet applied here")
	}
	return resp.Response, nil
}

// CheckCapacity refuses (ErrCapacity) while the replicated state is at the
// admission cap, so a handler can refuse a write that would grow it before
// spending its token: a spent token is a replicated row too. secret says
// the write would grow the secrets (the snapshot header) rather than the
// allowlist. It is the cap propose applies, for a write of no size.
func (n *Node) CheckCapacity(secret bool) error {
	return n.fsm.capacity(secret, 0, n.r() != nil && n.leading())
}

// replicate proposes e and decodes the FSM's answer. A failed proposal
// wraps unavailable, if set, so the store reports the cluster unavailable;
// one refused by the admission cap wraps full instead (a write the cluster
// will not take, not one it could not commit).
func replicate[R any](n *Node, e Entry, unavailable, full error) (R, error) {
	var res R
	raw, err := n.propose(e)
	if err != nil {
		if errors.Is(err, ErrCapacity) {
			if full != nil {
				err = fmt.Errorf("%w: %w", full, err)
			}
			return res, err
		}
		if unavailable != nil {
			err = fmt.Errorf("%w: %w", unavailable, err)
		}
		return res, err
	}
	return res, json.Unmarshal(raw, &res)
}

// Replicate implements allowlist.Replicator.
func (n *Node) Replicate(cmd allowlist.Command) (allowlist.Result, error) {
	return replicate[allowlist.Result](n, Entry{Kind: KindAllowlist, Allowlist: &cmd}, allowlist.ErrUnavailable, allowlist.ErrCapacity)
}

// ReplicateSecret implements secrets.Replicator.
func (n *Node) ReplicateSecret(cmd secrets.Command) (secrets.Result, error) {
	return replicate[secrets.Result](n, Entry{Kind: KindSecret, Secret: &cmd}, secrets.ErrUnavailable, secrets.ErrCapacity)
}

// ReplicateBinding implements sandboxledger.Replicator.
func (n *Node) ReplicateBinding(cmd sandboxledger.Command) (bool, error) {
	return replicate[bool](n, Entry{Kind: KindBinding, Binding: &cmd}, nil, nil)
}

// readCertificate is a quorum-confirmed watermark applied on this replica.
// at is the request start, not completion: network/apply delay cannot extend it.
const ctlReadBarrier = "read_barrier"

type readCertificate struct {
	raft     *raft.Raft
	leader   raft.ServerAddress
	leaderID raft.ServerID
	term     uint64
	epoch    uint64
	at       time.Time
	index    uint64
}

func (n *Node) validReadCertificate(cert *readCertificate) bool {
	if cert == nil || cert.raft != n.r() || n.stoppingReads.Load() == cert.raft || time.Since(cert.at) >= n.cfg.Timing.Lease {
		return false
	}
	leader, id := cert.raft.LeaderWithID()
	return leader != "" && leader == cert.leader && id == cert.leaderID && cert.raft.CurrentTerm() == cert.term && n.fsm.Core().Epoch == cert.epoch
}

// readBarrier confirms a quorum and waits for the leader's FSM to apply all
// preceding commands. Raft's Barrier timeout only bounds enqueueing, so also
// bound the wait for completion.
func (n *Node) readBarrier(r *raft.Raft, timeout time.Duration) (uint64, error) {
	if r == nil || r != n.r() || n.stoppingReads.Load() == r {
		return 0, errors.New("cds-ha: read instance stopping or replaced")
	}
	start := time.Now()
	deadline := start.Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	// Keep the token until the Raft future actually completes, not merely
	// until this caller times out. A stalled FSM cannot accumulate waiters.
	select {
	case n.barrierGate <- struct{}{}:
	case <-timer.C:
		return 0, errors.New("cds-ha: read barrier busy")
	}
	if r != n.r() || n.stoppingReads.Load() == r {
		<-n.barrierGate
		return 0, errors.New("cds-ha: read instance stopping or replaced")
	}
	type result struct {
		index uint64
		err   error
	}
	done := make(chan result, 1)
	term := r.CurrentTerm()
	leader, id := r.LeaderWithID()
	go func() {
		defer func() { <-n.barrierGate }()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			done <- result{err: errors.New("cds-ha: read barrier timed out")}
			return
		}
		err := r.Barrier(remaining).Error()
		currentLeader, currentID := r.LeaderWithID()
		if err == nil && (r != n.r() || n.stoppingReads.Load() == r || r.State() != raft.Leader || r.CurrentTerm() != term || currentLeader != leader || currentID != id || n.fsm.Stuck() != "") {
			err = errors.New("cds-ha: read leader or state changed")
		}
		if err == nil {
			// Certificates from this barrier date from before start.
			n.readOK.Store(&barrierMark{raft: r, term: term, start: start})
			n.barrierMS.Store(time.Since(start).Milliseconds())
		}
		done <- result{index: n.fsm.AppliedIndex(), err: err}
	}()
	select {
	case res := <-done:
		return res.index, res.err
	case <-timer.C:
		return 0, errors.New("cds-ha: read barrier timed out")
	}
}

func (n *Node) confirmRead(timeout time.Duration) (*readCertificate, error) {
	at, r := time.Now(), n.r()
	if r == nil || !n.fsm.Core().Joined() {
		return nil, errors.New("cds-ha: not joined")
	}
	leader, leaderID := r.LeaderWithID()
	epoch, term := n.fsm.Core().Epoch, r.CurrentTerm()
	var index uint64
	if r.State() == raft.Leader {
		var err error
		index, err = n.readBarrier(r, timeout)
		if err != nil {
			return nil, err
		}
	} else {
		hp := n.leaderHostPort()
		if hp == "" {
			return nil, errors.New("cds-ha: no leader")
		}
		resp, err := n.call(hp, timeout, controlRequest{Op: ctlReadBarrier})
		if err != nil {
			return nil, err
		}
		if resp.Err != "" {
			return nil, errors.New("cds-ha: " + resp.Err)
		}
		if resp.Index == 0 {
			return nil, errors.New("cds-ha: missing read watermark")
		}
		index = resp.Index
	}
	remaining := timeout - time.Since(at)
	if remaining <= 0 || !n.waitFor(remaining, func() bool { return n.fsm.AppliedIndex() >= index }) {
		return nil, errors.New("cds-ha: not caught up with quorum watermark")
	}
	if n.r() != r || n.stoppingReads.Load() == r || n.fsm.Stuck() != "" {
		return nil, errors.New("cds-ha: read state changed or stuck")
	}
	cert := &readCertificate{raft: r, leader: leader, leaderID: leaderID, epoch: epoch, term: term, at: at, index: index}
	currentLeader, currentID := r.LeaderWithID()
	if leader == "" || currentLeader != leader || currentID != leaderID || r.CurrentTerm() != term || n.fsm.Core().Epoch != epoch {
		return nil, errors.New("cds-ha: read leader or epoch changed")
	}
	return cert, nil
}

// CatchUp always obtains a new quorum barrier, including on the leader.
func (n *Node) CatchUp() error {
	_, err := n.confirmRead(n.cfg.Timing.Apply)
	return err
}

// refreshReads runs independently of membership and status handling. Serving
// never makes a network call, and a failed refresh cannot renew an old lease.
func (n *Node) refreshReads(ctx context.Context) {
	var down readOutage
	period := min(n.cfg.Timing.Tick, n.cfg.Timing.Lease/3)
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cert := n.readCert.Load()
		if n.validReadCertificate(cert) && time.Since(cert.at) < n.cfg.Timing.Lease/3 && n.jumpAt.Load() == 0 {
			continue
		}
		jump := n.jumpAt.Load()
		fresh, err := n.confirmRead(min(n.cfg.Timing.Apply, n.cfg.Timing.Lease))
		if err != nil {
			n.readCert.Store(nil)
			down.failed(n.log, err)
			continue
		}
		down.renewed(n.log)
		// A barrier started after the observed jump proves state freshness.
		n.readCert.Store(fresh)
		if fresh.at.UnixMilli() > jump {
			n.jumpAt.CompareAndSwap(jump, 0)
		}
	}
}

// readOutage reports why a replica cannot certify reads. Without it a
// replica that refuses every read says nothing about the reason: the first
// failure, a changed reason (at most every readOutageLogEvery), and the
// recovery are logged.
type readOutage struct {
	since, logged time.Time
	reason        string
}

const readOutageLogEvery = 5 * time.Second

func (o *readOutage) failed(log *slog.Logger, err error) {
	now, reason := time.Now(), err.Error()
	switch {
	case o.since.IsZero():
		o.since = now
	case reason == o.reason || now.Sub(o.logged) < readOutageLogEvery:
		return
	}
	o.reason, o.logged = reason, now
	log.Warn("cds-ha: reads not certified; not serving", "reason", reason, "for", now.Sub(o.since).Round(time.Millisecond))
}

func (o *readOutage) renewed(log *slog.Logger) {
	if o.since.IsZero() {
		return
	}
	log.Info("cds-ha: reads certified again; serving", "after", time.Since(o.since).Round(time.Millisecond))
	*o = readOutage{}
}

// Serving permits bounded-stale reads only after a quorum-confirmed watermark
// has applied locally. Independent Raft heartbeats cannot renew this lease.
func (n *Node) Serving() bool {
	core := n.fsm.Core()
	if !core.Joined() || !core.Pins(n.measurement) || n.r() == nil {
		return false
	}
	if n.jumpAt.Load() != 0 || n.fsm.Stuck() != "" {
		return false
	}
	cert := n.readCert.Load()
	return n.validReadCertificate(cert) && n.fsm.AppliedIndex() >= cert.index
}

// ErrStuck ends Run: this replica stopped following the log (see FSM.stop)
// and must be restarted to rejoin with the cluster's state.
var ErrStuck = errors.New("cds-ha: replica stopped following the log; restart to rejoin")

// StuckOverdue is the stuck reason once this replica has been stuck longer
// than Run allows (DeadAfter, plus a Lease of slack), "" otherwise. Run ends
// a stuck replica itself; a caller that watches StuckOverdue independently
// still ends a replica whose Run loop is blocked and never gets there.
func (n *Node) StuckOverdue() string {
	if d := n.fsm.stuckFor(); d > n.cfg.Timing.DeadAfter+n.cfg.Timing.Lease {
		return n.fsm.Stuck()
	}
	return ""
}

// ErrNotServing means the replica cannot currently admit a mesh CA read.
// Callers must not use a cached CA to bypass this refusal.
var ErrNotServing = errors.New("cds-ha: replica is not serving (not joined, not pinned, or not fresh)")

// CA is the mesh CA to issue with, while serving.
func (n *Node) CA() (*issuer.CA, error) {
	if !n.Serving() {
		return nil, ErrNotServing
	}
	if ca := n.fsm.CA(); ca != nil {
		return ca, nil
	}
	return nil, errors.New("cds-ha: no mesh CA")
}

// Core is the agreed cluster state.
func (n *Node) Core() Core { return n.fsm.Core() }

// Decrees is the record of applied decrees, oldest first.
func (n *Node) Decrees() []DecreeRecord { return n.fsm.Decrees() }

// Status is this replica's view of the cluster.
func (n *Node) Status() Status {
	core := n.fsm.Core()
	st := Status{ClusterID: n.cfg.ClusterID, NodeName: n.cfg.NodeName, ID: string(n.id), Joined: core.Joined(),
		Epoch: core.Epoch, Measurement: n.measurement, AppliedIndex: n.fsm.AppliedIndex(),
		Format: core.format(), Reads: n.fsm.readable, Stuck: n.fsm.Stuck(), Seats: n.seats()}
	if p := n.backupErr.Load(); p != nil && n.r() != nil && n.leading() {
		st.BackupError = *p
	}
	if core.Joined() {
		st.CAFingerprint = certutil.CertFingerprint(core.RootCert)
	}
	if n.r() == nil {
		return st
	}
	// Set before Raft started (n.r() is published after them).
	st.LogEntries, st.LogBytes = n.logs.usage()
	st.SnapshotIndex, st.SnapshotBytes, st.SnapshotAtMS = n.snaps.latest()
	st.State = n.r().State().String()
	st.Term = n.r().CurrentTerm()
	st.Serving = n.Serving()
	if c := n.r().CommitIndex(); c > st.AppliedIndex {
		st.ApplyLag = c - st.AppliedIndex
	}
	st.Leader = n.leaderHostPort()
	if lc := n.r().LastContact(); !lc.IsZero() {
		st.LastContactMS = time.Since(lc).Milliseconds()
	}
	for _, s := range n.servers() {
		if s.Suffrage == raft.Voter {
			st.Voters = append(st.Voters, string(s.ID))
		} else {
			st.NonVoters = append(st.NonVoters, string(s.ID))
		}
	}
	if n.leading() {
		st.SeatsFilled = n.seatsFilled()
		n.mu.Lock()
		for _, id := range n.retiring {
			st.RetiringVoters = append(st.RetiringVoters, string(id))
		}
		n.mu.Unlock()
		st.ReadBarrierMS = n.barrierMS.Load()
	}
	return st
}

// Ready is readiness for a rolling restart (a DaemonSet with
// maxUnavailable 1 restarts the next replica once this one is Ready): the
// replica serves, and either holds a voter seat or the leader reports every
// seat held by a healthy voter. A restarted voter comes back as a new member
// that serves as a non-voter until it is promoted; were it Ready then, the
// next restart could take a second voter and the majority with it.
func (n *Node) Ready() bool {
	if !n.Serving() {
		return false
	}
	if n.isVoter() {
		// A seat more than the seats: a dead or replaced voter still counts
		// for the quorum until it retires, so the next restart must wait.
		return n.voterCount() <= n.seats()
	}
	if n.leading() {
		return n.seatsFilled()
	}
	at := n.seatsOKAt.Load()
	if at == nil {
		return false
	}
	age := time.Since(*at)
	return age >= 0 && age < 3*n.cfg.Timing.Tick+time.Second
}

// watchClock notices the wall clock moving apart from the monotonic one: a
// paused VM, or a host stepping the clock. Either makes "I heard from the
// leader recently" untrustworthy, so the replica stops serving until it
// hears from the leader again.
func (n *Node) watchClock(ctx context.Context) {
	const period = 200 * time.Millisecond
	t := time.NewTicker(period)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			mono := now.Sub(last)
			if wall := now.Round(0).Sub(last.Round(0)); clockJumped(wall, mono) {
				n.jumpAt.Store(now.UnixMilli())
				n.log.Warn("clock jump: not serving until the leader is heard again", "wall_minus_mono", wall-mono, "tick", mono)
			}
			last = now
		}
	}
}

// clockJumped reports a wall clock that moved more than 2 s apart from the
// monotonic one over a tick, or a tick that took over 5 s (a suspended VM).
func clockJumped(wall, mono time.Duration) bool {
	d := wall - mono
	return d > 2*time.Second || d < -2*time.Second || mono > 5*time.Second
}

func (n *Node) leading() bool { return n.r().State() == raft.Leader }

// leaderHostPort is the leader's peer address, or "" when there is none.
func (n *Node) leaderHostPort() string {
	addr, _ := n.r().LeaderWithID()
	hp, _ := splitRaftAddr(string(addr))
	return hp
}

// waitFor polls cond until it holds or timeout passes.
func (n *Node) waitFor(timeout time.Duration, cond func() bool) bool {
	return wait.PollUntilContextTimeout(context.Background(), 5*time.Millisecond, timeout, true,
		func(context.Context) (bool, error) { return cond(), nil }) == nil
}

// peerStatus asks the member at Raft address addr for its status.
func (n *Node) peerStatus(addr raft.ServerAddress, timeout time.Duration) (*Status, error) {
	hp, _ := splitRaftAddr(string(addr))
	resp, err := n.call(hp, timeout, controlRequest{Op: ctlStatus})
	if err == nil && resp.Status == nil {
		err = errors.New("cds-ha: peer sent no status")
	}
	return resp.Status, err
}

// servers is the current configuration, or nil when Raft cannot say.
func (n *Node) servers() []raft.Server {
	f := n.r().GetConfiguration()
	if f.Error() != nil {
		return nil
	}
	return f.Configuration().Servers
}
