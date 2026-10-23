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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
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
	// Lease is how long a follower keeps serving after it last heard from
	// the leader. Past it, an isolated replica stops issuing and releasing,
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
	cfg         Config
	id          raft.ServerID
	fsm         *FSM
	rft         atomic.Pointer[raft.Raft]
	mux         atomic.Pointer[mux] // replaced by a recovery
	rcfg        *raft.Config
	logs        *raft.InmemStore
	stable      *raft.InmemStore
	snaps       *snapStore
	noLeader    time.Time    // since when a member has seen no leader
	lastMember  atomic.Int64 // Unix ms a reachable peer last reported membership (or this start)
	lastLoner   atomic.Int64 // Unix ms a reachable peer last answered that it holds no cluster either
	joinLogged  bool
	certs       *certHolder
	tls         *tls.Config
	verifier    peerVerifier
	measurement string
	log         *slog.Logger

	jumpAt atomic.Int64 // Unix ms of the last clock jump not yet cleared by fresh contact

	seatsOKAt atomic.Int64 // Unix ms the leader last reported every seat filled (non-voters)

	// blocked, in tests only, refuses connections to and from addresses as a
	// network partition would.
	blocked func(addr string) bool

	mu       sync.Mutex
	failing  map[raft.ServerID]time.Time // leader: when a member's heartbeats started failing
	joinedAt map[raft.ServerID]time.Time // leader: when a member was added
	addedAt  map[raft.ServerID]time.Time // leader: when this leader added a member (handleJoin)
	reads    map[raft.ServerID]uint32    // leader: the newest format each member reads

	joinRefusedLog logEvery // peer + reason

	backupAt    time.Time // leader: last backup attempt
	pruneAt     time.Time // leader: last history prune check
	renewAt     time.Time // leader: last mesh CA renewal attempt
	backupIndex uint64    // leader: applied index of the last stored backup
	recovery    *ecdsa.PublicKey
}

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
	// Format is the cluster's agreed encoding format; Reads the newest this
	// replica reads. Stuck says why it stopped following the log.
	Format uint32 `json:"format,omitempty"`
	Reads  uint32 `json:"reads,omitempty"`
	Stuck  string `json:"stuck,omitempty"`
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
		cfg:         cfg,
		id:          raft.ServerID(cfg.NodeName + "/" + strconv.FormatInt(time.Now().UnixMilli(), 10) + "-" + hex.EncodeToString(rnd[:])),
		measurement: own.Measurement,
		log:         cfg.Logger.With("component", "cds-ha"),
		failing:     map[raft.ServerID]time.Time{},
		joinedAt:    map[raft.ServerID]time.Time{},
		addedAt:     map[raft.ServerID]time.Time{},
		reads:       map[raft.ServerID]uint32{},
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
	if n.certs, err = newCertHolder(func() (tls.Certificate, error) { return newPeerCert(cfg.ClusterID, cfg.Attestor) }); err != nil {
		return nil, err
	}
	n.verifier = peerVerifier{clusterID: cfg.ClusterID, att: cfg.Attestor, anchor: own.Anchor, pins: n.peerPins}
	n.tls = peerTLSConfig(n.certs)
	return n, nil
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
	n.logs, n.stable, n.snaps = raft.NewInmemStore(), raft.NewInmemStore(), &snapStore{}
	rc := raft.DefaultConfig()
	rc.LocalID = n.id
	rc.HeartbeatTimeout = n.cfg.Timing.Heartbeat
	rc.ElectionTimeout = n.cfg.Timing.Election
	rc.LeaderLeaseTimeout = n.cfg.Timing.Heartbeat / 2
	rc.CommitTimeout = 20 * time.Millisecond
	rc.SnapshotThreshold = 512
	rc.TrailingLogs = 256
	rc.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Warn, DisableTime: true,
		Output: slog.NewLogLogger(n.log.Handler(), slog.LevelWarn).Writer()})
	n.rcfg = rc
	return n.startRaft()
}

// startRaft opens the transport and starts Raft on the node's stores.
func (n *Node) startRaft() error {
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
	r.RegisterObserver(raft.NewObserver(obs, false, func(o *raft.Observation) bool {
		switch o.Data.(type) {
		case raft.FailedHeartbeatObservation, raft.ResumedHeartbeatObservation:
			return true
		}
		return false
	}))
	go n.observe(obs)
	return nil
}

func (n *Node) transport() (*raft.NetworkTransport, error) {
	m, err := newMux(n.cfg.Bind, n.cfg.Advertise, string(n.id), n.tls, n.verifier, n.handleControl, n.blocked)
	if err != nil {
		return nil, err
	}
	n.mux.Store(m)
	return raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: m, MaxPool: 3, Timeout: 10 * time.Second, Logger: n.rcfg.Logger}), nil
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
	go n.watchClock(ctx)
	t := time.NewTicker(n.cfg.Timing.Tick)
	defer t.Stop()
	var lastEpoch uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if n.certs.age() > 6*time.Hour {
			if err := n.certs.renew(); err != nil {
				n.log.Warn("renew peer certificate", "err", err)
			}
		}
		if !n.member() {
			n.joinOrBootstrap(ctx)
			continue
		}
		n.clearJumpIfFresh()
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

func (n *Node) shutdown() {
	if n.r() != nil {
		_ = n.r().Shutdown().Error()
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
	case ctlJoin, ctlApply:
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
	if req.Op == ctlJoin {
		return n.handleJoin(req)
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
		return nil, errors.New("cds-ha: " + resp.Err)
	}
	if !n.waitFor(n.cfg.Timing.Apply, func() bool { return n.fsm.AppliedIndex() >= resp.Index }) {
		return nil, errors.New("cds-ha: write committed but not yet applied here")
	}
	return resp.Response, nil
}

// replicate proposes e and decodes the FSM's answer. A failed proposal
// wraps unavailable, if set, so the store reports the cluster unavailable.
func replicate[R any](n *Node, e Entry, unavailable error) (R, error) {
	var res R
	raw, err := n.propose(e)
	if err != nil {
		if unavailable != nil {
			err = fmt.Errorf("%w: %w", unavailable, err)
		}
		return res, err
	}
	return res, json.Unmarshal(raw, &res)
}

// Replicate implements allowlist.Replicator.
func (n *Node) Replicate(cmd allowlist.Command) (allowlist.Result, error) {
	return replicate[allowlist.Result](n, Entry{Kind: KindAllowlist, Allowlist: &cmd}, allowlist.ErrUnavailable)
}

// ReplicateSecret implements secrets.Replicator.
func (n *Node) ReplicateSecret(cmd secrets.Command) (secrets.Result, error) {
	return replicate[secrets.Result](n, Entry{Kind: KindSecret, Secret: &cmd}, secrets.ErrUnavailable)
}

// ReplicateBinding implements sandboxledger.Replicator.
func (n *Node) ReplicateBinding(cmd sandboxledger.Command) (bool, error) {
	return replicate[bool](n, Entry{Kind: KindBinding, Binding: &cmd}, nil)
}

// CatchUp implements sandboxledger.Replicator: it waits until this replica
// has applied everything the leader had applied when asked.
func (n *Node) CatchUp() error {
	if n.leading() {
		return nil
	}
	addr, _ := n.r().LeaderWithID()
	if addr == "" {
		return errors.New("cds-ha: no leader")
	}
	st, err := n.peerStatus(addr, 2*time.Second)
	if err != nil {
		return err
	}
	if !n.waitFor(2*time.Second, func() bool { return n.fsm.AppliedIndex() >= st.AppliedIndex }) {
		return errors.New("cds-ha: not caught up with the leader")
	}
	return nil
}

// Serving reports whether this replica may issue certificates and release
// secrets: it holds the cluster's mesh CA, its own image is pinned, and it
// is fresh. The leader is fresh while it keeps its quorum lease; any other
// replica while it heard from the leader within the lease and since the last
// clock jump. An isolated replica stops serving, so it cannot keep admitting
// what a decree it has not seen evicted.
func (n *Node) Serving() bool {
	core := n.fsm.Core()
	if !core.Joined() || !core.Pins(n.measurement) || n.r() == nil {
		return false
	}
	if n.jumpAt.Load() != 0 || n.fsm.Stuck() != "" {
		return false
	}
	if n.leading() {
		return true
	}
	lc := n.r().LastContact()
	return !lc.IsZero() && time.Since(lc) < n.cfg.Timing.Lease
}

// CA is the mesh CA to issue with, while serving.
func (n *Node) CA() (*issuer.CA, error) {
	if !n.Serving() {
		return nil, errors.New("cds-ha: replica is not serving (not joined, not pinned, or not fresh)")
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
	if core.Joined() {
		st.CAFingerprint = certutil.CertFingerprint(core.RootCert)
	}
	if n.r() == nil {
		return st
	}
	st.State = n.r().State().String()
	st.Serving = n.Serving()
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
		return true
	}
	if n.leading() {
		return n.seatsFilled()
	}
	at := n.seatsOKAt.Load()
	return at != 0 && time.Since(time.UnixMilli(at)) < 3*n.cfg.Timing.Tick+time.Second
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
			wall := now.Round(0).Sub(last.Round(0))
			if d := wall - mono; d > 2*time.Second || d < -2*time.Second || mono > 5*time.Second {
				n.jumpAt.Store(now.UnixMilli())
				n.log.Warn("clock jump: not serving until the leader is heard again", "wall_minus_mono", d, "tick", mono)
			}
			last = now
		}
	}
}

// clearJumpIfFresh ends a clock-jump stop once the replica has fresh
// contact: a leader that confirms its quorum, or a follower that heard from
// the leader after the jump.
func (n *Node) clearJumpIfFresh() {
	at := n.jumpAt.Load()
	if at == 0 {
		return
	}
	if n.leading() {
		if n.r().VerifyLeader().Error() == nil {
			n.jumpAt.CompareAndSwap(at, 0)
		}
		return
	}
	if lc := n.r().LastContact(); lc.UnixMilli() > at {
		n.jumpAt.CompareAndSwap(at, 0)
	}
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
