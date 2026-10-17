package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
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
}

// Node is one CDS replica.
type Node struct {
	cfg         Config
	id          raft.ServerID
	fsm         *FSM
	rft         atomic.Pointer[raft.Raft]
	mux         *mux
	rcfg        *raft.Config
	logs        *raft.InmemStore
	stable      *raft.InmemStore
	snaps       *raft.InmemSnapshotStore
	noLeader    time.Time    // since when a member has seen no leader
	lastMember  atomic.Int64 // Unix ms a reachable peer last reported membership (or this start)
	joinLogged  bool
	certs       *certHolder
	tls         *tls.Config
	measurement string
	log         *slog.Logger

	jumpAt atomic.Int64 // Unix ms of the last clock jump not yet cleared by fresh contact

	// blocked, in tests only, refuses connections to and from addresses as a
	// network partition would.
	blocked func(addr string) bool

	mu       sync.Mutex
	failing  map[raft.ServerID]time.Time // leader: when a member's heartbeats started failing
	joinedAt map[raft.ServerID]time.Time // leader: when a member was added
	addedAt  map[raft.ServerID]time.Time // leader: when this leader added a member (handleJoin)

	backupAt    time.Time // leader: last backup attempt
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
	if cfg.Timing == (Timing{}) {
		cfg.Timing = DefaultTiming
	}
	if cfg.Timing.Backup == 0 {
		cfg.Timing.Backup = DefaultTiming.Backup
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CACommonName == "" {
		cfg.CACommonName = "c8s-mesh-ca"
	}
	if cfg.CAValidity == 0 {
		cfg.CAValidity = 10 * 365 * 24 * time.Hour
	}
	own, err := ownClaims(cfg.Attestor)
	if err != nil {
		return nil, err
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
	n.lastMember.Store(time.Now().UnixMilli())
	if n.certs, err = newCertHolder(func() (tls.Certificate, error) { return newPeerCert(cfg.ClusterID, cfg.Attestor) }); err != nil {
		return nil, err
	}
	v := peerVerifier{clusterID: cfg.ClusterID, att: cfg.Attestor, anchor: own.Anchor, pins: n.peerPins}
	n.tls = peerTLSConfig(v, n.certs)
	return n, nil
}

// ownClaims verifies the replica's own evidence once, for its measurement
// and launch-key anchor.
func ownClaims(att Attestor) (Claims, error) {
	ev, err := att.Evidence([48]byte{})
	if err != nil {
		return Claims{}, fmt.Errorf("own evidence: %w", err)
	}
	c, err := att.Verify(ev)
	if err != nil {
		return Claims{}, fmt.Errorf("own evidence does not verify: %w", err)
	}
	return c, nil
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

// raftAddress is where peers reach this member's Raft, with its member ID.
func (n *Node) raftAddress() raft.ServerAddress {
	return raft.ServerAddress(n.cfg.Advertise + "#" + string(n.id))
}

// ID is this replica's Raft member ID.
func (n *Node) ID() string { return string(n.id) }

// Start opens the peer port and starts Raft. Run drives it.
func (n *Node) Start() error {
	n.logs, n.stable, n.snaps = raft.NewInmemStore(), raft.NewInmemStore(), raft.NewInmemSnapshotStore()
	rc := raft.DefaultConfig()
	rc.LocalID = n.id
	rc.HeartbeatTimeout = n.cfg.Timing.Heartbeat
	rc.ElectionTimeout = n.cfg.Timing.Election
	rc.LeaderLeaseTimeout = n.cfg.Timing.Heartbeat / 2
	rc.CommitTimeout = 20 * time.Millisecond
	rc.SnapshotThreshold = 512
	rc.TrailingLogs = 256
	rc.Logger = hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Warn, Output: slogWriter{n.log}})
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
	v := peerVerifier{clusterID: n.cfg.ClusterID, att: n.cfg.Attestor, anchor: n.ownAnchor(), pins: n.peerPins}
	m, err := newMux(n.cfg.Bind, n.cfg.Advertise, string(n.id), n.tls, v, n.handleControl, n.blocked)
	if err != nil {
		return nil, err
	}
	n.mux = m
	return raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: m, MaxPool: 3, Timeout: 10 * time.Second, Logger: n.rcfg.Logger}), nil
}

// recover makes this replica the only voter of the cluster, with the state
// it holds, for a verified Recover decree naming it.
func (n *Node) recover(ctx context.Context, p PendingDecree) {
	n.log.Warn("RECOVER: forcing a one-voter configuration with this replica's state", "decree", p.Name, "id", n.id)
	if err := n.r().Shutdown().Error(); err != nil {
		n.log.Error("recover: shut down raft", "err", err)
	}
	_ = n.mux.Close()
	// RecoverCluster replays the log into the FSM it is given; use a
	// scratch one, and let NewRaft restore the real one from the snapshot.
	al, err := allowlist.OpenInMemory()
	if err != nil {
		n.log.Error("recover: scratch store", "err", err)
		return
	}
	defer al.Close()
	scratch := NewFSM(PreGenesis(n.cfg.ClusterID, n.cfg.OperatorPubKey), &al, secrets.NewMemoryStore(1<<20, 1<<19, 1<<20), sandboxledger.New(time.Hour, 1<<20))
	trans, err := n.transport()
	if err != nil {
		n.log.Error("recover: transport", "err", err)
		return
	}
	conf := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: n.id, Address: n.raftAddress()}}}
	if err := raft.RecoverCluster(n.rcfg, scratch, n.logs, n.stable, n.snaps, trans, conf); err != nil {
		n.log.Error("recover: RecoverCluster", "err", err)
	}
	_ = trans.Close()
	_ = n.mux.Close()
	if err := n.startRaft(); err != nil {
		n.log.Error("recover: restart raft", "err", err)
		return
	}
	deadline := time.Now().Add(20 * n.cfg.Timing.Election)
	for n.r().State() != raft.Leader && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Record the decree in the log, so it can never apply again.
	n.applyDecree(ctx, p)
}

// pendingRecover is a valid Recover decree naming this replica.
func (n *Node) pendingRecover(ctx context.Context) (PendingDecree, bool) {
	if n.cfg.Decrees == nil {
		return PendingDecree{}, false
	}
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		return PendingDecree{}, false
	}
	for _, d := range ds {
		if d.Err != nil || d.Decree.Decree.Kind != Recover || d.Decree.Decree.BootstrapNode != n.cfg.NodeName {
			continue
		}
		if err := CheckDecree(d.Decree, n.fsm.Core(), time.Now()); err != nil {
			n.log.Info("recover decree not usable", "decree", d.Name, "why", err)
			continue
		}
		return d, true
	}
	return PendingDecree{}, false
}

func (n *Node) ownAnchor() string {
	c, _ := ownClaims(n.cfg.Attestor)
	return c.Anchor
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
			n.mux.recheck() // the pin set may have changed
		}
		switch addr, _ := n.r().LeaderWithID(); {
		case n.r().State() == raft.Leader:
			n.noLeader = time.Time{}
			n.reconcile()
			n.applyDecrees(ctx)
			n.maybeBackup(ctx)
		case addr != "":
			n.noLeader = time.Time{}
		case n.noLeader.IsZero():
			n.noLeader = time.Now()
		case time.Since(n.noLeader) > n.cfg.Timing.DeadAfter:
			// No majority for a while: an operator Recover decree naming us
			// makes us the only voter; otherwise the cluster may have been
			// recovered around us, so ask to be added again.
			if p, ok := n.pendingRecover(ctx); ok {
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
	if n.mux != nil {
		_ = n.mux.Close()
	}
}

// member reports whether this replica is in a Raft configuration.
func (n *Node) member() bool {
	if n.r() == nil {
		return false
	}
	f := n.r().GetConfiguration()
	if f.Error() != nil {
		return false
	}
	return slices.ContainsFunc(f.Configuration().Servers, func(s raft.Server) bool { return s.ID == n.id })
}

// joinOrBootstrap asks the replicas it can reach to add it. A replica named
// by a pending Genesis decree starts the group instead, but only when no
// reachable replica already belongs to one.
func (n *Node) joinOrBootstrap(ctx context.Context) {
	peers, err := n.cfg.Peers(ctx)
	if err != nil {
		n.log.Debug("peer discovery", "err", err)
	}
	anyMember := false
	for _, p := range peers {
		resp, err := n.askJoin(p)
		if err == nil && resp.Err == "" {
			if !n.joinLogged {
				n.log.Info("joined the CDS cluster", "via", p, "id", n.id)
				n.joinLogged = true
			}
			return
		}
		if err == nil && resp.Member {
			anyMember = true
		}
		if err != nil || resp.Err != "" {
			n.log.Debug("join refused", "peer", p, "err", errors.Join(err, errorsOrNil(resp.Err)))
		}
	}
	if anyMember {
		n.lastMember.Store(time.Now().UnixMilli())
	}
	if anyMember || n.cfg.Decrees == nil {
		return
	}
	if g, ok := n.pendingGenesis(ctx); ok {
		n.bootstrap(ctx, g)
	}
}

// rejoin asks reachable replicas to add this member, as a joiner would; a
// leader that already has it answers without change.
func (n *Node) rejoin(ctx context.Context) {
	peers, _ := n.cfg.Peers(ctx)
	for _, p := range peers {
		if resp, err := n.askJoin(p); err == nil && resp.Err == "" {
			return
		}
	}
}

func errorsOrNil(s string) error {
	if s == "" {
		return nil
	}
	return errors.New(s)
}

// askJoin asks peer p to add this replica, following one redirect to the
// leader.
func (n *Node) askJoin(p string) (controlResponse, error) {
	req := controlRequest{Op: ctlJoin, ID: string(n.id), Address: string(n.raftAddress())}
	resp, err := n.call(p, 5*time.Second, req)
	if err != nil || resp.Leader == "" || resp.Leader == p || resp.Leader == n.cfg.Advertise {
		return resp, err
	}
	// Whoever answers next, the first peer belongs to a cluster: that alone
	// must keep this replica from starting another.
	member := resp.Member
	resp, err = n.call(resp.Leader, 5*time.Second, req)
	resp.Member = resp.Member || member
	if err != nil && member {
		return controlResponse{Member: true, Err: err.Error()}, nil
	}
	return resp, err
}

func (n *Node) call(addr string, timeout time.Duration, req controlRequest) (controlResponse, error) {
	if n.blocked != nil && n.blocked(addr) {
		return controlResponse{}, errors.New("partitioned")
	}
	var local net.Addr
	if n.mux != nil {
		local = n.mux.advert.tcp
	}
	return callControl(addr, n.tls, timeout, req, local)
}

func (n *Node) pendingGenesis(ctx context.Context) (PendingDecree, bool) {
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		return PendingDecree{}, false
	}
	for _, d := range ds {
		if d.Err != nil || d.Decree.Decree.Kind != Genesis || d.Decree.Decree.BootstrapNode != n.cfg.NodeName {
			continue
		}
		if err := CheckDecree(d.Decree, n.fsm.Core(), time.Now()); err != nil {
			n.log.Info("genesis decree not usable", "decree", d.Name, "why", err)
			continue
		}
		return d, true
	}
	return PendingDecree{}, false
}

// bootstrap starts a one-voter group with this replica and applies Genesis.
func (n *Node) bootstrap(ctx context.Context, g PendingDecree) {
	n.log.Info("bootstrapping the CDS cluster", "decree", g.Name, "id", n.id)
	cfg := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: n.id, Address: n.raftAddress()}}}
	if err := n.r().BootstrapCluster(cfg).Error(); err != nil {
		n.log.Warn("bootstrap", "err", err)
		return
	}
	deadline := time.Now().Add(10 * n.cfg.Timing.Election)
	for n.r().State() != raft.Leader && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	n.applyDecree(ctx, g)
}

// maybeBackup seals and stores the state when it changed since the last
// stored backup, at most every Timing.Backup (leader only).
func (n *Node) maybeBackup(ctx context.Context) {
	if n.recovery == nil || n.cfg.Backups == nil || time.Since(n.backupAt) < n.cfg.Timing.Backup {
		return
	}
	core := n.fsm.Core()
	// Read the index before the snapshot: a write applied while it is taken
	// then still counts as not backed up, and the next round covers it.
	applied := n.fsm.AppliedIndex()
	if !core.Joined() || applied == n.backupIndex {
		return
	}
	n.backupAt = time.Now()
	f := n.r().Snapshot()
	if err := f.Error(); err != nil {
		n.log.Warn("backup: snapshot", "err", err)
		return
	}
	meta, rc, err := f.Open()
	if err != nil {
		n.log.Warn("backup: open snapshot", "err", err)
		return
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		return
	}
	sn, err := decodeSnapshot(bytes.NewReader(body))
	if err != nil {
		n.log.Warn("backup: decode snapshot", "err", err)
		return
	}
	sum := sha256.Sum256(sn.Core.RootCert)
	b, err := SealBackup(n.recovery, BackupMeta{ClusterID: sn.Core.ClusterID, Epoch: sn.Core.Epoch, Index: meta.Index,
		AppliedDecrees: sn.Core.AppliedDecrees, TakenAtMS: time.Now().UnixMilli(), CAFingerprint: hex.EncodeToString(sum[:])}, body)
	if err != nil {
		n.log.Warn("backup: seal", "err", err)
		return
	}
	if err := n.cfg.Backups.PutBackup(ctx, b); err != nil {
		n.log.Warn("backup: store", "err", err)
		return
	}
	n.backupIndex = applied
	n.log.Info("backup stored", "epoch", b.Meta.Epoch, "index", b.Meta.Index, "bytes", len(b.Ciphertext))
}

// AwaitingRestore reports a replica that holds no cluster and has not seen
// one for dead_after: every replica was lost, and only an operator Restore
// (or Genesis) can start one. It is how the pre-join server tells the Service
// it may take the operator's restore; a replica on its way into a live
// cluster is not ready.
func (n *Node) AwaitingRestore() bool {
	if n.member() || n.fsm.Core().Joined() {
		return false
	}
	return time.Since(time.UnixMilli(n.lastMember.Load())) > n.cfg.Timing.DeadAfter
}

// ErrNotForThisNode refuses a Restore decree that names another node.
var ErrNotForThisNode = errors.New("cds-ha: the Restore decree names another node")

// Restore starts a cluster from an operator backup on this replica, which
// must hold no cluster and be the node the decree names. No replica it can
// reach may belong to a cluster: a restore never forks a live one.
func (n *Node) Restore(ctx context.Context, sd SignedDecree, snapshot []byte) (DecreeResult, error) {
	d := sd.Decree
	switch {
	case n.r() == nil:
		return DecreeResult{}, errors.New("cds-ha: replica not started")
	case d.Kind != Restore:
		return DecreeResult{}, errors.New("cds-ha: not a Restore decree")
	case d.BootstrapNode != n.cfg.NodeName:
		return DecreeResult{}, ErrNotForThisNode
	case n.member() || n.fsm.Core().Joined():
		return DecreeResult{}, errors.New("cds-ha: this replica already belongs to a cluster")
	}
	if err := CheckDecree(sd, n.fsm.Core(), time.Now()); err != nil {
		return DecreeResult{}, err
	}
	if SnapshotSHA256(snapshot) != d.SnapshotSHA256 {
		return DecreeResult{}, errors.New("cds-ha: snapshot differs from the one the decree names")
	}
	peers, _ := n.cfg.Peers(ctx)
	for _, p := range peers {
		if resp, err := n.call(p, 3*time.Second, controlRequest{Op: ctlStatus}); err == nil && resp.Member {
			return DecreeResult{}, fmt.Errorf("cds-ha: replica %s belongs to a cluster; join it instead of restoring", p)
		}
	}
	n.log.Warn("RESTORE: starting the cluster from an operator backup", "decree", d.IntentID, "snapshot", d.SnapshotSHA256)
	conf := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: n.id, Address: n.raftAddress()}}}
	if err := n.r().BootstrapCluster(conf).Error(); err != nil {
		return DecreeResult{}, err
	}
	deadline := time.Now().Add(20 * n.cfg.Timing.Election)
	for n.r().State() != raft.Leader {
		if time.Now().After(deadline) {
			return DecreeResult{}, errors.New("cds-ha: did not become leader after bootstrap")
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, err := json.Marshal(Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: time.Now().UnixMilli(), Snapshot: snapshot}})
	if err != nil {
		return DecreeResult{}, err
	}
	_, resp, err := n.applyLocal(raw)
	if err != nil {
		return DecreeResult{}, err
	}
	var res DecreeResult
	if err := json.Unmarshal(resp, &res); err != nil {
		return DecreeResult{}, err
	}
	if res.Err != "" {
		return res, errors.New("cds-ha: restore refused: " + res.Err)
	}
	return res, nil
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
	if n.r().State() != raft.Leader {
		addr, _ := n.r().LeaderWithID()
		if addr == "" {
			return controlResponse{Member: member, Err: "no leader"}
		}
		hp, _ := splitRaftAddr(string(addr))
		return controlResponse{Member: member, Leader: hp, Err: "not the leader"}
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
	if err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	return controlResponse{Member: true, Index: idx, Response: resp}
}

func (n *Node) handleJoin(req controlRequest) controlResponse {
	id := raft.ServerID(req.ID)
	hostport, addrID := splitRaftAddr(req.Address)
	if nodeOf(id) == "" || hostport == "" || addrID != req.ID {
		return controlResponse{Member: true, Err: "bad join request"}
	}
	f := n.r().GetConfiguration()
	if err := f.Error(); err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	nonVoters := 0
	for _, s := range f.Configuration().Servers {
		if s.ID == id {
			return controlResponse{Member: true}
		}
		if hp, _ := splitRaftAddr(string(s.Address)); hp == hostport && s.ID != n.id {
			// Only one process listens on an address: the member there is a
			// dead earlier incarnation, and its seat is the joiner's.
			if err := n.r().RemoveServer(s.ID, 0, n.cfg.Timing.Apply).Error(); err != nil {
				return controlResponse{Member: true, Err: err.Error()}
			}
			n.log.Info("member replaced at its address", "old", s.ID, "new", id)
			continue
		}
		if s.Suffrage != raft.Voter {
			nonVoters++
		}
	}
	if max := n.cfg.MaxNonVoters; max > 0 && nonVoters >= max {
		return controlResponse{Member: true, Err: "no room for another replica"}
	}
	if err := n.r().AddNonvoter(id, raft.ServerAddress(req.Address), 0, n.cfg.Timing.Apply).Error(); err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	n.mu.Lock()
	n.joinedAt[id] = time.Now()
	n.addedAt[id] = n.joinedAt[id]
	delete(n.failing, id) // failures of an earlier membership (see noteFailure)
	n.mu.Unlock()
	n.log.Info("replica joined as non-voter", "id", id, "address", req.Address)
	return controlResponse{Member: true}
}

// nodeOf is the node name a member ID carries.
func nodeOf(id raft.ServerID) string {
	node, _, ok := strings.Cut(string(id), "/")
	if !ok {
		return ""
	}
	return node
}

// bornOf orders two members of one node: the later start replaces the other.
func bornOf(id raft.ServerID) int64 {
	_, rest, _ := strings.Cut(string(id), "/")
	ms, _, _ := strings.Cut(rest, "-")
	v, _ := strconv.ParseInt(ms, 10, 64)
	return v
}

func (n *Node) observe(ch <-chan raft.Observation) {
	for o := range ch {
		n.mu.Lock()
		switch d := o.Data.(type) {
		case raft.FailedHeartbeatObservation:
			n.noteFailure(d.PeerID, d.LastContact, time.Now())
		case raft.ResumedHeartbeatObservation:
			delete(n.failing, d.PeerID)
		}
		n.mu.Unlock()
	}
}

// clearReachable probes the members due for removal as dead and forgets the
// failures of any that answers: a removal is for a member unreachable now,
// not for a stale observation.
func (n *Node) clearReachable(servers []raft.Server, now time.Time) {
	n.mu.Lock()
	var suspects []raft.Server
	for _, s := range servers {
		if since, bad := n.failing[s.ID]; bad && s.ID != n.id && now.Sub(since) >= n.cfg.Timing.DeadAfter {
			suspects = append(suspects, s)
		}
	}
	n.mu.Unlock()
	for _, s := range suspects {
		hostport, _ := splitRaftAddr(string(s.Address))
		// The same member must answer, not a later process at its address.
		if resp, err := n.call(hostport, time.Second, controlRequest{Op: ctlStatus}); err == nil && resp.Status != nil && resp.Status.ID == string(s.ID) {
			n.log.Info("member answers; its heartbeat failures were stale", "id", s.ID)
			n.mu.Lock()
			delete(n.failing, s.ID)
			n.mu.Unlock()
		}
	}
}

// noteFailure records that heartbeats to a member fail, as of its last
// successful contact. A replication stream outlives the member's removal, so
// a member removed and added again can still see failures from the stream of
// its earlier membership, after the new stream already reaches it; nothing
// would clear them (the new stream never "resumes"), and the member would be
// removed again after dead_after. Those failures carry a last contact from
// before the member was added; they are ignored. Callers hold n.mu.
func (n *Node) noteFailure(id raft.ServerID, lastContact, now time.Time) {
	joined, ok := n.addedAt[id]
	if ok && !lastContact.IsZero() && lastContact.Before(joined) {
		return
	}
	if _, already := n.failing[id]; already {
		return
	}
	since := lastContact
	if since.IsZero() {
		since = now
	}
	if ok && since.Before(joined) {
		since = joined
	}
	n.failing[id] = since
}

// reconcile keeps the voter seats filled with one healthy replica per node:
// it removes members that are dead or were replaced by a restart of the
// same node, and promotes stable non-voters into free seats.
func (n *Node) reconcile() {
	f := n.r().GetConfiguration()
	if f.Error() != nil {
		return
	}
	servers := f.Configuration().Servers
	now := time.Now()
	n.clearReachable(servers, now)
	n.mu.Lock()
	failingSince := func(id raft.ServerID) (time.Time, bool) { t, ok := n.failing[id]; return t, ok }
	healthy := func(id raft.ServerID) bool {
		if id == n.id {
			return true
		}
		_, bad := failingSince(id)
		j, ok := n.joinedAt[id]
		if !ok {
			n.joinedAt[id] = now
			j = now
		}
		return !bad && now.Sub(j) >= n.cfg.Timing.Stabilize
	}
	var remove []raft.ServerID
	newest := map[string]raft.ServerID{}
	for _, s := range servers {
		node := nodeOf(s.ID)
		if cur, ok := newest[node]; !ok || bornOf(s.ID) > bornOf(cur) {
			newest[node] = s.ID
		}
	}
	for _, s := range servers {
		if s.ID == n.id {
			continue
		}
		if since, bad := failingSince(s.ID); bad && now.Sub(since) >= n.cfg.Timing.DeadAfter {
			remove = append(remove, s.ID)
			continue
		}
		if nw := newest[nodeOf(s.ID)]; nw != s.ID && nw != n.id && healthy(nw) {
			remove = append(remove, s.ID) // restarted: the new member takes over
		}
	}
	voters, voterNodes := 0, map[string]bool{}
	for _, s := range servers {
		if s.Suffrage == raft.Voter && !slices.Contains(remove, s.ID) {
			voters++
			voterNodes[nodeOf(s.ID)] = true
		}
	}
	var promote []raft.Server
	for _, s := range servers {
		if voters+len(promote) >= n.cfg.Seats {
			break
		}
		if s.Suffrage == raft.Voter || slices.Contains(remove, s.ID) || voterNodes[nodeOf(s.ID)] || !healthy(s.ID) {
			continue
		}
		voterNodes[nodeOf(s.ID)] = true
		promote = append(promote, s)
	}
	n.mu.Unlock()
	for _, id := range remove {
		if err := n.r().RemoveServer(id, 0, n.cfg.Timing.Apply).Error(); err != nil {
			n.log.Warn("remove member", "id", id, "err", err)
			continue
		}
		n.mu.Lock()
		delete(n.failing, id)
		delete(n.joinedAt, id)
		delete(n.addedAt, id)
		n.mu.Unlock()
		n.log.Info("member removed", "id", id)
	}
	for _, s := range promote {
		if err := n.r().AddVoter(s.ID, s.Address, 0, n.cfg.Timing.Apply).Error(); err != nil {
			n.log.Warn("promote member", "id", s.ID, "err", err)
			continue
		}
		n.log.Info("member promoted to voter", "id", s.ID)
	}
}

// applyDecrees applies pending operator decrees (leader only).
func (n *Node) applyDecrees(ctx context.Context) {
	if n.cfg.Decrees == nil {
		return
	}
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		n.log.Debug("list decrees", "err", err)
		return
	}
	for _, d := range ds {
		n.applyDecree(ctx, d)
	}
}

func (n *Node) applyDecree(ctx context.Context, p PendingDecree) {
	core := n.fsm.Core()
	if p.Err == nil {
		if i := slices.Index(core.AppliedDecrees, p.Decree.Decree.IntentID); i >= 0 {
			epoch := uint64(i + 1)
			n.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &epoch})
			return
		}
	}
	err := p.Err
	if err == nil {
		err = CheckDecree(p.Decree, core, time.Now())
	}
	d := p.Decree.Decree
	if err == nil && d.Kind == RotateKey && len(d.Measurements) > 0 && !slices.Contains(d.Measurements, n.measurement) {
		err = errors.New("bundled pin set excludes the leader; apply UpdateMeasurements first")
	}
	if err != nil {
		n.log.Info("decree rejected", "decree", p.Name, "why", err)
		n.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: err.Error()})
		return
	}
	de := DecreeEntry{Decree: p.Decree, AtMS: time.Now().UnixMilli()}
	if d.Kind == Genesis {
		de.Pins = n.cfg.BakedPins
	}
	if d.Kind == Genesis || d.Kind == RotateKey {
		ca, err := issuer.NewCAWithCurve(n.cfg.CACommonName, n.cfg.CAValidity, elliptic.P384())
		if err != nil {
			n.log.Error("mint mesh CA", "err", err)
			return
		}
		key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			n.log.Error("encode mesh CA key", "err", err)
			return
		}
		de.RootCert, de.Key = ca.Cert.Raw, key
	}
	raw, err := json.Marshal(Entry{Kind: KindDecree, Decree: &de})
	if err != nil {
		return
	}
	_, resp, err := n.applyLocal(raw)
	if err != nil {
		n.log.Warn("apply decree", "decree", p.Name, "err", err)
		return
	}
	var res DecreeResult
	_ = json.Unmarshal(resp, &res)
	if res.Err != "" {
		n.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: res.Err})
		return
	}
	n.log.Info("decree applied", "decree", p.Name, "kind", d.Kind, "epoch", res.Epoch)
	n.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &res.Epoch})
}

func (n *Node) setStatus(ctx context.Context, name string, st DecreeStatus) {
	if err := n.cfg.Decrees.SetDecreeStatus(ctx, name, st); err != nil {
		n.log.Warn("write decree status", "decree", name, "err", err)
	}
}

// applyLocal commits an entry through this replica, which must lead.
func (n *Node) applyLocal(raw json.RawMessage) (uint64, json.RawMessage, error) {
	f := n.r().Apply(raw, n.cfg.Timing.Apply)
	if err := f.Error(); err != nil {
		return 0, nil, err
	}
	resp := f.Response()
	if err, ok := resp.(error); ok {
		return 0, nil, err
	}
	body, err := json.Marshal(resp)
	return f.Index(), body, err
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
	if n.r().State() == raft.Leader {
		_, resp, err := n.applyLocal(raw)
		return resp, err
	}
	addr, _ := n.r().LeaderWithID()
	if addr == "" {
		return nil, errors.New("cds-ha: no leader (fewer than a majority of replicas reachable)")
	}
	hp, _ := splitRaftAddr(string(addr))
	resp, err := n.call(hp, n.cfg.Timing.Apply, controlRequest{Op: ctlApply, Entry: raw})
	if err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New("cds-ha: " + resp.Err)
	}
	deadline := time.Now().Add(n.cfg.Timing.Apply)
	for n.fsm.AppliedIndex() < resp.Index {
		if time.Now().After(deadline) {
			return nil, errors.New("cds-ha: write committed but not yet applied here")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return resp.Response, nil
}

// Replicate implements allowlist.Replicator.
func (n *Node) Replicate(cmd allowlist.Command) (allowlist.Result, error) {
	var res allowlist.Result
	raw, err := n.propose(Entry{Kind: KindAllowlist, Allowlist: &cmd})
	if err != nil {
		return res, fmt.Errorf("%w: %w", allowlist.ErrUnavailable, err)
	}
	return res, json.Unmarshal(raw, &res)
}

// ReplicateSecret implements secrets.Replicator.
func (n *Node) ReplicateSecret(cmd secrets.Command) (secrets.Result, error) {
	var res secrets.Result
	raw, err := n.propose(Entry{Kind: KindSecret, Secret: &cmd})
	if err != nil {
		return res, fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}
	return res, json.Unmarshal(raw, &res)
}

// ReplicateBinding implements sandboxledger.Replicator.
func (n *Node) ReplicateBinding(cmd sandboxledger.Command) (bool, error) {
	var held bool
	raw, err := n.propose(Entry{Kind: KindBinding, Binding: &cmd})
	if err == nil {
		err = json.Unmarshal(raw, &held)
	}
	return held, err
}

// CatchUp implements sandboxledger.Replicator: it waits until this replica
// has applied everything the leader had applied when asked.
func (n *Node) CatchUp() error {
	if n.r().State() == raft.Leader {
		return nil
	}
	addr, _ := n.r().LeaderWithID()
	if addr == "" {
		return errors.New("cds-ha: no leader")
	}
	hp, _ := splitRaftAddr(string(addr))
	resp, err := n.call(hp, 2*time.Second, controlRequest{Op: ctlStatus})
	if err != nil {
		return err
	}
	if resp.Status == nil {
		return errors.New("cds-ha: leader sent no status")
	}
	deadline := time.Now().Add(2 * time.Second)
	for n.fsm.AppliedIndex() < resp.Status.AppliedIndex {
		if time.Now().After(deadline) {
			return errors.New("cds-ha: not caught up with the leader")
		}
		time.Sleep(5 * time.Millisecond)
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
	if n.jumpAt.Load() != 0 {
		return false
	}
	if n.r().State() == raft.Leader {
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

// Status is this replica's view of the cluster.
func (n *Node) Status() Status {
	core := n.fsm.Core()
	st := Status{ClusterID: n.cfg.ClusterID, NodeName: n.cfg.NodeName, ID: string(n.id), Joined: core.Joined(),
		Epoch: core.Epoch, Measurement: n.measurement, AppliedIndex: n.fsm.AppliedIndex()}
	if core.Joined() {
		sum := sha256.Sum256(core.RootCert)
		st.CAFingerprint = hex.EncodeToString(sum[:])
	}
	if n.r() == nil {
		return st
	}
	st.State = n.r().State().String()
	st.Serving = n.Serving()
	addr, _ := n.r().LeaderWithID()
	st.Leader, _ = splitRaftAddr(string(addr))
	if lc := n.r().LastContact(); !lc.IsZero() {
		st.LastContactMS = time.Since(lc).Milliseconds()
	}
	if f := n.r().GetConfiguration(); f.Error() == nil {
		for _, s := range f.Configuration().Servers {
			if s.Suffrage == raft.Voter {
				st.Voters = append(st.Voters, string(s.ID))
			} else {
				st.NonVoters = append(st.NonVoters, string(s.ID))
			}
		}
	}
	return st
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
	if n.r().State() == raft.Leader {
		if n.r().VerifyLeader().Error() == nil {
			n.jumpAt.CompareAndSwap(at, 0)
		}
		return
	}
	if lc := n.r().LastContact(); lc.UnixMilli() > at {
		n.jumpAt.CompareAndSwap(at, 0)
	}
}

type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.l.Info(strings.TrimSpace(string(p)), "source", "raft")
	return len(p), nil
}

var _ io.Writer = slogWriter{}
