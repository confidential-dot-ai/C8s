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
	"k8s.io/apimachinery/pkg/util/wait"

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

	joinRefusedAt map[string]time.Time // peer + reason -> last logged

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
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CACommonName == "" {
		cfg.CACommonName = issuer.DefaultCACommonName
	}
	if cfg.CAValidity <= 0 {
		cfg.CAValidity = issuer.DefaultCAValidity
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
	n.tls = peerTLSConfig(n.verifier, n.certs)
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
	n.logs, n.stable, n.snaps = raft.NewInmemStore(), raft.NewInmemStore(), newSnapStore()
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

// recover makes this replica the only voter of the cluster, with the state
// it holds, for a verified Recover decree naming it.
func (n *Node) recover(ctx context.Context, p PendingDecree) {
	n.log.Warn("RECOVER: forcing a one-voter configuration with this replica's state", "decree", p.Name, "id", n.id)
	if err := n.r().Shutdown().Error(); err != nil {
		n.log.Error("recover: shut down raft", "err", err)
	}
	_ = n.mux.Load().Close()
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
	if err := raft.RecoverCluster(n.rcfg, scratch, n.logs, n.stable, n.snaps, trans, n.solo()); err != nil {
		n.log.Error("recover: RecoverCluster", "err", err)
	}
	_ = trans.Close()
	_ = n.mux.Load().Close()
	if err := n.startRaft(); err != nil {
		n.log.Error("recover: restart raft", "err", err)
		return
	}
	n.waitFor(20*n.cfg.Timing.Election, n.leading)
	// Record the decree in the log, so it can never apply again.
	n.applyDecree(ctx, p)
}

// pendingDecree is a valid pending decree of kind naming this replica.
func (n *Node) pendingDecree(ctx context.Context, kind DecreeKind) (PendingDecree, bool) {
	if n.cfg.Decrees == nil {
		return PendingDecree{}, false
	}
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		return PendingDecree{}, false
	}
	for _, d := range ds {
		if d.Err != nil || d.Decree.Decree.Kind != kind || d.Decree.Decree.BootstrapNode != n.cfg.NodeName {
			continue
		}
		if err := CheckDecree(d.Decree, n.fsm.Core(), time.Now()); err != nil {
			n.log.Info("decree not usable", "decree", d.Name, "kind", kind, "why", err)
			continue
		}
		return d, true
	}
	return PendingDecree{}, false
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
		case n.r().State() == raft.Leader:
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

// member reports whether this replica is in a Raft configuration.
func (n *Node) member() bool {
	if n.r() == nil {
		return false
	}
	return slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == n.id })
}

// joinOrBootstrap asks the replicas it can reach to add it. A replica named
// by a pending Genesis decree starts the group instead, but only when no
// reachable replica already belongs to one.
func (n *Node) joinOrBootstrap(ctx context.Context) {
	peers, err := n.cfg.Peers(ctx)
	switch {
	case err != nil:
		// A replica that cannot find its peers can never join: say so.
		n.joinRefused("peer discovery", err)
	case len(peers) == 0:
		n.joinRefused("peer discovery", errors.New("no other replica found"))
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
		if err == nil && !resp.Member {
			n.lastLoner.Store(time.Now().UnixMilli())
		}
		if err == nil {
			err = errors.New(resp.Err)
		}
		n.joinRefused(p, err)
	}
	if anyMember {
		n.lastMember.Store(time.Now().UnixMilli())
		return
	}
	if g, ok := n.pendingDecree(ctx, Genesis); ok {
		n.bootstrap(ctx, g)
	}
}

// joinRefused logs why a peer would not add this replica, at Info once a
// minute per peer and reason: a replica that can never join (a release too
// old for the cluster's format, an image not pinned) must say so.
func (n *Node) joinRefused(peer string, err error) {
	key := peer + " " + err.Error()
	now := time.Now()
	n.mu.Lock()
	if n.joinRefusedAt == nil {
		n.joinRefusedAt = map[string]time.Time{}
	}
	last, seen := n.joinRefusedAt[key]
	if seen && now.Sub(last) < time.Minute {
		n.mu.Unlock()
		return
	}
	n.joinRefusedAt[key] = now
	n.mu.Unlock()
	n.log.Info("join refused", "peer", peer, "err", err)
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

// askJoin asks peer p to add this replica, following one redirect to the
// leader.
func (n *Node) askJoin(p string) (controlResponse, error) {
	req := controlRequest{Op: ctlJoin, ID: string(n.id), Address: string(n.raftAddress()), Reads: n.fsm.readable}
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
	if m := n.mux.Load(); m != nil {
		local = m.advert.tcp
	}
	return callControl(addr, n.tls, timeout, req, local)
}

// bootstrap starts a one-voter group with this replica and applies Genesis.
func (n *Node) bootstrap(ctx context.Context, g PendingDecree) {
	n.log.Info("bootstrapping the CDS cluster", "decree", g.Name, "id", n.id)
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		n.log.Warn("bootstrap", "err", err)
		return
	}
	n.waitFor(10*n.cfg.Timing.Election, n.leading)
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
	sn, err := decodeSnapshot(bytes.NewReader(body), n.fsm.readable)
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
		if errors.Is(err, ErrBackupNotNewer) {
			// Another leader stored later state (this one is deposed or was
			// cut off): leave it.
			n.log.Warn("backup: not stored, a newer one exists", "err", err)
			n.backupIndex = applied
			return
		}
		n.log.Warn("backup: store", "err", err)
		return
	}
	n.backupIndex = applied
	n.log.Info("backup stored", "epoch", b.Meta.Epoch, "index", b.Meta.Index, "bytes", len(b.Ciphertext))
}

// pruneSlack lets the history grow this far past HistoryVersions before the
// leader prunes, so pruning is one entry per batch of writes, not per write.
var pruneSlack = 64 // a var so tests can prune small histories

// maybePruneHistory (leader) bounds the allowlist history through the log,
// so every replica drops the same entries. A replica of a release that
// cannot apply the command would keep its history and drift, so the command
// waits for an agreed format every member reads.
func (n *Node) maybePruneHistory() {
	keep := n.cfg.HistoryVersions
	if (keep <= 0 && n.cfg.HistoryBytes <= 0) || n.cfg.Allowlist == nil || n.fsm.Core().format() < 2 || time.Since(n.pruneAt) < n.cfg.Timing.Backup {
		return
	}
	n.pruneAt = time.Now()
	have, err := n.cfg.Allowlist.HistoryLen()
	if err != nil {
		return
	}
	slack := pruneSlack
	if n.cfg.HistoryBytes > 0 {
		// The leader turns the byte budget into a count, so every replica
		// prunes the same entries.
		fit, err := n.cfg.Allowlist.HistoryKeepForBytes(n.cfg.HistoryBytes)
		if err != nil {
			return
		}
		if keep <= 0 || fit < keep {
			keep, slack = fit, 0
		}
	}
	if have <= keep+slack {
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindAllowlist, Format: 2,
		Allowlist: &allowlist.Command{Op: allowlist.OpPruneHistory, Keep: keep, AtMS: time.Now().UnixMilli()}}); err != nil {
		n.log.Warn("prune allowlist history", "err", err)
		return
	}
	n.log.Info("allowlist history pruned", "kept", keep, "had", have)
}

// maybeRenewCA (leader) renews the mesh CA certificate under the cluster's
// key once it is past half its lifetime, through the log, so every replica
// serves the same certificate and running workloads keep their trust anchor.
// A replica of a release that cannot apply the entry would stop, so it waits
// for format 2, which every member reads.
func (n *Node) maybeRenewCA() {
	ca := n.fsm.CA()
	if ca == nil || n.fsm.Core().format() < 2 || time.Since(n.renewAt) < n.cfg.Timing.Backup {
		return
	}
	cert := ca.Cert
	if time.Now().Before(cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)) {
		return
	}
	n.renewAt = time.Now()
	renewed, err := issuer.SelfSignCA(ca.Key, cert.Subject.CommonName, n.cfg.CAValidity)
	if err != nil {
		n.log.Error("renew mesh CA certificate", "err", err)
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindRenewCA, Format: 2, RenewCA: &RenewCAEntry{RootCert: renewed.Raw}}); err != nil {
		n.log.Warn("renew mesh CA certificate", "err", err)
		return
	}
	keyID := sha256.Sum256(renewed.RawSubjectPublicKeyInfo)
	n.log.Info("renewed mesh CA certificate", "audit", true,
		"key_id", hex.EncodeToString(keyID[:]), "not_after", renewed.NotAfter.Format(time.RFC3339))
}

// AwaitingRestore reports a replica that holds no cluster and has not seen
// one for dead_after: every replica was lost, and only an operator Restore
// (or Genesis) can start one. It is how the pre-join server tells the Service
// it may take the operator's restore; a replica on its way into a live
// cluster is not ready.
//
// Not hearing from a member is not enough: a replica on a node whose pod
// network is still coming up hears from nobody, and taking client traffic
// then would answer it from the pre-join server. It needs a peer that
// answered and holds no cluster either, or, for a lone survivor of a total
// loss, no member for lonerAfter.
func (n *Node) AwaitingRestore() bool {
	if n.member() || n.fsm.Core().Joined() {
		return false
	}
	sinceMember := time.Since(time.UnixMilli(n.lastMember.Load()))
	if sinceMember <= n.cfg.Timing.DeadAfter {
		return false
	}
	return n.lastLoner.Load() > n.lastMember.Load() || sinceMember > lonerAfter
}

// lonerAfter is how long a replica that reaches no peer at all waits before
// it offers to take a restore on its own.
const lonerAfter = 5 * time.Minute

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
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		return DecreeResult{}, err
	}
	if !n.waitFor(20*n.cfg.Timing.Election, n.leading) {
		return DecreeResult{}, errors.New("cds-ha: did not become leader after bootstrap")
	}
	resp, err := n.applyEntry(Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: time.Now().UnixMilli(), Snapshot: snapshot}})
	if err != nil {
		return DecreeResult{}, err
	}
	res, _ := resp.(DecreeResult)
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
	var body json.RawMessage
	if err == nil {
		body, err = json.Marshal(resp)
	}
	if err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	return controlResponse{Member: true, Index: idx, Response: body}
}

func (n *Node) handleJoin(req controlRequest) controlResponse {
	id := raft.ServerID(req.ID)
	hostport, addrID := splitRaftAddr(req.Address)
	if nodeOf(id) == "" || hostport == "" || addrID != req.ID {
		return controlResponse{Member: true, Err: "bad join request"}
	}
	if reads, agreed := formatOr1(req.Reads), n.fsm.Core().format(); reads < agreed {
		// It could not apply the log it would receive.
		return controlResponse{Member: true, Err: fmt.Sprintf("replica reads format %d, the cluster writes %d", reads, agreed)}
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
	n.reads[id] = formatOr1(req.Reads)
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
		// The same member must answer, not a later process at its address.
		if st, err := n.peerStatus(s.Address, time.Second); err == nil && st.ID == string(s.ID) {
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
	servers := n.servers()
	if servers == nil {
		return
	}
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
		if voters+len(promote) >= n.seats() {
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
		delete(n.reads, id)
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
	if len(remove) == 0 && len(promote) == 0 {
		n.demoteExtraVoter(servers)
	}
	if len(remove) == 0 {
		n.raiseFormat(servers)
	}
}

// demoteExtraVoter (leader) demotes one voter when there are more voters than
// seats: a failing one first, never itself. One per pass, so the group never
// loses more than one vote at a time.
func (n *Node) demoteExtraVoter(servers []raft.Server) {
	var voters []raft.ServerID
	for _, s := range servers {
		if s.Suffrage == raft.Voter {
			voters = append(voters, s.ID)
		}
	}
	if len(voters) <= n.seats() {
		return
	}
	n.mu.Lock()
	var pick raft.ServerID
	for _, id := range voters {
		if id == n.id {
			continue
		}
		if _, bad := n.failing[id]; bad || pick == "" {
			pick = id
			if bad {
				break
			}
		}
	}
	n.mu.Unlock()
	if pick == "" {
		return
	}
	if err := n.r().DemoteVoter(pick, 0, n.cfg.Timing.Apply).Error(); err != nil {
		n.log.Warn("demote voter", "id", pick, "err", err)
		return
	}
	n.log.Info("voter demoted: more voters than seats", "id", pick, "seats", n.seats())
}

// raiseFormat (leader): once every voter seat is filled and every member
// reads a newer format than the agreed one, the cluster agrees on it, so the
// new encoding is only written after the last old replica left. Waiting for
// the seats keeps a group that shrank to new replicas (an old one crashed
// mid-rollout) from locking the old release out before the operator chose to
// move on. A member that joined under an earlier leader is asked what it
// reads; one that does not answer holds the format.
func (n *Node) raiseFormat(servers []raft.Server) {
	agreed := n.fsm.Core().format()
	low := n.fsm.readable
	if low <= agreed || !n.seatsFilled() {
		return
	}
	for _, s := range servers {
		if s.ID == n.id {
			continue
		}
		n.mu.Lock()
		v, ok := n.reads[s.ID]
		n.mu.Unlock()
		if !ok {
			st, err := n.peerStatus(s.Address, time.Second)
			if err != nil || st.ID != string(s.ID) {
				return
			}
			v = formatOr1(st.Reads)
			n.mu.Lock()
			n.reads[s.ID] = v
			n.mu.Unlock()
		}
		low = min(low, v)
	}
	if low <= agreed {
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindFormat, SetFormat: low}); err != nil {
		n.log.Warn("raise cluster format", "to", low, "err", err)
		return
	}
	n.log.Info("cluster format raised: every member reads it", "from", agreed, "to", low)
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
	applied := n.fsm.Core().AppliedDecrees
	for _, d := range ds {
		if d.Err == nil && d.Decree.Decree.Kind == Recover && !slices.Contains(applied, d.Decree.Decree.IntentID) {
			// A leader holds a majority: nothing was lost for good. Applied
			// here, the decree would only bump the epoch, and the replica it
			// names, if merely cut off, would come back to an epoch it did
			// not see.
			n.log.Warn("Recover decree refused: the cluster has a leader with a majority", "decree", d.Name)
			n.setStatus(ctx, d.Name, DecreeStatus{RejectedReason: ErrRecoverWithQuorum.Error()})
			continue
		}
		n.applyDecree(ctx, d)
	}
}

// checkPinsKeepMajority refuses a pin set that would unpin a majority of the
// voters. Peers check each other's pins on every connection, so such a set
// leaves no leader, and with no leader no later decree can undo it. A rolling
// upgrade adds the new image's pin first and drops the old one once a
// majority of voters run the new image.
func (n *Node) checkPinsKeepMajority(pins []string) error {
	f := n.r().GetConfiguration()
	if err := f.Error(); err != nil {
		return err
	}
	voters, pinned := 0, 0
	for _, s := range f.Configuration().Servers {
		if s.Suffrage != raft.Voter {
			continue
		}
		voters++
		m := n.measurement
		if s.ID != n.id {
			st, err := n.peerStatus(s.Address, 2*time.Second)
			if err != nil {
				continue // unknown counts as unpinned
			}
			m = st.Measurement
		}
		if slices.Contains(pins, m) {
			pinned++
		}
	}
	if pinned*2 <= voters {
		return fmt.Errorf("%w: %d of %d voters run a pinned image", ErrPinsLoseMajority, pinned, voters)
	}
	return nil
}

// ErrPinsLoseMajority refuses a pin set that a majority of voters fail.
var ErrPinsLoseMajority = errors.New("refused: the new pin set leaves fewer than a majority of voters pinned, which would stop the cluster for good; pin the new image beside the running one first")

// ErrRecoverWithQuorum refuses a Recover decree on a cluster that has a
// leader, and so a majority of its voters.
var ErrRecoverWithQuorum = errors.New("refused: the cluster has a leader with a majority of its voters; Recover is break-glass after losing the majority for good")

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
	if err == nil && (d.Kind == UpdateMeasurements || d.Kind == RotateKey) && len(d.Measurements) > 0 {
		err = n.checkPinsKeepMajority(d.Measurements)
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
		minted, err := issuer.NewMeshCA(n.cfg.CACommonName, n.cfg.CAValidity)
		if err != nil {
			n.log.Error("mint mesh CA", "err", err)
			return
		}
		ca := minted.Current().CA
		key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			n.log.Error("encode mesh CA key", "err", err)
			return
		}
		de.RootCert, de.Key = ca.Cert.Raw, key
	}
	resp, err := n.applyEntry(Entry{Kind: KindDecree, Decree: &de})
	if err != nil {
		n.log.Warn("apply decree", "decree", p.Name, "err", err)
		return
	}
	res, _ := resp.(DecreeResult)
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
	if n.r().State() == raft.Leader {
		_, resp, err := n.applyLocal(raw)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)
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
	if n.r().State() == raft.Leader {
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

// Decrees is the record of applied decrees, oldest first (empty while the
// cluster's agreed format is below 2).
func (n *Node) Decrees() []DecreeRecord { return n.fsm.Decrees() }

// PinsDecree is the signed decree behind the current pin set, or nil when
// the pins came from Genesis or from a decree without images.
func (n *Node) PinsDecree() *SignedDecree { return n.fsm.Core().PinsDecree }

// Status is this replica's view of the cluster.
func (n *Node) Status() Status {
	core := n.fsm.Core()
	st := Status{ClusterID: n.cfg.ClusterID, NodeName: n.cfg.NodeName, ID: string(n.id), Joined: core.Joined(),
		Epoch: core.Epoch, Measurement: n.measurement, AppliedIndex: n.fsm.AppliedIndex(),
		Format: core.format(), Reads: n.fsm.readable, Stuck: n.fsm.Stuck(), Seats: n.seats()}
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
	for _, s := range n.servers() {
		if s.Suffrage == raft.Voter {
			st.Voters = append(st.Voters, string(s.ID))
		} else {
			st.NonVoters = append(st.NonVoters, string(s.ID))
		}
	}
	if n.r().State() == raft.Leader {
		st.SeatsFilled = n.seatsFilled()
	}
	return st
}

// seatsFilled (leader): the configuration has Seats voters and none of them
// is failing heartbeats.
func (n *Node) seatsFilled() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	voters := 0
	for _, s := range n.servers() {
		if s.Suffrage != raft.Voter {
			continue
		}
		if _, bad := n.failing[s.ID]; bad && s.ID != n.id {
			return false
		}
		voters++
	}
	return voters >= n.seats()
}

// seats is the voter seat count: the agreed one once a SetVoters decree
// set it, the launch configuration's before.
func (n *Node) seats() int {
	if s := n.fsm.Core().Seats; s > 0 {
		return s
	}
	return n.cfg.Seats
}

// isVoter reports whether this member holds a voter seat.
func (n *Node) isVoter() bool {
	ss := n.servers()
	i := slices.IndexFunc(ss, func(s raft.Server) bool { return s.ID == n.id })
	return i >= 0 && ss[i].Suffrage == raft.Voter
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
	if n.r().State() == raft.Leader {
		return n.seatsFilled()
	}
	at := n.seatsOKAt.Load()
	return at != 0 && time.Since(time.UnixMilli(at)) < 3*n.cfg.Timing.Tick+time.Second
}

// refreshSeats asks the leader whether every seat is filled (non-voters
// only; see Ready).
func (n *Node) refreshSeats() {
	if n.isVoter() {
		return
	}
	addr, _ := n.r().LeaderWithID()
	if addr == "" {
		return
	}
	if st, err := n.peerStatus(addr, time.Second); err == nil && st.SeatsFilled {
		n.seatsOKAt.Store(time.Now().UnixMilli())
	}
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

func (n *Node) leading() bool { return n.r().State() == raft.Leader }

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
