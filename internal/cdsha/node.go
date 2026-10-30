package cdsha

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// Timing are the replica's timers. Apply bounds one replicated write and the
// catch-up a read waits for; Tick is the period of the replica's own loop.
type Timing struct {
	Heartbeat time.Duration
	Election  time.Duration
	Apply     time.Duration
	Tick      time.Duration
	// DeadAfter is how long an answer counts as live. Within it, an address
	// several members answer at belongs to none of them.
	DeadAfter time.Duration
}

// releaseTiming is the timer of every field a caller leaves unset.
var releaseTiming = Timing{
	Heartbeat: time.Second,
	Election:  time.Second,
	Apply:     10 * time.Second,
	Tick:      time.Second,
	DeadAfter: 20 * time.Second,
}

func (t Timing) orRelease() Timing {
	return Timing{
		Heartbeat: cmp.Or(t.Heartbeat, releaseTiming.Heartbeat),
		Election:  cmp.Or(t.Election, releaseTiming.Election),
		Apply:     cmp.Or(t.Apply, releaseTiming.Apply),
		Tick:      cmp.Or(t.Tick, releaseTiming.Tick),
		DeadAfter: cmp.Or(t.DeadAfter, releaseTiming.DeadAfter),
	}
}

// minRaftTimer is the shortest timer Raft takes.
const minRaftTimer = 5 * time.Millisecond

// check refuses the timers Raft refuses, and a tick that outlasts the wait a
// peer gives the next control request. The leader lease is half the heartbeat.
func (t Timing) check() error {
	switch {
	case t.Heartbeat < 2*minRaftTimer:
		return fmt.Errorf("cds-ha: a heartbeat of %s leaves a leader lease below %s", t.Heartbeat, minRaftTimer)
	case t.Election < t.Heartbeat:
		return fmt.Errorf("cds-ha: an election timer of %s is shorter than the %s heartbeat", t.Election, t.Heartbeat)
	case t.Tick >= controlDeadline:
		return fmt.Errorf("cds-ha: a tick of %s outlasts the %s a replica waits for a peer's next control request", t.Tick, controlDeadline)
	}
	return nil
}

// Config is what a replica of a CDS HA cluster runs on. Every field of it
// comes from the measured configuration every replica of the cluster boots.
type Config struct {
	Launch Launch
	// LaunchFile is the configuration file this replica booted; the images it
	// admits are pinned to it.
	LaunchFile []byte
	// Peer is the address this replica's peer port binds, and the one its
	// peers dial.
	Peer netip.AddrPort
	// AttestationURL is the attestation-api on this VM's own loopback.
	AttestationURL string
	Timing         Timing
	// Replicas are the names and addresses the cluster's replicas answer at,
	// as the configuration lists them.
	Replicas []string
	// Resolve answers every address one replica entry names; the system
	// resolver answers where the caller gives none.
	Resolve resolveEntry

	Allowlist *allowlist.Store
	Secrets   *secrets.MemoryStore
	Ledger    *sandboxledger.Ledger
}

// resolve answers every address one replica entry names: the system resolver,
// unless the caller gave another. Every replica of a cluster serves its peers
// on the one port this replica binds, so no entry names a port of its own.
func (c Config) resolve(ctx context.Context, entry string) ([]netip.AddrPort, error) {
	if c.Resolve != nil {
		return c.Resolve(ctx, entry)
	}
	return resolveAtPort(ctx, entry, c.Peer.Port())
}

func (c Config) check() error {
	switch {
	case len(c.LaunchFile) == 0:
		return errors.New("cds-ha: a replica launches with the configuration file it booted")
	case !c.Peer.IsValid() || c.Peer.Addr().IsUnspecified():
		return fmt.Errorf("cds-ha: a replica launches with the address its peers dial, and %q is none", c.Peer)
	case c.Allowlist == nil || c.Secrets == nil || c.Ledger == nil:
		return errors.New("cds-ha: a replica launches with its allowlist, secret and binding stores")
	case len(c.Replicas) == 0:
		return errors.New("cds-ha: a replica launches with the replica set of its cluster")
	}
	return c.Timing.check()
}

// Node is one replica of a CDS HA cluster: the Raft member this process is,
// over the state machine and the stores the log writes.
//
// Every process is a member of its own: the log lives in the replica's
// memory, so a restarted process has forgotten the votes it cast and must
// not cast them again as the member that cast them.
type Node struct {
	cfg      Config
	member   memberID
	attestor attestor
	fsm      *FSM
	logs     *memLog
	snaps    *snapStore
	// identity is read by every handshake and replaced by renewIdentity.
	identity atomic.Pointer[heldIdentity]
	// admitting is the cluster version the connections this replica holds
	// were judged against. Only Run reads and writes it.
	admitting uint64
	// peers is where this replica reached the members of its cluster.
	peers *members
	// discoveryLog keeps a discovery that stays broken to one log line.
	discoveryLog changedReason

	allowlist *allowlist.Handle
	secrets   *secrets.Handle
	bindings  *sandboxledger.Handle

	// Start builds these three and Run stops them.
	raft      *raft.Raft
	mux       *mux
	transport *termSafeHeartbeats
}

// attestationTimeout bounds one call to the attestation-api on this VM.
const attestationTimeout = 10 * time.Second

// memberID is this replica's Raft server id, bound into its peer certificate
// and its Raft address.
type memberID string

func newMemberID() memberID {
	return memberID(rand.Text())
}

func NewNode(cfg Config) (*Node, error) {
	cfg.Timing = cfg.Timing.orRelease()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	attestor, err := newAttestor(cfg.AttestationURL, attestationTimeout)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		member:   newMemberID(),
		attestor: attestor,
		fsm:      NewFSM(cfg.Launch, cfg.Allowlist, cfg.Secrets, cfg.Ledger),
		logs:     newMemLog(),
		snaps:    &snapStore{},
	}
	n.peers = newMembers(string(n.member), cfg.Timing.DeadAfter)
	if err := n.mintIdentity(); err != nil {
		return nil, err
	}
	n.allowlist = cfg.Allowlist.CommittedBy(allowlistWrites(n))
	n.secrets = cfg.Secrets.CommittedBy(secretWrites(n))
	n.bindings = cfg.Ledger.CommittedBy(bindingWrites(n))
	return n, nil
}

// Every mutation through these handles becomes a log entry every replica
// applies.

func (n *Node) Allowlist() *allowlist.Handle {
	return n.allowlist
}

func (n *Node) Secrets() *secrets.Handle {
	return n.secrets
}

func (n *Node) Bindings() *sandboxledger.Handle {
	return n.bindings
}

const (
	peerIdentityLife = 24 * time.Hour
	// renewIdentityAfter is well inside the life, so no peer meets an expired
	// certificate.
	renewIdentityAfter = peerIdentityLife / 4
)

type heldIdentity struct {
	peerIdentity
	mintedAt time.Time
}

func (i heldIdentity) aged() bool {
	return time.Since(i.mintedAt) >= renewIdentityAfter
}

// mintIdentity takes fresh evidence over a fresh key as this process's
// identity.
func (n *Node) mintIdentity() error {
	minted, err := newPeerIdentity(
		n.attestor,
		n.cfg.Launch.ClusterID,
		string(n.member),
		n.cfg.LaunchFile,
		time.Now().Add(peerIdentityLife),
	)
	if err != nil {
		return err
	}
	n.identity.Store(&heldIdentity{
		peerIdentity: minted,
		mintedAt:     time.Now(),
	})
	return nil
}

// renewIdentity leaves a failure to the next tick.
func (n *Node) renewIdentity() {
	if !n.identity.Load().aged() {
		return
	}
	if err := n.mintIdentity(); err != nil {
		slog.Warn("cds-ha: this replica could not renew the evidence its peers admit it by", "error", err)
	}
}

func (n *Node) certificate() *tls.Certificate {
	return &n.identity.Load().certificate
}

// Start opens the peer port and starts Raft; Run drives the replica from there.
func (n *Node) Start() error {
	if n.raft != nil {
		return errors.New("cds-ha: this replica is started")
	}
	listener, err := net.Listen("tcp", n.cfg.Peer.String())
	if err != nil {
		return err
	}
	config := n.raftConfig()
	n.mux = newMux(
		listener,
		n.answeringAt(listener),
		n.certificate,
		n.verifier(),
		n.answerControl,
	)
	n.transport = newTermSafeHeartbeats(
		raft.NewNetworkTransportWithConfig(peerTransportConfig(n.mux, config.Logger)),
	)
	started, err := raft.NewRaft(config, raftFSM{FSM: n.fsm}, n.logs, n.logs, n.snaps, n.transport)
	if err != nil {
		n.transport.Close()
		return err
	}
	n.transport.follows(started)
	n.raft = started
	// A control request is answered out of this replica's Raft, so the port
	// takes none before there is one.
	n.mux.serving()
	return nil
}

// answeringAt is the Raft address peers dial this replica at.
func (n *Node) answeringAt(listener net.Listener) raftAddr {
	return raftAddr{
		endpoint: listener.Addr().(*net.TCPAddr).AddrPort(),
		member:   string(n.member),
	}
}

func (n *Node) verifier() peerVerifier {
	return peerVerifier{
		clusterID: n.cfg.Launch.ClusterID,
		attestor:  n.attestor,
		admits:    n.admits,
	}
}

// admitsNobody is the image set that admits no peer.
var admitsNobody []remote.ImagePin

// admits is the cluster's CDS image set once it holds one, and this replica's
// own image until then.
func (n *Node) admits() []remote.ImagePin {
	core := n.fsm.ClusterState()
	if !core.Joined() {
		return []remote.ImagePin{n.identity.Load().self}
	}
	images, err := clusterImages(core, n.cfg.LaunchFile)
	if err != nil {
		slog.Error("cds-ha: this replica admits no peer: the cluster's CDS images are none of this launch file's", "error", err)
		return admitsNobody
	}
	return images
}

// clusterImages are the images of the cluster's pin decree, bound to the
// launch file this replica boots.
func clusterImages(core ClusterState, launchFile []byte) ([]remote.ImagePin, error) {
	if core.PinsDecree == nil || core.PinsDecree.Decree.CDSPins == nil {
		return nil, errors.New("the cluster pins no CDS image")
	}
	images, err := core.PinsDecree.Decree.CDSPins.WithLaunchFile(launchFile)
	if err != nil {
		return nil, err
	}
	return images.Images, nil
}

// The log lives in the replica's memory until a snapshot lets Raft compact
// it, and Raft compacts only at a check, so a replica snapshots on fewer
// entries and checks more often than Raft's defaults.
const (
	snapshotThreshold = 512
	trailingLogs      = 256
	snapshotInterval  = 30 * time.Second
)

func (n *Node) raftConfig() *raft.Config {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(n.member)
	config.HeartbeatTimeout = n.cfg.Timing.Heartbeat
	config.ElectionTimeout = n.cfg.Timing.Election
	config.LeaderLeaseTimeout = n.cfg.Timing.Heartbeat / 2
	config.SnapshotThreshold = snapshotThreshold
	config.TrailingLogs = trailingLogs
	config.SnapshotInterval = snapshotInterval
	config.Logger = raftLogger()
	return config
}

// raftLogger carries Raft's warnings into this process's log.
func raftLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:        "cds-ha raft",
		Level:       hclog.Warn,
		DisableTime: true,
		Output:      slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn).Writer(),
	})
}

// Run drives the replica until ctx ends, then stops Raft and closes the peer
// port.
func (n *Node) Run(ctx context.Context) error {
	if n.raft == nil {
		return errors.New("cds-ha: this replica is not started")
	}
	defer n.stop()
	stopReaching := n.reachingMembers(ctx)
	defer stopReaching()
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	n.admitting = n.fsm.ClusterState().Version
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		n.renewIdentity()
		n.recheckPeers()
	}
}

// reachingMembers runs the membership loop on a goroutine of its own, so a
// dial that waits on the network holds up no other duty of the replica.
func (n *Node) reachingMembers(ctx context.Context) (stopReaching func()) {
	reaching, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.reachMembers(reaching)
	}()
	return func() {
		stop()
		<-done
	}
}

// recheckPeers judges the connections again once the cluster's state moved: a
// peer admitted at its handshake may not be admitted any more.
func (n *Node) recheckPeers() {
	version := n.fsm.ClusterState().Version
	if version == n.admitting {
		return
	}
	n.admitting = version
	n.mux.recheck()
}

func (n *Node) stop() {
	if err := n.raft.Shutdown().Error(); err != nil {
		slog.Error("cds-ha: this replica's Raft did not shut down", "error", err)
	}
	if err := n.transport.Close(); err != nil {
		slog.Error("cds-ha: this replica's peer port did not close", "error", err)
	}
}

// propose commits one entry and answers what the state machine made of it.
// This replica must be the cluster's leader, which is what appends to the log.
func (n *Node) propose(e Entry) (Result, error) {
	entry, err := json.Marshal(e)
	if err != nil {
		return Result{}, err
	}
	if err := n.proposable(e, entry); err != nil {
		return Result{}, err
	}
	committed := n.raft.Apply(entry, n.cfg.Timing.Apply)
	if err := committed.Error(); err != nil {
		return Result{}, err
	}
	res, applied := committed.Response().(Result)
	if !applied {
		return Result{}, fmt.Errorf("cds-ha: the state machine answered a %T", committed.Response())
	}
	// A stop leaves the store command's result incomplete.
	if res.Stop != nil {
		return Result{}, res.Stop
	}
	return res, nil
}

// proposable refuses an entry this replica must not put on the log.
func (n *Node) proposable(e Entry, entry []byte) error {
	if e.Kind != KindDecree && !n.fsm.ClusterState().Joined() {
		return errors.New("cds-ha: this replica holds no cluster")
	}
	if reason := n.fsm.Stuck(); reason != "" {
		return errors.New("cds-ha: this replica stopped following the log: " + reason)
	}
	return n.fsm.Admit(entry)
}

const appliedPoll = 2 * time.Millisecond

// appliedKnownCommitted waits for this replica to apply every entry it knows
// the cluster committed. A replica hearing no leader knows only what it heard
// last.
func (n *Node) appliedKnownCommitted(within time.Duration) bool {
	committed := n.raft.CommitIndex()
	deadline := time.Now().Add(within)
	for n.fsm.AppliedIndex() < committed {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(appliedPoll)
	}
	return true
}
