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
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// Timing are the replica's timers. Apply bounds one replicated write and the
// catch-up a read waits for; Tick is the period of the replica's own loop.
type Timing struct {
	Heartbeat time.Duration
	Election  time.Duration
	// Lease is how long a replica answers reads under one watermark its
	// leader confirmed. It confirms another at a third of it.
	Lease time.Duration
	Apply time.Duration
	Tick  time.Duration
	// DeadAfter is how long an answer counts as live. Within it, an address
	// several members answer at belongs to none of them.
	DeadAfter time.Duration
	// Checkpoint is how often the leader asks every replica to record the
	// digest of its state (divergence.go).
	Checkpoint time.Duration
}

// releaseTiming is the timer of every field a caller leaves unset.
var releaseTiming = Timing{
	Heartbeat:  time.Second,
	Election:   time.Second,
	Lease:      5 * time.Second,
	Apply:      10 * time.Second,
	Tick:       time.Second,
	DeadAfter:  20 * time.Second,
	Checkpoint: 10 * time.Second,
}

func (t Timing) orRelease() Timing {
	return Timing{
		Heartbeat:  cmp.Or(t.Heartbeat, releaseTiming.Heartbeat),
		Election:   cmp.Or(t.Election, releaseTiming.Election),
		Lease:      cmp.Or(t.Lease, releaseTiming.Lease),
		Apply:      cmp.Or(t.Apply, releaseTiming.Apply),
		Tick:       cmp.Or(t.Tick, releaseTiming.Tick),
		DeadAfter:  cmp.Or(t.DeadAfter, releaseTiming.DeadAfter),
		Checkpoint: cmp.Or(t.Checkpoint, releaseTiming.Checkpoint),
	}
}

// minRaftTimer is the shortest timer Raft takes.
const minRaftTimer = 5 * time.Millisecond

// check refuses the timers Raft refuses, a tick that outlasts the wait a peer
// gives the next control request, and a read lease the replica's own loop
// cannot confirm a read within. The leader lease is half the heartbeat.
func (t Timing) check() error {
	switch {
	case t.Heartbeat < 2*minRaftTimer:
		return fmt.Errorf("cds-ha: a heartbeat of %s leaves a leader lease below %s", t.Heartbeat, minRaftTimer)
	case t.Election < t.Heartbeat:
		return fmt.Errorf("cds-ha: an election timer of %s is shorter than the %s heartbeat", t.Election, t.Heartbeat)
	case t.Tick >= controlDeadline:
		return fmt.Errorf("cds-ha: a tick of %s outlasts the %s a replica waits for a peer's next control request", t.Tick, controlDeadline)
	case t.Lease < 3*t.Tick:
		return fmt.Errorf("cds-ha: a read lease of %s is not three turns of a %s loop", t.Lease, t.Tick)
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
	// genesisCA is the mesh CA this process installs if a Genesis decree
	// names it, minted once.
	genesisCA func() (*issuer.CA, error)
	// posted are the decrees the operator posted to this replica and it has
	// yet to act on.
	posted postedDecrees
	// decreedImages are admitted until this replica joins a cluster.
	decreedImages atomic.Pointer[[]remote.ImagePin]
	// These keep a condition that holds tick after tick to one log line.
	discoveryLog changedReason
	genesisLog   changedReason
	joinLog      changedReason
	admitLog     changedReason
	formatLog    changedReason
	stuckLog     changedReason

	// failures, transfers and refusals carry a leader's judgement of its
	// members between passes (liveness.go, handoff.go, barriers.go).
	failures  *heartbeatFailures
	transfers *transfers
	refusals  barrierRefusals
	// Only Run writes stuckAlarmed (stuck.go).
	stuckAlarmed time.Time

	// lease is the read lease this replica answers reads under, and outage
	// is why it has none (lease.go). barriers holds the one barrier a leader
	// has in flight, and clockJumps counts the clock jumps this replica saw.
	lease      atomic.Pointer[readLease]
	outage     atomic.Pointer[readOutage]
	barriers   oneBarrier
	clockJumps atomic.Uint64
	// servingSince and seatbook carry the seat duty between passes
	// (serving.go, seats.go).
	servingSince servingState
	seatbook     *seatBook
	// div is what this replica, while it leads, makes of its members' digest
	// reports (divergence.go).
	div divergence

	allowlist *allowlist.Handle
	secrets   *secrets.Handle
	bindings  *sandboxledger.Handle

	// Start builds these three and Run stops them.
	raft      *raft.Raft
	mux       *mux
	transport *termSafeHeartbeats
	// divergenceLog keeps one finding about its members' state to one log
	// line (divergence.go).
	divergenceLog changedReason
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
		cfg:       cfg,
		member:    newMemberID(),
		attestor:  attestor,
		fsm:       NewFSM(cfg.Launch, cfg.Allowlist, cfg.Secrets, cfg.Ledger),
		logs:      newMemLog(),
		snaps:     &snapStore{},
		genesisCA: sync.OnceValues(mintMeshCA),
		barriers:  newOneBarrier(),
		seatbook:  newSeatBook(),
		failures:  newHeartbeatFailures(),
		transfers: newTransfers(),
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

// admits is the images this replica admits a peer by: the cluster's CDS image
// set once it holds one, and its own image, with whatever an Admit decree
// names for it, until then.
func (n *Node) admits() []remote.ImagePin {
	core := n.fsm.ClusterState()
	if !core.Joined() {
		return n.admitsBeforeJoining()
	}
	images, err := clusterImages(core, n.cfg.LaunchFile)
	if err != nil {
		slog.Error("cds-ha: this replica admits no peer: the cluster's CDS images are none of this launch file's", "error", err)
		return admitsNobody
	}
	return images
}

// admitsBeforeJoining adds the images an Admit decree names for this replica,
// so a replica of a new image reaches a cluster still running the old one.
func (n *Node) admitsBeforeJoining() []remote.ImagePin {
	own := []remote.ImagePin{n.identity.Load().self}
	decreed := n.decreedImages.Load()
	if decreed == nil {
		return own
	}
	return append(own, *decreed...)
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

// Run drives the replica until ctx ends: it keeps the lease it answers reads
// under and the evidence its peers admit it by fresh, and judges the
// connections it holds again whenever the cluster's image set may have
// changed. It returns before ctx ends on a fault this replica cannot serve
// through (stuck.go), which the restart of this process cures. It stops Raft
// and closes the peer port before it returns.
func (n *Node) Run(ctx context.Context) error {
	if n.raft == nil {
		return errors.New("cds-ha: this replica is not started")
	}
	defer n.stop()
	stopWorkers := startWorkers(ctx,
		n.reachMembers,
		n.keepCluster,
		n.keepSeating,
		n.watchHeartbeats,
		n.watchHandover,
		n.watchStalls,
		n.watchDivergence,
	)
	defer stopWorkers()
	stopReads := n.serveReads(ctx)
	defer stopReads()
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
		if err := n.endsAtAFault(); err != nil {
			return err
		}
	}
}

// Answers with the function that ends every loop and waits for it.
func startWorkers(ctx context.Context, loops ...func(context.Context)) (endAndWait func()) {
	ending := make([]func(), 0, len(loops))
	for _, loop := range loops {
		ending = append(ending, onItsOwn(ctx, loop))
	}
	return func() {
		for _, end := range ending {
			end()
		}
	}
}

// onItsOwn runs one loop of the replica on a goroutine of its own, so work
// that waits on the network holds up no other duty of the replica.
func onItsOwn(ctx context.Context, loop func(context.Context)) (endAndWait func()) {
	running, end := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		loop(running)
	}()
	return func() {
		end()
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
	n.shutDownRaft()
	if err := n.transport.Close(); err != nil {
		slog.Error("cds-ha: this replica's peer port did not close", "error", err)
	}
}

// A state machine held on a command never lets Raft's goroutines return. The
// peer port closes after the wait either way, which is what they then fail on.
func (n *Node) shutDownRaft() {
	stopped := make(chan error, 1)
	go func() {
		stopped <- n.raft.Shutdown().Error()
	}()
	select {
	case err := <-stopped:
		if err != nil {
			slog.Error("cds-ha: this replica's Raft did not shut down", "error", err)
		}
	case <-time.After(n.cfg.Timing.Apply):
		slog.Error("cds-ha: this replica's Raft did not shut down; its goroutines are left running",
			"waited", n.cfg.Timing.Apply)
	}
}

// propose commits one entry and answers what the state machine made of it.
// Only the leader appends to the log, so a client write taken anywhere else
// is handed to it, and an entry that is the leader's own is refused here.
func (n *Node) propose(e Entry) (Result, error) {
	entry, err := json.Marshal(e)
	if err != nil {
		return Result{}, err
	}
	if err := n.proposable(e, entry); err != nil {
		return Result{}, err
	}
	if n.leading() {
		res, _, err := n.commit(entry)
		return res, err
	}
	if leadersOwn(e) {
		return Result{}, errors.New("cds-ha: this replica does not lead the cluster")
	}
	return n.forward(entry)
}

// commit appends an entry to the log of the cluster this replica leads, and
// answers the index it applied at.
func (n *Node) commit(entry []byte) (Result, uint64, error) {
	committed := n.raft.Apply(entry, n.cfg.Timing.Apply)
	if err := committed.Error(); err != nil {
		return Result{}, 0, err
	}
	res, applied := committed.Response().(Result)
	if !applied {
		return Result{}, 0, fmt.Errorf("cds-ha: the state machine answered a %T", committed.Response())
	}
	// A stop leaves the store command's result incomplete.
	if res.Stop != nil {
		return Result{}, 0, res.Stop
	}
	return res, committed.Index(), nil
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

func (n *Node) awaitApplied(index uint64, within time.Duration) bool {
	return await(within, func() bool { return n.fsm.AppliedIndex() >= index })
}

// await waits for cond, asking again until within has passed.
func await(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(appliedPoll)
	}
	return true
}
