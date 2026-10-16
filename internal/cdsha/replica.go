package cdsha

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

var haEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "cds_ha_events_total",
	Help: "CDS HA named conditions (spec §16), by reason.",
}, []string{"reason"})

// Timing holds the §17 parameters.
type Timing struct {
	Heartbeat     time.Duration
	LeaseDuration time.Duration
	AckTimeout    time.Duration
}

// DefaultTiming is the spec's indicative defaults.
var DefaultTiming = Timing{Heartbeat: 2 * time.Second, LeaseDuration: 15 * time.Second, AckTimeout: 10 * time.Second}

// Validate enforces P1.
func (t Timing) Validate() error {
	if t.Heartbeat <= 0 || t.Heartbeat >= t.LeaseDuration || t.AckTimeout <= 0 {
		return errors.New("timing must satisfy 0 < heartbeat < lease_duration and ack_timeout > 0 (P1)")
	}
	// The Lease stores whole seconds; a fractional duration is truncated and
	// a sub-second one becomes 0, which lets every candidate take the Lease.
	if t.LeaseDuration%time.Second != 0 {
		return errors.New("lease_duration must be a whole number of seconds")
	}
	return nil
}

// Config of one replica.
type Config struct {
	ClusterID       string
	Identity        string                                  // lease holder identity, e.g. pod name
	ListenAddr      string                                  // peer API listen address, host:port
	Peers           func(context.Context) ([]string, error) // other replicas, host:port
	Attestor        Attestor
	BakedPins       []string // replica pins compiled into the image (§2.1)
	OperatorPubKey  []byte   // PKIX DER or nil (G5)
	Kube            kubernetes.Interface
	Namespace       string
	DecreeNamespace string // where operators write decrees; "" = Namespace
	CACommonName    string
	CAValidity      time.Duration
	Timing          Timing
	Logger          *slog.Logger
}

// Replica runs the HA protocol for one CDS instance.
type Replica struct {
	cfg         Config
	measurement string // own, from our own evidence
	anchor      string // own launch-key binding, from our own evidence
	log         *slog.Logger
	store       Store
	verifier    peerVerifier
	client      peerClient

	mu          sync.Mutex
	state       State
	ca          *issuer.CA
	serving     bool
	retired     bool              // own measurement left the pin set (Q3 interim)
	behindOf    uint64            // a verified epoch we saw but hold no key for; 0 = none
	peerErrs    map[string]string // last problem logged per peer (notePeer)
	lastContact time.Time
	hiTerm      uint64 // L6, W5
	writerTerm  uint64
	isWriter    bool
	eligible    bool // W1: may contend for the Lease
	elector     *leaderelection.LeaderElector
	stepDown    context.CancelFunc // releases the Lease
	minted      int                // genesis count, for tests
}

// New validates cfg and builds a replica. Run starts it.
func New(cfg Config) (*Replica, error) {
	if cfg.ClusterID == "" || cfg.Attestor == nil || cfg.Kube == nil || cfg.Peers == nil {
		return nil, errors.New("cdsha: cluster id, attestor, kube client and peer discovery are required")
	}
	if len(cfg.BakedPins) == 0 {
		return nil, errors.New("cdsha: the baked replica pin set must not be empty")
	}
	if len(cfg.OperatorPubKey) == 0 {
		return nil, errors.New("cdsha: an operator public key is required (genesis and every change are operator decrees)")
	}
	if err := cfg.Timing.Validate(); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	self, err := ownClaims(cfg.Attestor)
	if err != nil {
		return nil, err
	}
	r := &Replica{
		cfg:         cfg,
		measurement: self.Measurement,
		anchor:      self.Anchor,
		log:         cfg.Logger.With("component", "cds-ha", "cluster_id", cfg.ClusterID),
		store:       Store{Client: cfg.Kube, Namespace: cfg.Namespace, DecreeNamespace: cfg.DecreeNamespace, ClusterID: cfg.ClusterID},
	}
	r.verifier = peerVerifier{clusterID: cfg.ClusterID, att: cfg.Attestor, pins: r.pins, anchor: self.Anchor}
	r.log.Info("cds-ha replica identity", "measurement", self.Measurement, "anchor", self.Anchor)
	return r, nil
}

// ownClaims reads our measurement and anchor from our own evidence, so they
// are the TEE's word rather than launch flags.
func ownClaims(att Attestor) (Claims, error) {
	ev, err := att.Evidence([48]byte{})
	if err != nil {
		return Claims{}, fmt.Errorf("cdsha: own evidence: %w", err)
	}
	c, err := att.Verify(ev)
	if err != nil {
		return Claims{}, fmt.Errorf("cdsha: own evidence: %w", err)
	}
	return c, nil
}

// pins is the set peers are checked against: the accepted tail's once
// joined (L2); nil while cold (see peerVerifier and syncFrom).
func (r *Replica) pins() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.state.Chain) == 0 {
		return nil
	}
	return r.state.Chain.Tail().Measurements
}

func (r *Replica) snapshot() (State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state, r.serving
}

// Heartbeat is this replica's public position.
func (r *Replica) Heartbeat() Heartbeat {
	st, serving := r.snapshot()
	hb := heartbeatOf(st, serving, r.cfg.ClusterID)
	hb.Measurement = r.measurement
	return hb
}

// CA returns the mesh CA to issue with. It fails while the replica is a
// candidate or retired (L3, L4); every serving replica may issue (L5).
func (r *Replica) CA() (*issuer.CA, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.serving || r.ca == nil {
		return nil, errors.New("cds-ha: replica is not serving (no current mesh CA key)")
	}
	return r.ca, nil
}

func (r *Replica) event(reason string, kv ...any) {
	haEvents.WithLabelValues(reason).Inc()
	r.log.Info("cds-ha event", append([]any{"reason", reason}, kv...)...)
}

// Run serves the peer API and drives the replica until ctx ends. It returns
// only after its goroutines have stopped (the Lease is released on the way).
func (r *Replica) Run(ctx context.Context) error {
	cert, err := newPeerCert(r.cfg.ClusterID, r.cfg.Attestor)
	if err != nil {
		return err
	}
	tlsCfg := r.verifier.tlsConfig(cert)
	r.client = newPeerClient(tlsCfg, r.verifier, r.cfg.Timing)
	ln, err := net.Listen("tcp", r.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("cds-ha peer listener: %w", err)
	}
	srv := &http.Server{
		Handler:           r.peerHandler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		// Refused handshakes (wrong cluster, unpinned peer) are expected noise.
		ErrorLog: slog.NewLogLogger(r.log.Handler(), slog.LevelDebug),
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
			r.log.Error("peer server stopped", "err", err)
		}
	})
	wg.Go(func() { r.leaseLoop(ctx) })
	defer wg.Wait()
	defer srv.Close()
	t := time.NewTicker(r.cfg.Timing.Heartbeat)
	defer t.Stop()
	for {
		r.tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// tick is one heartbeat round: learn from peers and CDSEpoch (E6), update
// the serving decision (L4), then act as writer if we hold the Lease.
func (r *Replica) tick(ctx context.Context) {
	// CDSEpoch first: it is how a replica cut off from its peers learns of
	// a rotation, and peer discovery can block (DNS servers on unreachable
	// nodes), which kept a partitioned replica serving the old key for ~35 s
	// on real hardware.
	r.pollEpoch(ctx)
	peers, reached := r.heartbeatPeers(ctx)
	r.updateServing()
	r.updateEligible(reached)
	if term, ok := r.writer(); ok {
		r.writerTick(ctx, term, peers)
	}
}

type peerResult struct {
	addr string
	hb   Heartbeat
	err  error
}

// heartbeatPeers polls every peer in parallel (H1) and syncs from any that
// is ahead (H2). reached reports whether at least one attested peer
// answered this round.
func (r *Replica) heartbeatPeers(ctx context.Context) ([]string, bool) {
	dctx, cancel := context.WithTimeout(ctx, r.cfg.Timing.Heartbeat)
	peers, err := r.cfg.Peers(dctx)
	cancel()
	if err != nil {
		r.log.Warn("peer discovery failed", "err", err)
		return nil, false
	}
	results := make([]peerResult, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Go(func() {
			hb, err := r.client.heartbeat(ctx, p)
			results[i] = peerResult{addr: p, hb: hb, err: err}
		})
	}
	wg.Wait()
	results = slices.DeleteFunc(results, func(res peerResult) bool { return errors.Is(res.err, errSelf) })
	peers = peers[:0]
	reached := false
	for _, res := range results {
		peers = append(peers, res.addr)
		if res.err != nil {
			r.notePeer(res.addr+" heartbeat", "peer not reached", res.err)
			continue
		}
		reached = true
		r.notePeer(res.addr+" heartbeat", "", nil)
		r.compare(ctx, res.addr, res.hb)
	}
	return peers, reached
}

func (r *Replica) compare(ctx context.Context, peer string, hb Heartbeat) {
	if !hb.Joined || hb.ClusterID != r.cfg.ClusterID {
		return
	}
	local, _ := r.snapshot()
	if len(local.Chain) == 0 || local.Chain.Tuple().Less(hb.Tuple()) {
		err := r.syncFrom(ctx, peer)
		if errors.Is(err, ErrNotNewer) {
			err = nil
		}
		r.notePeer(peer+" sync", "sync failed", err)
		return
	}
	if hb.Tuple().Less(local.Chain.Tuple()) {
		r.event("StalePeer", "peer", peer, "peer_epoch", hb.Epoch, "peer_term", hb.Term) // H3
	}
}

// syncFrom pulls the chain and key from peer (E2, K). On a cold start the
// source must be pinned by the chain it hands over (Q2 interim): an unpinned
// replica that still passes our baked pins cannot feed a cold replica its
// own history. A joined replica only extends its own chain, whose previous
// epoch pinned the source, so a writer may hand over the epoch that unpins it.
func (r *Replica) syncFrom(ctx context.Context, peer string) error {
	offer, sourceMeasurement, err := r.client.sync(ctx, peer)
	if err != nil {
		return err
	}
	if err := offer.Chain.Verify(r.cfg.ClusterID); err != nil {
		return err
	}
	if local, _ := r.snapshot(); len(local.Chain) == 0 {
		tail := offer.Chain.Tail().Measurements
		if !slices.Contains(tail, sourceMeasurement) {
			return fmt.Errorf("peer %s is not pinned by the chain it offers", peer)
		}
		// Cold: the operator must have pinned us too, so only a chain
		// decreed after our image was accepted can bring us in.
		if !slices.Contains(tail, r.measurement) {
			return fmt.Errorf("the chain peer %s offers does not pin this replica", peer)
		}
	}
	return r.accept(offer, "peer "+peer)
}

// accept moves to offer if Next allows it.
func (r *Replica) accept(offer State, source string) error {
	return r.acceptAs(offer, source, true)
}

// acceptAs is accept; retire=false lets a writer finish handing over an
// epoch that excludes it before it retires (applyDecree).
func (r *Replica) acceptAs(offer State, source string, retire bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next, _, err := Next(r.state, offer, r.cfg.ClusterID)
	if errors.Is(err, ErrFork) {
		r.event("ForkDetected", "source", source, "local_epoch", r.state.Chain.Tail().Epoch, "offered_epoch", offer.Chain.Tail().Epoch)
	}
	if err != nil {
		return err
	}
	tail := next.Chain.Tail()
	_, cert, err := tail.RootPublicKey()
	if err != nil {
		return err
	}
	ca, err := issuer.WrapCA(cert, next.Key)
	if err != nil {
		return fmt.Errorf("epoch %d mesh CA unusable: %w", tail.Epoch, err)
	}
	r.state, r.ca = next, ca // D16: the old epoch's CA is dropped here
	r.hiTerm = max(r.hiTerm, tail.Term)
	r.log.Info("accepted epoch", "epoch", tail.Epoch, "term", tail.Term, "source", source,
		"key_fingerprint", heartbeatOf(next, true, r.cfg.ClusterID).KeyFingerprint, "pins", len(tail.Measurements))
	if slices.Contains(tail.Measurements, r.measurement) {
		r.retired = false
	} else if retire {
		r.retireLocked()
	}
	return nil
}

// retireLocked is the Q3 interim rule: a replica whose own measurement is no
// longer pinned drops its key, stops serving and leaves the Lease, so the
// next RotateKey is applied by, and only reaches, pinned replicas (D13).
// Go cannot guarantee the dropped key is zeroized.
func (r *Replica) retireLocked() {
	if len(r.state.Chain) == 0 || slices.Contains(r.state.Chain.Tail().Measurements, r.measurement) {
		return
	}
	r.state.Key, r.ca, r.serving, r.retired = nil, nil, false, true
	if r.stepDown != nil {
		r.stepDown()
	}
	haEvents.WithLabelValues("Retired").Inc()
	r.log.Warn("cds-ha event", "reason", "Retired", "epoch", r.state.Chain.Tail().Epoch, "measurement", r.measurement)
}

// pollEpoch reads CDSEpoch (E6). A verified record that extends our chain
// by one epoch with the same root is accepted: we already hold its key, and
// its embedded operator decree proves the change. This is how a replica that
// an UpdateMeasurements excludes learns it must retire, since excluded
// replicas can no longer sync from peers. Anything else ahead waits for an
// attested peer (E3). Lower records are rollbacks (E5).
//
// A successful read is contact for L4, as the spec words it ("any peer or
// the API server"). Residual (review F7): a replica cut off from every peer
// but not from the API server keeps serving its last epoch. The alternative,
// peers only, would stop the last surviving pinned replica. The spec owner
// decides; see outbox/spec-suggestions.md.
func (r *Replica) pollEpoch(ctx context.Context) {
	rec, _, err := r.store.GetEpoch(ctx)
	if err != nil {
		r.log.Debug("read CDSEpoch failed", "err", err)
		return
	}
	r.mu.Lock()
	r.lastContact = time.Now()
	local := r.state
	r.mu.Unlock()
	if rec == nil || len(local.Chain) == 0 {
		return
	}
	lt := local.Chain.Tuple()
	recT := Tuple{Epoch: rec.Record.Epoch, Term: rec.Record.Term, Hash: rec.Hash()}
	switch {
	case recT.Less(lt):
		r.event("RollbackDetected", "stored_epoch", recT.Epoch, "local_epoch", lt.Epoch)
	case rec.Record.Epoch == lt.Epoch+1:
		cand := append(slices.Clone(local.Chain), *rec)
		if err := r.accept(State{Chain: cand}, "CDSEpoch"); err != nil {
			r.log.Debug("CDSEpoch not accepted directly", "err", err)
			// A verified next epoch we cannot adopt is a rotation whose key
			// we do not hold. Stop issuing under the old key until a peer
			// hands us the new one (D16). Only our own key can have signed
			// it, so the control plane cannot forge this signal.
			if cand.Verify(r.cfg.ClusterID) == nil {
				r.markBehind(rec.Record.Epoch)
			}
		}
	}
}

// markBehind records that a verified newer epoch exists that we cannot serve.
func (r *Replica) markBehind(epoch uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.behindOf != epoch {
		haEvents.WithLabelValues("BehindRotation").Inc()
		r.log.Warn("cds-ha event", "reason", "BehindRotation", "local_epoch", r.state.Chain.Tail().Epoch, "seen_epoch", epoch)
	}
	r.behindOf = epoch
}

// updateServing applies L3/L4: serve only with a key, recent contact, and
// no verified newer epoch we lack the key for.
func (r *Replica) updateServing() {
	r.mu.Lock()
	defer r.mu.Unlock()
	behind := r.behindOf != 0 && len(r.state.Chain) > 0 && r.state.Chain.Tail().Epoch < r.behindOf
	serving := r.state.Joined() && !r.retired && !behind && time.Since(r.lastContact) <= r.cfg.Timing.LeaseDuration
	if serving != r.serving {
		r.log.Info("serving state changed", "serving", serving)
	}
	r.serving = serving
}

// updateEligible applies W1: contend for the Lease only while serving, or
// while unjoined and able to see peers (or alone). Otherwise a keyless or
// unpinned replica could hold the Lease and stall every decree. A writer
// that stops being eligible releases the Lease.
func (r *Replica) updateEligible(reached bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Unjoined: contend only if no reached peer holds a key (else we would
	// sync, not mint). The Genesis decree, not a timer, authorizes minting.
	r.eligible = r.serving || (len(r.state.Chain) == 0 && reached)
	if !r.eligible && r.isWriter && r.stepDown != nil {
		r.log.Info("releasing the writer lease: not eligible (W1)")
		r.stepDown()
	}
}

// writer reports our term while we hold the Lease. IsLeader is asked each
// time, so a stale callback cannot leave us acting as writer (W4).
func (r *Replica) writer() (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.isWriter || r.elector == nil || !r.elector.IsLeader() {
		return 0, false
	}
	return r.writerTerm, true
}

func (r *Replica) stillWriter(term uint64) bool {
	t, ok := r.writer()
	return ok && t == term
}

// leaseLoop contends for the writer Lease (§7). The Lease is a liveness
// signal and term dispenser only (O11). Only an eligible replica contends.
func (r *Replica) leaseLoop(ctx context.Context) {
	name := "cds-ha-" + r.cfg.ClusterID
	t := r.cfg.Timing
	for ctx.Err() == nil {
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock: &resourcelock.LeaseLock{
				LeaseMeta:  metav1.ObjectMeta{Name: name, Namespace: r.cfg.Namespace},
				Client:     r.cfg.Kube.CoordinationV1(),
				LockConfig: resourcelock.ResourceLockConfig{Identity: r.cfg.Identity},
			},
			LeaseDuration:   t.LeaseDuration,
			RenewDeadline:   t.LeaseDuration * 2 / 3,
			RetryPeriod:     t.Heartbeat,
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: r.onLeading,
				OnStoppedLeading: r.onStopped,
			},
		})
		if err != nil {
			r.log.Error("leader elector", "err", err)
			return
		}
		lctx, cancel := context.WithCancel(ctx)
		r.mu.Lock()
		eligible := r.eligible && !r.retired
		r.elector, r.stepDown = le, cancel
		r.mu.Unlock()
		if eligible {
			le.Run(lctx)
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-time.After(t.Heartbeat):
		}
	}
}

// onLeading records term = leaseTransitions (W3) if the Lease still names
// us, refusing a term below one already seen (W5). client-go cancels ctx
// before OnStoppedLeading runs, so checking ctx under the lock means a late
// callback cannot mark us writer after we stopped.
func (r *Replica) onLeading(ctx context.Context) {
	lease, err := r.cfg.Kube.CoordinationV1().Leases(r.cfg.Namespace).Get(ctx, "cds-ha-"+r.cfg.ClusterID, metav1.GetOptions{})
	if err != nil || lease.Spec.LeaseTransitions == nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != r.cfg.Identity {
		r.log.Warn("cannot read our lease term; not acting as writer", "err", err)
		return
	}
	term := uint64(max(*lease.Spec.LeaseTransitions, 0))
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	if term < r.hiTerm {
		haEvents.WithLabelValues("LeaseRollback").Inc()
		r.log.Warn("cds-ha event", "reason", "LeaseRollback", "lease_term", term, "highest_term", r.hiTerm)
		return
	}
	if !r.eligible || r.retired {
		// W1: we stopped being eligible while acquiring. Give it back now
		// rather than at the next tick, which may be blocked in awaitAcks.
		r.log.Info("releasing the writer lease: not eligible (W1)")
		if r.stepDown != nil {
			r.stepDown()
		}
		return
	}
	r.hiTerm, r.writerTerm, r.isWriter = term, term, true
	r.log.Info("became writer", "term", term)
}

// onStopped is W4: stop writing at once; issuance continues.
func (r *Replica) onStopped() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isWriter {
		r.log.Info("lost writer lease", "term", r.writerTerm)
	}
	r.isWriter, r.writerTerm = false, 0
}

// newMeshCA mints a fresh random mesh CA (G1, D12). Never derived from an old key.
func (r *Replica) newMeshCA() (*issuer.CA, error) {
	return issuer.NewCAWithCurve(r.cfg.CACommonName, r.cfg.CAValidity, elliptic.P384())
}

var portRE = regexp.MustCompile(`:[0-9]+`)

// notePeer logs a peer problem at Info when it first appears or changes, and
// once when it clears, so an operator sees why replicas do not join (for
// example an unpinned image) without debug logging or log floods.
func (r *Replica) notePeer(peer, what string, err error) {
	msg := ""
	if err != nil {
		// Ephemeral ports differ on every attempt; they are not a new problem.
		msg = what + ": " + portRE.ReplaceAllString(err.Error(), ":")
	}
	r.mu.Lock()
	if r.peerErrs == nil {
		r.peerErrs = map[string]string{}
	}
	prev := r.peerErrs[peer]
	if msg == prev || (err == nil && prev == "") {
		r.mu.Unlock()
		return
	}
	if err == nil {
		delete(r.peerErrs, peer)
	} else {
		r.peerErrs[peer] = msg
	}
	r.mu.Unlock()
	if err == nil {
		r.log.Info("peer problem cleared", "peer", peer)
		return
	}
	r.log.Info(what, "peer", peer, "err", err)
}
