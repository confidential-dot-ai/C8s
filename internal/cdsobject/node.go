// Package cdsobject is an opt-in CDS HA pilot. It reuses the Raft backend's
// state machine and command results, with an encrypted object WAL as authority.
package cdsobject

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const operationTimeout = 5 * time.Second

type Provision struct {
	Key           []byte                `json:"key,omitempty"`
	Grant         *cdsrecovery.Grant    `json:"grant,omitempty"`
	Credentials   objectwal.Credentials `json:"credentials"`
	MetadataToken string                `json:"metadata_token,omitempty"`
}

type Config struct {
	Launch    cdsha.Launch
	Storage   cdsconfig.ObjectWALPilot
	Allowlist *allowlist.Store
	Secrets   *secrets.MemoryStore
	Ledger    *sandboxledger.Ledger
	// OpenStore is an injection point for deterministic tests. Production uses
	// the measured S3 settings and attested credentials exclusively.
	OpenStore      func(objectwal.Credentials) (objectwal.Store, error)
	WALOptions     objectwal.Options
	Address        string
	PeerHosts      []string
	LaunchFile     []byte
	AttestationURL string
}

type Node struct {
	ctx           context.Context
	cfg           Config
	fsm           *cdsha.FSM
	id            string
	candidate     *issuer.CA
	wal           atomic.Pointer[objectwal.Log]
	provision     chan *provisionRequest
	cancel        context.CancelFunc
	closed        chan struct{}
	s3            *objectwal.S3
	metadata      *metadatapilot.Client
	allowlist     *allowlist.Handle
	secrets       *secrets.Handle
	bindings      *sandboxledger.Handle
	forwardKey    atomic.Pointer[[32]byte]
	peerClient    atomic.Pointer[pinnedPeerClient]
	incoming      chan struct{}
	incomingBytes atomic.Int64
	recovery      *cdsrecovery.Recipient // immutable recipient; only control actor opens grants
	authority     ed25519.PublicKey
	recoveredHash [32]byte // control actor owns credential refresh/key consistency
	allowGenesis  atomic.Bool
}

func New(ctx context.Context, cfg Config) (*Node, error) {
	if err := cfg.Storage.Check(); err != nil {
		return nil, err
	}
	mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	n := &Node{ctx: ctx, cfg: cfg, id: cdsdecree.NewIntentID(), candidate: mesh.Current().CA,
		provision: make(chan *provisionRequest, 8), cancel: cancel, closed: make(chan struct{}),
		incoming: make(chan struct{}, 16),
		fsm:      cdsha.NewFSM(cfg.Launch, cfg.Allowlist, cfg.Secrets, cfg.Ledger)}
	n.cfg.PeerHosts = append([]string(nil), cfg.PeerHosts...)
	n.cfg.LaunchFile = bytes.Clone(cfg.LaunchFile)
	if cfg.Storage.RecoveryAuthority != "" {
		n.authority, _ = cdsrecovery.ParseAuthority(cfg.Storage.RecoveryAuthority) // Check validated it.
		n.recovery, err = cdsrecovery.NewRecipient(cdsrecovery.Identity{ClusterID: cfg.Launch.ClusterID, ConfigSHA256: cfg.Launch.ConfigSHA256, Prefix: cfg.Storage.Prefix})
		if err != nil {
			cancel()
			return nil, err
		}
	} else {
		n.allowGenesis.Store(true) // Legacy operator-held-key pilot.
	}
	if cfg.Address != "" {
		check, stop := context.WithTimeout(ctx, operationTimeout)
		err := n.checkPeer(check, cfg.Address)
		stop()
		if err != nil || cfg.AttestationURL == "" || len(cfg.LaunchFile) == 0 {
			cancel()
			return nil, errors.New("object WAL: preferred writer requires its measured replica address, launch file and attestation API")
		}
	}
	n.allowlist = cfg.Allowlist.CommittedBy(writer[allowlist.Command, allowlist.Result]{n,
		func(c allowlist.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindAllowlist, Allowlist: &c} },
		func(r cdsha.Result) *allowlist.Result { return r.Allowlist }, allowlist.ErrUnavailable})
	n.secrets = cfg.Secrets.CommittedBy(writer[secrets.Command, secrets.Result]{n,
		func(c secrets.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindSecret, Secret: &c} },
		func(r cdsha.Result) *secrets.Result { return r.Secret }, secrets.ErrUnavailable})
	n.bindings = cfg.Ledger.CommittedBy(ledgerWriter{writer[sandboxledger.Command, sandboxledger.Held]{n,
		func(c sandboxledger.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindBinding, Binding: &c} },
		func(r cdsha.Result) *sandboxledger.Held { return r.Binding }, errors.New("object WAL: ledger unavailable")}})
	go n.provisionLoop()
	return n, nil
}

// Provision admits bounded work to the control actor. Protected mode accepts
// only a signed grant sealed to this incarnation; legacy mode checks the
// measured raw-key commitment. Refresh never changes the WAL's encryption key.
func (n *Node) Provision(p Provision) error {
	if n.recovery != nil {
		if len(p.Key) != 0 || p.Grant == nil {
			return errors.New("object WAL: sealed recovery grant required; raw keys refused")
		}
		if err := p.Grant.Check(); err != nil {
			return err
		}
		p.Grant = p.Grant.Clone()
	} else {
		if p.Grant != nil || len(p.Key) != 32 {
			return errors.New("object WAL: a 32-byte key is required")
		}
		want, _ := hex.DecodeString(n.cfg.Storage.KeySHA256)
		got := sha256.Sum256(p.Key)
		if subtle.ConstantTimeCompare(want, got[:]) != 1 {
			return errors.New("object WAL: key does not match the measured commitment")
		}
	}
	ctx, cancel := context.WithTimeout(n.ctx, operationTimeout)
	defer cancel()
	p.Key = bytes.Clone(p.Key)
	r := &provisionRequest{ctx: ctx, value: p, reply: make(chan error, 1)}
	select {
	case <-ctx.Done():
		clear(p.Key)
		return ctx.Err()
	case n.provision <- r:
	default:
		clear(p.Key)
		return objectwal.ErrBackpressure
	}
	select {
	case err := <-r.reply:
		return err
	case <-ctx.Done():
		if r.state.CompareAndSwap(0, 2) {
			clear(p.Key)
		}
		return ctx.Err()
	}
}

type provisionRequest struct {
	ctx   context.Context
	value Provision
	reply chan error
	state atomic.Uint32
}

// One control actor owns provisioning and credential refresh. Storage IO is
// owned separately by the WAL actor, so no provisioning mutex guards IO.
func (n *Node) provisionLoop() {
	defer close(n.closed)
	defer func() {
		if wal := n.wal.Load(); wal != nil {
			wal.Close()
		}
	}()
	for {
		if n.ctx.Err() != nil {
			return
		}
		select {
		case <-n.ctx.Done():
			return
		case r := <-n.provision:
			if !r.state.CompareAndSwap(0, 1) {
				continue
			}
			err := r.ctx.Err()
			if err == nil {
				err = n.provisionOwned(r.value)
			}
			clear(r.value.Key)
			r.reply <- err
		}
	}
}

func (n *Node) Close() {
	n.cancel()
	<-n.closed
	if n.metadata != nil {
		n.metadata.Close()
	}
	if client := n.peerClient.Load(); client != nil {
		client.http.CloseIdleConnections()
	}
}

func (n *Node) provisionOwned(p Provision) error {
	initialize := n.allowGenesis.Load()
	if n.recovery != nil {
		material, err := n.recovery.Open(*p.Grant, n.authority)
		if err != nil {
			return err
		}
		defer clear(material.Key)
		p.Key, initialize = material.Key, material.AllowGenesis
		if n.wal.Load() != nil {
			hash := sha256.Sum256(p.Key)
			if subtle.ConstantTimeCompare(hash[:], n.recoveredHash[:]) != 1 {
				return errors.New("object WAL: credential refresh cannot replace the recovery key")
			}
		}
	}
	if n.cfg.Storage.MetadataEndpoint != "" {
		if !metadatapilot.ValidToken(p.MetadataToken) {
			return errors.New("metadata pilot: separate metadata token required")
		}
	} else if p.MetadataToken != "" {
		return errors.New("metadata token supplied without a measured endpoint")
	}
	if n.wal.Load() != nil {
		if n.metadata != nil {
			if err := n.metadata.SetToken(p.MetadataToken); err != nil {
				return err
			}
		}
		if n.s3 != nil {
			return n.s3.SetCredentials(p.Credentials)
		}
		return nil
	}
	var store objectwal.Store
	var err error
	if n.cfg.OpenStore != nil {
		store, err = n.cfg.OpenStore(p.Credentials)
	} else {
		c := n.cfg.Storage
		n.s3, err = objectwal.NewS3(objectwal.S3Config{Bucket: c.Bucket, Region: c.Region, Endpoint: c.Endpoint, PathStyle: c.PathStyle}, p.Credentials)
		store = n.s3
	}
	if err != nil {
		return err
	}
	var metadata *metadatapilot.Client
	if endpoint := n.cfg.Storage.MetadataEndpoint; endpoint != "" {
		transport, err := metadatapilot.Transport(n.cfg.Storage.MetadataRootCA)
		if err != nil {
			return err
		}
		metadata, err = metadatapilot.NewClient(endpoint, n.cfg.Storage.Prefix, p.MetadataToken, transport)
		if err != nil {
			return err
		}
		store = metadatapilot.SplitStore{Objects: store, Metadata: metadata, HeadKey: n.cfg.Storage.Prefix + "/head"}
	}
	options := n.cfg.WALOptions
	if n.cfg.Address != "" && !n.cfg.Storage.DirectWriters {
		options.Writer = &objectwal.WriterConfig{ID: n.id, Address: n.cfg.Address, Forward: n.forward}
	}
	wal, err := objectwal.NewWithOptions(n.ctx, store, machine{n.fsm}, p.Key, n.cfg.Storage.Prefix, n.cfg.Launch.ClusterID+"/"+n.cfg.Launch.ConfigSHA256, options)
	if err != nil {
		if metadata != nil {
			metadata.Close()
		}
		return err
	}
	n.metadata = metadata
	n.forwardKey.Store(deriveForwardKey(p.Key, n.cfg.Launch))
	n.recoveredHash = sha256.Sum256(p.Key)
	n.allowGenesis.Store(initialize)
	n.wal.Store(wal)
	return nil
}

func (n *Node) Run(ctx context.Context) {
	defer n.Close()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if n.ConfirmRead() != nil {
			continue
		}
		if err := n.renewMeshCA(time.Now()); err != nil && !errors.Is(err, objectwal.ErrStateChanged) {
			slog.Warn("object WAL: mesh CA certificate renewal did not commit", "error", err)
		}
		wal := n.wal.Load()
		stats := wal.Stats()
		if stats.Applied-stats.Snapshot >= 100 {
			checkpoint, cancel := context.WithTimeout(ctx, operationTimeout)
			_ = wal.Checkpoint(checkpoint) // Conflict leaves only an orphan; retry next tick.
			cancel()
		}
	}
}

func (n *Node) ConfirmRead() error {
	wal := n.wal.Load()
	if wal == nil {
		return errors.New("object WAL: waiting for attested provisioning")
	}
	ctx, cancel := context.WithTimeout(n.ctx, operationTimeout)
	defer cancel()
	return wal.Sync(ctx)
}

func (n *Node) Serving() cdsha.Serving {
	s := cdsha.Serving{}
	switch {
	case n.ctx.Err() != nil:
		s.Reason = "object WAL: process is stopping"
	case n.wal.Load() == nil:
		s.Reason = "object WAL: waiting for attested provisioning"
	case !n.fsm.ClusterState().Joined():
		s.Reason = "object WAL: waiting for signed Genesis"
	case n.fsm.Stuck() != "":
		s.Reason = "object WAL: state machine stopped"
	case n.fsm.ApplyingFor() >= operationTimeout:
		s.Reason = "object WAL: state machine stalled"
	default:
		fresh := n.wal.Load().Fresh()
		if fresh.IsZero() || time.Since(fresh) >= operationTimeout {
			s.Reason = "object WAL: no current read watermark"
		} else {
			s.OK = true
		}
	}
	return s
}

func (n *Node) CA() (*issuer.CA, bool) {
	if !n.Serving().OK {
		return nil, false
	}
	ca := n.fsm.CA()
	return ca, ca != nil
}

func (n *Node) ClusterState() cdsha.ClusterState { return n.fsm.ClusterState() }
func (n *Node) Decrees() []cdsha.DecreeRecord    { return n.fsm.Decrees() }
func (n *Node) Allowlist() *allowlist.Handle     { return n.allowlist }
func (n *Node) Secrets() *secrets.Handle         { return n.secrets }
func (n *Node) Bindings() *sandboxledger.Handle  { return n.bindings }
func (n *Node) WALStats() objectwal.Stats {
	if wal := n.wal.Load(); wal != nil {
		return wal.Stats()
	}
	return objectwal.Stats{}
}

func (n *Node) Status() cdsha.Status {
	core := n.fsm.ClusterState()
	s := cdsha.Status{ClusterID: core.ClusterID, ID: n.id, Joined: core.Joined(), Serving: n.Serving(),
		Version: core.Version, NodeImagesVersion: core.NodeImagesVersion, AppliedIndex: n.fsm.AppliedIndex(),
		State: "ObjectWALPilot", Stuck: n.fsm.Stuck()}
	if n.cfg.Storage.MetadataEndpoint != "" {
		s.State = "TransactionalMetadataPilot"
	}
	if core.Joined() {
		s.CAFingerprint = certutil.CertFingerprint(core.MeshCACert)
	} else {
		s.GenesisCA = certutil.CertFingerprint(n.candidate.Cert.Raw)
	}
	return s
}

func (n *Node) TakeDecree(signed cdsdecree.Signed) (cdsha.Delivered, error) {
	if err := cdsdecree.Verify(signed, n.cfg.Launch.OperatorKeys, n.cfg.Launch.ClusterID); err != nil {
		return cdsha.Delivered{}, err
	}
	d := signed.Decree
	de := cdsha.DecreeEntry{Decree: signed, AtMS: time.Now().UnixMilli()}
	switch d.Kind {
	case cdsdecree.Genesis:
		if !n.allowGenesis.Load() {
			return cdsha.Delivered{}, errors.New("object WAL: recovery grant does not authorize Genesis")
		}
		if d.TargetMember != n.id {
			return cdsha.Delivered{}, errors.New("object WAL: Genesis names another process")
		}
		de.Policy = n.fsm.LocalPolicy()
		de.MeshCACert = n.candidate.Cert.Raw
		var err error
		de.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(n.candidate.Key)
		if err != nil {
			return cdsha.Delivered{}, err
		}
	case cdsdecree.SetNodeImages, cdsdecree.UpdateMeasurements:
		// Policy changes retain exactly the shared FSM's validation.
	case cdsdecree.RotateKey:
		// The signed intent and base version still pass through the shared
		// FSM. Concurrent or replayed rotations can install only one new key.
		mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
		if err != nil {
			return cdsha.Delivered{}, err
		}
		ca := mesh.Current().CA
		de.MeshCACert = ca.Cert.Raw
		de.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			return cdsha.Delivered{}, err
		}
	default:
		return cdsha.Delivered{}, fmt.Errorf("object WAL pilot supports Genesis, SetNodeImages, UpdateMeasurements and RotateKey; %s requires a separate lifecycle design", d.Kind)
	}
	defer clear(de.MeshCAKey)
	res, err := n.propose(cdsha.Entry{Kind: cdsha.KindDecree, Decree: &de})
	if err != nil {
		return cdsha.Delivered{}, err
	}
	if res.Decree == nil {
		return cdsha.Delivered{}, errors.New("object WAL: decree produced no result")
	}
	return cdsha.Delivered{Intent: d.IntentID, Version: res.Decree.Version, Refused: res.Decree.Refused}, nil
}

func (n *Node) propose(e cdsha.Entry) (cdsha.Result, error) {
	wal := n.wal.Load()
	if wal == nil {
		return cdsha.Result{}, errors.New("object WAL: waiting for attested provisioning")
	}
	if e.Kind != cdsha.KindDecree && !n.fsm.ClusterState().Joined() {
		return cdsha.Result{}, errors.New("object WAL: Genesis is required")
	}
	body, err := json.Marshal(e)
	if err != nil {
		return cdsha.Result{}, err
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(n.ctx, operationTimeout)
	defer cancel()
	// A recovered replica already holds the measured seed and journal. These
	// two startup commands can finish as reads when they would change nothing.
	// The actor's fresh barrier comes first; a stale local copy can never skip
	// a required write. Changed seeds still use the ordinary committed path.
	if e.Kind == cdsha.KindAllowlist && e.Allowlist != nil &&
		(e.Allowlist.Op == allowlist.OpSeed || e.Allowlist.Op == allowlist.OpStartJournal) {
		if err := wal.Sync(ctx); err != nil {
			return cdsha.Result{}, err
		}
		noOp, err := n.cfg.Allowlist.BootstrapNoOp(*e.Allowlist)
		if err != nil {
			return cdsha.Result{}, err
		}
		if noOp {
			if err := ctx.Err(); err != nil {
				return cdsha.Result{}, err
			}
			return cdsha.Result{Allowlist: &allowlist.Result{}}, nil
		}
	}
	answer, err := wal.Append(ctx, body)
	if err != nil {
		return cdsha.Result{}, err
	}
	res, ok := answer.(cdsha.Result)
	if !ok {
		return cdsha.Result{}, errors.New("object WAL: invalid state-machine result")
	}
	return res, nil
}

// WriteOperator submits one authenticated request to the same bounded actor
// as every other mutation. No handler can acknowledge a separate token spend.
func (n *Node) WriteOperator(c cdsha.OperatorCommand) (cdsha.OperatorResult, error) {
	if !n.cfg.Storage.AtomicOperatorWrites {
		return cdsha.OperatorResult{}, errors.New("object WAL: atomic operator writes are not enabled")
	}
	r, err := n.propose(cdsha.Entry{Kind: cdsha.KindOperator, Operator: &c})
	if err != nil {
		return cdsha.OperatorResult{}, err
	}
	if r.Operator == nil {
		return cdsha.OperatorResult{}, errors.New("object WAL: operator command produced no result")
	}
	return *r.Operator, nil
}

type machine struct{ fsm *cdsha.FSM }

func (m machine) Apply(index uint64, data []byte) (any, error) {
	r := m.fsm.Apply(index, data)
	return r, r.Stop
}
func (m machine) Capture() ([]byte, error) {
	snapshot, err := m.fsm.Snapshot()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := snapshot.Encode(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func (m machine) Restore(data []byte) (uint64, error) {
	err := m.fsm.Install(bytes.NewReader(data))
	return m.fsm.AppliedIndex(), err
}

type writer[C, R any] struct {
	node        *Node
	entry       func(C) cdsha.Entry
	result      func(cdsha.Result) *R
	unavailable error
}

func (w writer[C, R]) Commit(c C) (R, error) {
	var zero R
	r, err := w.node.propose(w.entry(c))
	if err != nil {
		return zero, fmt.Errorf("%w: %w", w.unavailable, err)
	}
	answer := w.result(r)
	if answer == nil {
		return zero, errors.New("object WAL: committed command produced no result")
	}
	return *answer, nil
}

type ledgerWriter struct {
	writer[sandboxledger.Command, sandboxledger.Held]
}

func (w ledgerWriter) CatchUp() { _ = w.node.ConfirmRead() }
