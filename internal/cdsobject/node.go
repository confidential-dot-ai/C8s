// Package cdsobject is an opt-in CDS HA pilot. It reuses the Raft backend's
// state machine and command results, with an encrypted object WAL as authority.
package cdsobject

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const operationTimeout = 5 * time.Second

type Provision struct {
	Key         []byte                `json:"key"`
	Credentials objectwal.Credentials `json:"credentials"`
}

type Config struct {
	Launch    cdsha.Launch
	Storage   cdsconfig.ObjectWALPilot
	Allowlist *allowlist.Store
	Secrets   *secrets.MemoryStore
	Ledger    *sandboxledger.Ledger
	// OpenStore is an injection point for deterministic tests. Production uses
	// the measured S3 settings and attested credentials exclusively.
	OpenStore func(objectwal.Credentials) (objectwal.Store, error)
}

type Node struct {
	ctx         context.Context
	cfg         Config
	fsm         *cdsha.FSM
	id          string
	candidate   *issuer.CA
	wal         atomic.Pointer[objectwal.Log]
	fresh       atomic.Pointer[time.Time]
	provisionMu sync.Mutex
	s3          *objectwal.S3
	allowlist   *allowlist.Handle
	secrets     *secrets.Handle
	bindings    *sandboxledger.Handle
}

func New(ctx context.Context, cfg Config) (*Node, error) {
	if err := cfg.Storage.Check(); err != nil {
		return nil, err
	}
	mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
	if err != nil {
		return nil, err
	}
	n := &Node{ctx: ctx, cfg: cfg, id: cdsdecree.NewIntentID(), candidate: mesh.Current().CA,
		fsm: cdsha.NewFSM(cfg.Launch, cfg.Allowlist, cfg.Secrets, cfg.Ledger)}
	n.allowlist = cfg.Allowlist.CommittedBy(writer[allowlist.Command, allowlist.Result]{n,
		func(c allowlist.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindAllowlist, Allowlist: &c} },
		func(r cdsha.Result) *allowlist.Result { return r.Allowlist }, allowlist.ErrUnavailable})
	n.secrets = cfg.Secrets.CommittedBy(writer[secrets.Command, secrets.Result]{n,
		func(c secrets.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindSecret, Secret: &c} },
		func(r cdsha.Result) *secrets.Result { return r.Secret }, secrets.ErrUnavailable})
	n.bindings = cfg.Ledger.CommittedBy(ledgerWriter{writer[sandboxledger.Command, sandboxledger.Held]{n,
		func(c sandboxledger.Command) cdsha.Entry { return cdsha.Entry{Kind: cdsha.KindBinding, Binding: &c} },
		func(r cdsha.Result) *sandboxledger.Held { return r.Binding }, errors.New("object WAL: ledger unavailable")}})
	return n, nil
}

// Provision authorizes possession of the measured key commitment. The client
// verifies the server's TEE and launch file before transmitting either secret.
// Reprovisioning refreshes expiring S3 credentials without replacing local state.
func (n *Node) Provision(p Provision) error {
	if len(p.Key) != 32 {
		return errors.New("object WAL: a 32-byte key is required")
	}
	want, _ := hex.DecodeString(n.cfg.Storage.KeySHA256)
	got := sha256.Sum256(p.Key)
	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return errors.New("object WAL: key does not match the measured commitment")
	}
	n.provisionMu.Lock()
	defer n.provisionMu.Unlock()
	if n.wal.Load() != nil {
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
	wal, err := objectwal.New(store, machine{n.fsm}, p.Key, n.cfg.Storage.Prefix, n.cfg.Launch.ClusterID+"/"+n.cfg.Launch.ConfigSHA256)
	if err != nil {
		return err
	}
	n.wal.Store(wal)
	return nil
}

func (n *Node) Run(ctx context.Context) {
	defer n.fresh.Store(nil)
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
	// Start the freshness interval before IO, so a slow request cannot renew
	// readiness using an observation it made more than five seconds ago.
	start := time.Now()
	if err := wal.Sync(ctx); err != nil {
		n.fresh.Store(nil)
		return err
	}
	n.fresh.Store(&start)
	return nil
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
		fresh := n.fresh.Load()
		if fresh == nil || time.Since(*fresh) >= operationTimeout {
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
	case cdsdecree.SetNodeImages:
		// Policy changes retain exactly the shared FSM's validation.
	default:
		return cdsha.Delivered{}, fmt.Errorf("object WAL pilot supports Genesis and SetNodeImages; %s requires a separate lifecycle design", d.Kind)
	}
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
	ctx, cancel := context.WithTimeout(n.ctx, operationTimeout)
	defer cancel()
	start := time.Now()
	answer, err := wal.Append(ctx, body)
	if err != nil {
		n.fresh.Store(nil)
		return cdsha.Result{}, err
	}
	n.fresh.Store(&start)
	res, ok := answer.(cdsha.Result)
	if !ok {
		return cdsha.Result{}, errors.New("object WAL: invalid state-machine result")
	}
	return res, nil
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
