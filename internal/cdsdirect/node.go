package cdsdirect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const timeout = 5 * time.Second

type Node struct {
	ctx          context.Context
	cancel       context.CancelFunc
	cfg          cdsobject.Config
	id           string
	candidate    *issuer.CA
	policy       cdsha.Policy
	state        atomic.Pointer[State]
	control      *requestgate.Gate // one actor-owned permit for provisioning/refresh
	metadata     *metadatapilot.Client
	s3           *objectwal.S3
	keyHash      [32]byte
	allowGenesis atomic.Bool
	recipient    *cdsrecovery.Recipient
	authority    ed25519.PublicKey
	al           *allowlist.Handle
	sec          *secrets.Handle
	ledger       *sandboxledger.Handle
}

func New(ctx context.Context, cfg cdsobject.Config) (*Node, error) {
	if err := cfg.Storage.Check(); err != nil {
		return nil, err
	}
	if !cfg.Storage.DirectState {
		return nil, errors.New("direct state: explicit measured option required")
	}
	mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	f := cdsha.NewFSM(cfg.Launch, cfg.Allowlist, cfg.Secrets, cfg.Ledger)
	n := &Node{ctx: ctx, cancel: cancel, cfg: cfg, id: cdsdecree.NewIntentID(), candidate: mesh.Current().CA, policy: f.LocalPolicy()}
	if cfg.Storage.RecoveryAuthority != "" {
		n.authority, _ = cdsrecovery.ParseAuthority(cfg.Storage.RecoveryAuthority)
		n.recipient, err = cdsrecovery.NewRecipient(cdsrecovery.Identity{ClusterID: cfg.Launch.ClusterID, ConfigSHA256: cfg.Launch.ConfigSHA256, Prefix: cfg.Storage.Prefix})
		if err != nil {
			cancel()
			return nil, err
		}
	} else {
		n.allowGenesis.Store(true)
	}
	n.control, _ = requestgate.New(ctx, 1, 8)
	n.al = allowlist.Current(policyReader{n}, allowlistWriter{n})
	n.sec = cfg.Secrets.Current(secretReader{n}, secretWriter{n})
	n.ledger = cfg.Ledger.Current(bindingWriter{n}, n.lookupBinding)
	return n, nil
}

func (n *Node) Provision(p cdsobject.Provision) error {
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	release, err := n.control.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	key := bytes.Clone(p.Key)
	defer func() { clear(key) }()
	initialize := n.allowGenesis.Load()
	if n.recipient != nil {
		if len(key) != 0 || p.Grant == nil {
			return errors.New("direct state: sealed grant required")
		}
		material, err := n.recipient.Open(*p.Grant, n.authority)
		if err != nil {
			return err
		}
		key, initialize = material.Key, material.AllowGenesis
	} else {
		if p.Grant != nil || len(key) != 32 {
			return errors.New("direct state: measured 32-byte key required")
		}
		want, _ := hex.DecodeString(n.cfg.Storage.KeySHA256)
		got := sha256.Sum256(key)
		if subtle.ConstantTimeCompare(want, got[:]) != 1 {
			return errors.New("direct state: key commitment mismatch")
		}
	}
	if !metadatapilot.ValidToken(p.MetadataToken) {
		return errors.New("direct state: metadata token required")
	}
	if n.state.Load() != nil {
		if hash := sha256.Sum256(key); subtle.ConstantTimeCompare(hash[:], n.keyHash[:]) != 1 {
			return errors.New("direct state: refresh cannot change identity key")
		}
		if err := n.metadata.SetToken(p.MetadataToken); err != nil {
			return err
		}
		if n.s3 != nil {
			return n.s3.SetCredentials(p.Credentials)
		}
		return nil
	}
	var objects objectwal.Store
	if n.cfg.OpenStore != nil {
		objects, err = n.cfg.OpenStore(p.Credentials)
	} else {
		c := n.cfg.Storage
		n.s3, err = objectwal.NewS3(objectwal.S3Config{Bucket: c.Bucket, Region: c.Region, Endpoint: c.Endpoint, PathStyle: c.PathStyle}, p.Credentials)
		objects = n.s3
	}
	if err != nil {
		return err
	}
	transport, err := metadatapilot.Transport(n.cfg.Storage.MetadataRootCA)
	if err != nil {
		return err
	}
	metadata, err := metadatapilot.NewClient(n.cfg.Storage.MetadataEndpoint, n.cfg.Storage.Prefix, p.MetadataToken, transport)
	if err != nil {
		return err
	}
	store, err := directstate.New(n.ctx, metadata, objects, key, n.cfg.Storage.Prefix, n.cfg.Launch.ClusterID+"/"+n.cfg.Launch.ConfigSHA256)
	if err != nil {
		metadata.Close()
		return err
	}
	n.metadata, n.keyHash = metadata, sha256.Sum256(key)
	n.allowGenesis.Store(initialize)
	n.state.Store(NewState(n.ctx, store, n.cfg.Launch, n.policy))
	return nil
}

func (n *Node) Close() {
	n.cancel()
	n.control.Close()
	if s := n.state.Load(); s != nil {
		s.policyWrites.close()
		s.store.Close()
	}
	if n.metadata != nil {
		n.metadata.Close()
	}
}

func (n *Node) Run(ctx context.Context) {
	defer n.Close()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = n.renew()
		}
	}
}

func (n *Node) readyState() (*State, error) {
	if err := n.ctx.Err(); err != nil {
		return nil, err
	}
	s := n.state.Load()
	if s == nil {
		return nil, errors.New("direct state: waiting for attested provisioning")
	}
	return s, nil
}

func (n *Node) current() (cdsha.CurrentCore, *issuer.CA, error) {
	s, err := n.readyState()
	if err != nil {
		return cdsha.CurrentCore{}, nil, err
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	return s.Core(ctx)
}

func (n *Node) ConfirmRead() error { _, _, err := n.current(); return err }
func (n *Node) Serving() cdsha.Serving {
	if err := n.ConfirmRead(); err != nil {
		return cdsha.Serving{Reason: "direct state: current identity unavailable"}
	}
	return cdsha.Serving{OK: true}
}
func (n *Node) CA() (*issuer.CA, bool) { _, ca, err := n.current(); return ca, err == nil && ca != nil }
func (n *Node) ClusterState() cdsha.ClusterState {
	c, _, err := n.current()
	if err != nil {
		return cdsha.ClusterState{ClusterID: n.cfg.Launch.ClusterID}
	}
	return c.Core
}
func (n *Node) Decrees() []cdsha.DecreeRecord   { c, _, _ := n.current(); return c.Decrees }
func (n *Node) Allowlist() *allowlist.Handle    { return n.al }
func (n *Node) Secrets() *secrets.Handle        { return n.sec }
func (n *Node) Bindings() *sandboxledger.Handle { return n.ledger }
func (n *Node) Stats() directstate.Stats {
	if s := n.state.Load(); s != nil {
		stats := s.store.Stats()
		stats.PolicyBatches, stats.PolicyRequests, stats.PolicyLargestBatch = s.policyWrites.batches.Load(), s.policyWrites.requests.Load(), s.policyWrites.largest.Load()
		stats.PolicyAdmission = s.policyWrites.gate.Stats()
		return stats
	}
	return directstate.Stats{}
}

func (n *Node) Status() cdsha.Status {
	c, _, err := n.current()
	s := cdsha.Status{ClusterID: n.cfg.Launch.ClusterID, ID: n.id, State: "DirectStatePilot", Version: c.Core.Version, NodeImagesVersion: c.Core.NodeImagesVersion}
	if err != nil {
		s.GenesisCA = certutil.CertFingerprint(n.candidate.Cert.Raw)
		s.Serving.Reason = "direct state: current identity unavailable"
	} else {
		s.Joined, s.Serving.OK, s.CAFingerprint = true, true, certutil.CertFingerprint(c.Core.MeshCACert)
	}
	return s
}

func (n *Node) TakeDecree(signed cdsdecree.Signed) (cdsha.Delivered, error) {
	if err := cdsdecree.Verify(signed, n.cfg.Launch.OperatorKeys, n.cfg.Launch.ClusterID); err != nil {
		return cdsha.Delivered{}, err
	}
	s, err := n.readyState()
	if err != nil {
		return cdsha.Delivered{}, err
	}
	d := signed.Decree
	e := cdsha.DecreeEntry{Decree: signed, AtMS: time.Now().UnixMilli()}
	switch d.Kind {
	case cdsdecree.Genesis:
		if !n.allowGenesis.Load() || d.TargetMember != n.id {
			return cdsha.Delivered{}, errors.New("direct state: Genesis not authorized for this process")
		}
		e.Policy, e.MeshCACert = n.policy, n.candidate.Cert.Raw
		e.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(n.candidate.Key)
	case cdsdecree.SetNodeImages, cdsdecree.UpdateMeasurements:
	case cdsdecree.RotateKey:
		var mesh *issuer.MeshCA
		mesh, err = issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
		if err == nil {
			ca := mesh.Current().CA
			e.MeshCACert = ca.Cert.Raw
			e.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(ca.Key)
		}
	default:
		return cdsha.Delivered{}, errors.New("direct state: decree requires a separate lifecycle design")
	}
	defer clear(e.MeshCAKey)
	if err != nil {
		return cdsha.Delivered{}, err
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	r, err := s.ApplyControl(ctx, cdsha.Entry{Kind: cdsha.KindDecree, Decree: &e})
	if err != nil {
		return cdsha.Delivered{}, err
	}
	if r.Decree == nil {
		return cdsha.Delivered{}, errors.New("direct state: missing decree result")
	}
	return cdsha.Delivered{Intent: d.IntentID, Version: r.Decree.Version, Refused: r.Decree.Refused}, nil
}

func (n *Node) WriteOperator(c cdsha.OperatorCommand) (cdsha.OperatorResult, error) {
	s, err := n.readyState()
	if err != nil {
		return cdsha.OperatorResult{}, err
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	return s.WriteOperator(ctx, c)
}

func (n *Node) ServeRecoveryRequest(w http.ResponseWriter, r *http.Request) {
	if n.recipient == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(n.recipient.Request())
}

func (n *Node) renew() error {
	s, err := n.readyState()
	if err != nil {
		return err
	}
	_, ca, err := n.current()
	if err != nil {
		return err
	}
	now := time.Now()
	lifetime := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore)
	if lifetime <= 0 {
		return errors.New("direct state: invalid CA lifetime")
	}
	if !now.After(ca.Cert.NotBefore.Add(lifetime / 2)) {
		return nil
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return err
	}
	template := *ca.Cert
	template.SerialNumber = serial
	template.NotBefore = now.UTC().Truncate(time.Second)
	template.NotAfter = template.NotBefore.Add(lifetime)
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, ca.Key.Public(), ca.Key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	_, err = s.ApplyControl(ctx, cdsha.Entry{Kind: cdsha.KindRenewCA, RenewCA: &cdsha.RenewCAEntry{MeshCACert: cert}})
	return err
}
