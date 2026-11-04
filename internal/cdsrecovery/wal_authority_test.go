package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type policyBucket struct {
	objects  sync.Map // immutable *objectwal.Object, replaced by per-key CAS
	revision atomic.Uint64
	outage   atomic.Bool
}

func (b *policyBucket) Get(ctx context.Context, key string) (objectwal.Object, error) {
	if err := ctx.Err(); err != nil {
		return objectwal.Object{}, err
	}
	if b.outage.Load() {
		return objectwal.Object{}, errors.New("injected storage outage")
	}
	v, ok := b.objects.Load(key)
	if !ok {
		return objectwal.Object{}, objectwal.ErrNotFound
	}
	o := *v.(*objectwal.Object)
	o.Data = bytes.Clone(o.Data)
	return o, nil
}
func (b *policyBucket) Put(ctx context.Context, key string, data []byte, expected string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if b.outage.Load() {
		return "", errors.New("injected storage outage")
	}
	old, found := b.objects.Load(key)
	if (expected == "" && found) || (expected != "" && (!found || old.(*objectwal.Object).ETag != expected)) {
		return "", objectwal.ErrConflict
	}
	o := &objectwal.Object{Data: bytes.Clone(data), ETag: fmt.Sprint(b.revision.Add(1))}
	if found {
		if !b.objects.CompareAndSwap(key, old, o) {
			return "", objectwal.ErrConflict
		}
	} else if _, loaded := b.objects.LoadOrStore(key, o); loaded {
		return "", objectwal.ErrConflict
	}
	return o.ETag, nil
}

type policyFixture struct {
	*authorityFixture
	operator *ecdsa.PrivateKey
	launch   cdsha.Launch
	file     []byte
	bucket   *policyBucket
	writer   *objectwal.Log
	fsm      *cdsha.FSM
	capsule  Capsule
	root     []byte
}

// Only this writer can publish/checkpoint. Release authorities get independent
// read-only replay actors over exactly the same encrypted CDS history.
type policyWriter struct{ replayMachine }

func (m policyWriter) Capture() ([]byte, error) {
	s, err := m.fsm.Snapshot()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := s.Encode(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (f *policyFixture) machine(t *testing.T) *cdsha.FSM {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	return cdsha.NewFSM(f.launch, al, secrets.NewMemoryStore(1024, 100, 4096), sandboxledger.New(time.Hour, 100))
}

func newPolicyFixture(t *testing.T, cluster string) *policyFixture {
	t.Helper()
	f := &policyFixture{authorityFixture: newAuthorityFixture(t, cluster), bucket: &policyBucket{}, root: wrappingFixture(t), file: []byte("recovery test launch " + cluster)}
	var err error
	f.operator, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = cdsha.Launch{ClusterID: cluster, ConfigSHA256: f.identity.ConfigSHA256, OperatorKeys: []*ecdsa.PublicKey{&f.operator.PublicKey}, Voters: 3}
	f.fsm = f.machine(t)
	f.writer, err = objectwal.New(f.bucket, policyWriter{replayMachine{f.fsm}}, f.key, f.identity.Prefix, cluster+"/"+f.identity.ConfigSHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.writer.Close)
	f.capsule, err = SealAuthority(f.identity, f.record, f.key, f.signer, f.root)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *policyFixture) restorePolicy(t *testing.T, store objectwal.Store) *WALAuthority {
	t.Helper()
	a, err := RestoreWALAuthority(t.Context(), f.identity, f.record, f.capsule, f.root, f.verifier.URL(), Replay{Store: store, Machine: f.machine(t), LaunchFile: f.file})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func (f *policyFixture) replacement(t *testing.T, measurement string) {
	t.Helper()
	v := f.verdict
	v.Claims.LaunchDigest = measurement
	f.verifier.SetVerdict(v)
	r, err := NewRecipient(f.identity)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient.Store(r)
}

func (f *policyFixture) grant(t *testing.T, a *WALAuthority) Material {
	t.Helper()
	g, err := a.Release(t.Context(), f.origin)
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.recipient.Load().Open(*g, f.signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Key, f.key) {
		t.Fatal("released a different WAL key")
	}
	t.Cleanup(func() { clear(m.Key) })
	return m
}

func (f *policyFixture) command(t *testing.T, kind cdsdecree.Kind, measurement string) cdsha.DecreeEntry {
	t.Helper()
	now := time.Now()
	d := cdsdecree.Decree{ClusterID: f.identity.ClusterID, Kind: kind, IntentID: cdsdecree.NewIntentID(), BaseVersion: f.fsm.ClusterState().Version, ExpiresAt: now.Add(time.Hour)}
	de := cdsha.DecreeEntry{AtMS: now.UnixMilli()}
	if kind == cdsdecree.Genesis || kind == cdsdecree.UpdateMeasurements {
		var err error
		d.CDSPins, err = cdsdecree.NewPinDocument([]byte(testutil.CDSPinDocument(measurement, string(f.file))))
		if err != nil {
			t.Fatal(err)
		}
	}
	if kind == cdsdecree.Genesis || kind == cdsdecree.SetNodeImages {
		var err error
		d.NodePins, err = cdsdecree.NewNodeImages([]byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(f.file))))
		if err != nil {
			t.Fatal(err)
		}
	}
	if kind == cdsdecree.Genesis {
		mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
		if err != nil {
			t.Fatal(err)
		}
		ca := mesh.Current().CA
		de.MeshCACert = ca.Cert.Raw
		de.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			t.Fatal(err)
		}
		de.Policy = f.fsm.LocalPolicy()
		d.TargetMember, d.TargetAddress, d.IssuedAtMS = cdsdecree.NewIntentID(), "127.0.0.1:8443", now.UnixMilli()
		d.GenesisCA = certutil.CertFingerprint(ca.Cert.Raw)
	}
	var err error
	de.Decree, err = cdsdecree.Sign(d, f.operator)
	if err != nil {
		t.Fatal(err)
	}
	return de
}

func (f *policyFixture) append(t *testing.T, de cdsha.DecreeEntry) *cdsha.DecreeResult {
	t.Helper()
	b, err := json.Marshal(cdsha.Entry{Kind: cdsha.KindDecree, Decree: &de})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b)
	defer clear(de.MeshCAKey)
	r, err := f.writer.Append(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	return r.(cdsha.Result).Decree
}

func (f *policyFixture) commit(t *testing.T, kind cdsdecree.Kind, measurement string) {
	t.Helper()
	if r := f.append(t, f.command(t, kind, measurement)); r == nil || r.Refused != "" {
		t.Fatalf("decree refused: %+v", r)
	}
}

func TestWALAuthorityOriginalCapsuleUsesCurrentPolicyAfterRestart(t *testing.T) {
	f := newPolicyFixture(t, "policy")
	a := f.restorePolicy(t, f.bucket)
	if !f.grant(t, a).AllowGenesis {
		t.Fatal("initial process cannot initialize")
	}
	f.replacement(t, testutil.TestMeasurement)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("replacement got key from empty history")
	}
	f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
	if f.grant(t, a).AllowGenesis {
		t.Fatal("replacement got Genesis authority")
	}
	f.commit(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("old image recovered after revocation")
	}
	a.Close()
	if err := f.writer.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	a = f.restorePolicy(t, f.bucket) // Original capsule/record, not updated enrollment.
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("cold authority trusted old capsule policy")
	}
	f.replacement(t, testutil.NextCDSImage)
	if f.grant(t, a).AllowGenesis {
		t.Fatal("upgrade got Genesis authority")
	}
	if a.WALStats().Snapshot == 0 || a.WALStats().Puts != 0 {
		t.Fatal("did not restore checkpoint read-only")
	}
}

type pausedPolicyRead struct {
	objectwal.Store
	count   atomic.Int64
	at      int64
	after   bool
	entered chan struct{}
	resume  chan struct{}
}

func (p *pausedPolicyRead) Get(ctx context.Context, key string) (objectwal.Object, error) {
	if !strings.HasSuffix(key, "/head") || p.count.Add(1) != p.at {
		return p.Store.Get(ctx, key)
	}
	var o objectwal.Object
	var err error
	if p.after {
		o, err = p.Store.Get(ctx, key)
	}
	close(p.entered)
	select {
	case <-p.resume:
	case <-ctx.Done():
		return objectwal.Object{}, ctx.Err()
	}
	if p.after {
		return o, err
	}
	return p.Store.Get(ctx, key)
}

func pausePolicyRead(t *testing.T, store objectwal.Store, at int64, after bool) (*pausedPolicyRead, func()) {
	p := &pausedPolicyRead{Store: store, at: at, after: after, entered: make(chan struct{}), resume: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(p.resume) })
	t.Cleanup(unblock)
	return p, unblock
}

func TestWALAuthorityOrdersRevocationAgainstFinalRead(t *testing.T) {
	for _, scenario := range []string{"revocation before final read", "revocation after final read", "unrelated policy change", "outage before final read"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPolicyFixture(t, "race")
			f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
			p, unblock := pausePolicyRead(t, f.bucket, 2, scenario == "revocation after final read")
			a := f.restorePolicy(t, p)
			type result struct {
				grant *Grant
				err   error
			}
			done := make(chan result, 1)
			go func() { g, err := a.Release(t.Context(), f.origin); done <- result{g, err} }()
			select {
			case <-p.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("release did not reach final read")
			}
			if scenario == "outage before final read" {
				f.bucket.outage.Store(true)
			} else if scenario == "unrelated policy change" {
				f.commit(t, cdsdecree.SetNodeImages, "")
			} else {
				f.commit(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
			}
			unblock()
			r := <-done
			if scenario == "outage before final read" {
				if r.err == nil || r.grant != nil {
					t.Fatal("released despite failed final read")
				}
			} else if scenario == "revocation before final read" {
				if !errors.Is(r.err, ErrPolicyChanged) || r.grant != nil {
					t.Fatalf("stale release: %v", r.err)
				}
			} else if r.err != nil || r.grant == nil {
				t.Fatalf("valid linearization refused: %v", r.err)
			}
		})
	}
}

func TestWALAuthorityFailsClosedOnOutageMissingHeadAndLiveRollback(t *testing.T) {
	for _, fault := range []string{"outage", "missing", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			f := newPolicyFixture(t, "fault")
			f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
			old, _ := f.bucket.Get(t.Context(), f.identity.Prefix+"/head")
			f.commit(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
			f.replacement(t, testutil.NextCDSImage)
			a := f.restorePolicy(t, f.bucket)
			f.grant(t, a)
			switch fault {
			case "outage":
				f.bucket.outage.Store(true)
			case "missing":
				f.bucket.objects.Delete(f.identity.Prefix + "/head")
			case "rollback":
				f.bucket.objects.Store(f.identity.Prefix+"/head", &old)
			}
			if g, err := a.Release(t.Context(), f.origin); err == nil || g != nil {
				t.Fatal("released using cached policy")
			}
			if fault == "outage" {
				f.bucket.outage.Store(false)
				f.grant(t, a)
			}
			if fault == "missing" {
				a.Close()
				a = f.restorePolicy(t, f.bucket)
				f.replacement(t, testutil.TestMeasurement)
				if g, err := a.Release(t.Context(), f.origin); err == nil || g != nil {
					t.Fatal("cold recovery treated missing head as initialization")
				}
			}
		})
	}
}

func TestWALAuthorityUsesOnlyAppliedSignedPolicy(t *testing.T) {
	f := newPolicyFixture(t, "signed")
	f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
	a := f.restorePolicy(t, f.bucket)
	for _, bad := range []string{"unsigned", "stale version"} {
		de := f.command(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
		if bad == "unsigned" {
			de.Decree.Signature = "bad"
		} else {
			de.Decree.Decree.BaseVersion = 0
			de.Decree, _ = cdsdecree.Sign(de.Decree.Decree, f.operator)
		}
		if r := f.append(t, de); r == nil || r.Refused == "" {
			t.Fatal("invalid decree changed policy")
		}
	}
	f.grant(t, a)
	f.replacement(t, testutil.NextCDSImage)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("rejected decree authorized the new image")
	}
}

// Counterexample: a fresh authority cannot distinguish a complete authentic
// old history from the latest history if its supposedly linearizable store
// lies. Current-policy release inherits, rather than removes, that trust.
func TestWALAuthorityColdRollbackStillRequiresTrustedStorage(t *testing.T) {
	f := newPolicyFixture(t, "cold-rollback")
	f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
	old, _ := f.bucket.Get(t.Context(), f.identity.Prefix+"/head")
	f.commit(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
	f.bucket.objects.Store(f.identity.Prefix+"/head", &old) // Deliberately violate Store's contract.
	f.replacement(t, testutil.TestMeasurement)
	f.grant(t, f.restorePolicy(t, f.bucket)) // Demonstrates the remaining boundary.
}

func TestWALAuthorityBackpressureIsPerClusterAndCloseCancelsReplay(t *testing.T) {
	f := newPolicyFixture(t, "busy")
	f.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
	p, unblock := pausePolicyRead(t, f.bucket, 1, false)
	a := f.restorePolicy(t, p)
	results := make(chan error, 16)
	for range 16 {
		go func() { _, err := a.Release(t.Context(), f.origin); results <- err }()
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for a.Stats().Admitted != 16 || a.Stats().Active != 4 {
		select {
		case <-deadline.C:
			t.Fatal("release queue did not saturate")
		case <-tick.C:
		}
	}
	if _, err := a.Release(t.Context(), f.origin); !errors.Is(err, requestgate.ErrBusy) {
		t.Fatalf("overflow: %v", err)
	}
	other := newPolicyFixture(t, "independent")
	other.commit(t, cdsdecree.Genesis, testutil.TestMeasurement)
	other.grant(t, other.restorePolicy(t, other.bucket))
	a.Close()
	unblock()
	for range 16 {
		if err := <-results; err == nil {
			t.Fatal("shutdown released a pending key")
		}
	}
	if s := a.Stats(); s.Active != 0 || s.Admitted != 0 {
		t.Fatal("shutdown leaked admission slots")
	}
}
