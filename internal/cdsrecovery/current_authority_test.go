package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

type currentFixture struct {
	*policyFixture
	metadata *metadatapilot.Client
	store    *directstate.Store
}

func newCurrentFixture(t *testing.T) *currentFixture {
	f := &currentFixture{policyFixture: newPolicyFixture(t, "current")}
	m, err := metadatapilot.Open(filepath.Join(t.TempDir(), "metadata.db"), f.identity.Prefix, "test-current-recovery-metadata-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	h := httptest.NewTLSServer(m)
	t.Cleanup(h.Close)
	f.metadata, err = metadatapilot.NewClient(h.URL, f.identity.Prefix, "test-current-recovery-metadata-token", h.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.metadata.Close)
	f.store, err = directstate.New(t.Context(), f.metadata, f.bucket, f.key, f.identity.Prefix, f.identity.ClusterID+"/"+f.identity.ConfigSHA256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.store.Close)
	return f
}

func (f *currentFixture) publish(t *testing.T, kind cdsdecree.Kind, image string) {
	t.Helper()
	// The shared fixture constructs signed decrees; this path applies them to
	// a private machine and publishes current state, without appending a WAL.
	de := f.command(t, kind, image)
	defer clear(de.MeshCAKey)
	body, err := json.Marshal(cdsha.Entry{Kind: cdsha.KindDecree, Decree: &de})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	r := f.fsm.Apply(f.fsm.AppliedIndex()+1, body)
	if r.Stop != nil || r.Decree == nil || r.Decree.Refused != "" {
		t.Fatalf("fixture decree: %+v", r)
	}
	core, err := f.fsm.CurrentCore()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(core.MeshCAKey)
	data, err := json.Marshal(core)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	_, err = f.store.Update(t.Context(), directstate.IdentityRecord, []string{directstate.IdentityRecord}, func(*directstate.View) (map[string][]byte, any, error) {
		return map[string][]byte{directstate.IdentityRecord: bytes.Clone(data)}, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *currentFixture) restore(t *testing.T, metadata directstate.Metadata) *CurrentAuthority {
	t.Helper()
	a, err := RestoreCurrentAuthority(t.Context(), f.identity, f.record, f.capsule, f.root, f.verifier.URL(), CurrentRecords{
		Metadata: metadata, Objects: f.bucket, Launch: f.launch, Policy: f.fsm.LocalPolicy(), LaunchFile: f.file,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func (f *currentFixture) grant(t *testing.T, a *CurrentAuthority) Material {
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
		t.Fatal("changed the recovered state key")
	}
	t.Cleanup(func() { clear(m.Key) })
	return m
}

func TestCurrentAuthorityOriginalCapsuleUsesCurrentPolicyAfterRestart(t *testing.T) {
	f := newCurrentFixture(t)
	a := f.restore(t, f.metadata)
	if !f.grant(t, a).AllowGenesis {
		t.Fatal("initial process cannot initialize")
	}
	f.replacement(t, testutil.TestMeasurement)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("replacement got key before Genesis")
	}
	f.publish(t, cdsdecree.Genesis, testutil.TestMeasurement)
	if f.grant(t, a).AllowGenesis {
		t.Fatal("replacement got initialization permission")
	}
	f.publish(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("retired image recovered key")
	}
	a.Close()
	a = f.restore(t, f.metadata)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("cold authority used original enrollment as current image policy")
	}
	f.replacement(t, testutil.NextCDSImage)
	if f.grant(t, a).AllowGenesis {
		t.Fatal("approved upgrade got initialization permission")
	}
	if a.store.Stats().Commits != 0 || a.store.Stats().ObjectPuts != 0 {
		t.Fatal("recovery authority wrote application state")
	}
}

type pausedCurrentRead struct {
	directstate.Metadata
	reads           atomic.Int64
	after           bool
	offline         atomic.Bool
	entered, resume chan struct{}
}

func (p *pausedCurrentRead) Read(ctx context.Context, keys []string) ([]metadatapilot.Record, error) {
	var rows []metadatapilot.Record
	var err error
	if p.reads.Add(1) == 2 {
		if p.after {
			rows, err = p.Metadata.Read(ctx, keys)
		}
		close(p.entered)
		select {
		case <-p.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if p.after {
			return rows, err
		}
	}
	if p.offline.Load() {
		return nil, errors.New("injected metadata outage")
	}
	return p.Metadata.Read(ctx, keys)
}

func TestCurrentAuthorityOrdersRevocationAgainstFinalRead(t *testing.T) {
	for _, scenario := range []string{"revocation before final read", "revocation after final read", "unrelated policy change", "metadata outage"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCurrentFixture(t)
			f.publish(t, cdsdecree.Genesis, testutil.TestMeasurement)
			p := &pausedCurrentRead{Metadata: f.metadata, after: scenario == "revocation after final read", entered: make(chan struct{}), resume: make(chan struct{})}
			unblock := sync.OnceFunc(func() { close(p.resume) })
			t.Cleanup(unblock)
			a := f.restore(t, p)
			type result struct {
				grant *Grant
				err   error
			}
			done := make(chan result, 1)
			go func() { g, err := a.Release(t.Context(), f.origin); done <- result{g, err} }()
			select {
			case <-p.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("release did not reach final metadata read")
			}
			switch scenario {
			case "metadata outage":
				p.offline.Store(true)
			case "unrelated policy change":
				f.publish(t, cdsdecree.SetNodeImages, "")
			default:
				f.publish(t, cdsdecree.UpdateMeasurements, testutil.NextCDSImage)
			}
			unblock()
			r := <-done
			switch scenario {
			case "revocation before final read":
				if !errors.Is(r.err, ErrPolicyChanged) || r.grant != nil {
					t.Fatalf("stale grant: %v", r.err)
				}
			case "metadata outage":
				if r.err == nil || r.grant != nil {
					t.Fatal("released without fresh metadata")
				}
			default:
				if r.err != nil || r.grant == nil {
					t.Fatalf("valid ordering refused: %v", r.err)
				}
			}
		})
	}
}
