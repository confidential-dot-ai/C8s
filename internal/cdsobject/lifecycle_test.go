package cdsobject

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func lifecycleStore(t *testing.T, f *fixture, backend string) objectwal.Store {
	t.Helper()
	if backend == "object" {
		return f.bucket
	}
	const token = "synthetic-lifecycle-metadata-token"
	service, err := metadatapilot.Open(filepath.Join(t.TempDir(), "metadata.db"), "isolated", token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	server := httptest.NewTLSServer(service)
	t.Cleanup(server.Close)
	client, err := metadatapilot.NewClient(server.URL, "isolated", token, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return metadatapilot.SplitStore{Objects: f.bucket, Metadata: client, HeadKey: "isolated/head"}
}

func storedNode(t *testing.T, f *fixture, store objectwal.Store) *Node {
	t.Helper()
	return f.nodeConfig(t, func(c *Config) {
		c.OpenStore = func(objectwal.Credentials) (objectwal.Store, error) { return store, nil }
	})
}

func agingCA(t *testing.T, ca *issuer.CA) *issuer.CA {
	t.Helper()
	template := *ca.Cert
	now := time.Now().UTC().Truncate(time.Second)
	template.NotBefore, template.NotAfter = now.Add(-3*time.Hour), now.Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, ca.Key.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer.CA{Cert: cert, Key: ca.Key}
}

func lifecycleLeaf(t *testing.T, ca *issuer.CA, f *fixture) *x509.Certificate {
	t.Helper()
	template, err := certutil.NewLeafTemplate("lifecycle-workload", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, f.operator.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestAutomaticCARenewalPreservesIdentityAndColdRecovery(t *testing.T) {
	for _, backend := range []string{"object", "metadata"} {
		t.Run(backend, func(t *testing.T) {
			f := newFixture(t)
			store := lifecycleStore(t, f, backend)
			n := storedNode(t, f, store)
			n.candidate = agingCA(t, n.candidate)
			f.genesis(t, n)
			original := n.fsm.CA()
			leaf := lifecycleLeaf(t, original, f)
			version := n.ClusterState().Version
			if _, err := n.Secrets().Put(t.Context(), "/lifecycle", []byte("retained")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); n.Run(ctx) }()
			defer func() { cancel(); <-done }()
			deadline := time.Now().Add(5 * time.Second)
			for bytes.Equal(n.fsm.CA().Cert.Raw, original.Cert.Raw) {
				if time.Now().After(deadline) {
					t.Fatal("maintenance loop did not renew the aging CA")
				}
				time.Sleep(10 * time.Millisecond)
			}
			renewed := n.fsm.CA()
			if !renewed.Key.Equal(original.Key) || !bytes.Equal(renewed.Cert.RawSubject, original.Cert.RawSubject) ||
				!bytes.Equal(renewed.Cert.SubjectKeyId, original.Cert.SubjectKeyId) || !renewed.Cert.NotAfter.After(original.Cert.NotAfter) {
				t.Fatal("renewal changed the issuer or did not extend validity")
			}
			roots := x509.NewCertPool()
			roots.AddCert(renewed.Cert)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatalf("pre-renewal leaf lost its anchor: %v", err)
			}
			if n.ClusterState().Version != version {
				t.Fatal("automatic renewal advanced the operator decree version")
			}
			if err := n.wal.Load().Checkpoint(t.Context()); err != nil {
				t.Fatal(err)
			}
			cancel()
			<-done
			restarted := storedNode(t, f, store)
			if err := restarted.ConfirmRead(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restarted.fsm.CA().Cert.Raw, renewed.Cert.Raw) || !restarted.fsm.CA().Key.Equal(original.Key) {
				t.Fatal("checkpoint recovery lost the renewed CA or retained key")
			}
			if value, err := restarted.Secrets().Get(t.Context(), "/lifecycle"); err != nil || string(value) != "retained" {
				t.Fatalf("renewal/recovery lost a secret: %q %v", value, err)
			}
			before := restarted.WALStats().Applied
			if err := restarted.renewMeshCA(time.Now()); err != nil || restarted.WALStats().Applied != before {
				t.Fatalf("a certificate in its first half was renewed again: %v", err)
			}
		})
	}
}

type pausePublication struct {
	objectwal.Store
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (p *pausePublication) Put(ctx context.Context, key string, data []byte, expected string) (string, error) {
	if key == "isolated/head" && p.armed.CompareAndSwap(true, false) {
		close(p.entered)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-p.release:
		}
	}
	return p.Store.Put(ctx, key, data, expected)
}

func signedRotation(t *testing.T, f *fixture, version uint64) cdsdecree.Signed {
	t.Helper()
	signed, err := cdsdecree.Sign(cdsdecree.Decree{Kind: cdsdecree.RotateKey, ClusterID: f.launch.ClusterID,
		IntentID: cdsdecree.NewIntentID(), BaseVersion: version, ExpiresAt: time.Now().Add(time.Hour)}, f.operator)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestDelayedRenewalCannotOverwriteRotationOrNewerRenewal(t *testing.T) {
	for _, backend := range []string{"object", "metadata"} {
		for _, intervening := range []string{"rotation", "renewal"} {
			t.Run(backend+"/"+intervening, func(t *testing.T) {
				f := newFixture(t)
				store := lifecycleStore(t, f, backend)
				paused := &pausePublication{Store: store, entered: make(chan struct{}), release: make(chan struct{})}
				release := sync.OnceFunc(func() { close(paused.release) })
				defer release()
				a, b := storedNode(t, f, paused), storedNode(t, f, store)
				a.candidate = agingCA(t, a.candidate)
				f.genesis(t, a)
				if err := b.ConfirmRead(); err != nil {
					t.Fatal(err)
				}
				old := a.fsm.CA()
				paused.armed.Store(true)
				done := make(chan error, 1)
				go func() { done <- a.renewMeshCA(time.Now()) }()
				<-paused.entered
				if intervening == "rotation" {
					result, err := b.TakeDecree(signedRotation(t, f, b.ClusterState().Version))
					if err != nil || result.Refused != "" {
						t.Fatalf("rotation: %+v %v", result, err)
					}
				} else if err := b.renewMeshCA(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				want := b.fsm.CA()
				release()
				if err := <-done; !errors.Is(err, objectwal.ErrStateChanged) {
					t.Fatalf("delayed renewal outcome: %v", err)
				}
				if a.WALStats().Stopped || !bytes.Equal(a.fsm.CA().Cert.Raw, want.Cert.Raw) {
					t.Fatal("delayed renewal stopped the FSM or replaced newer state")
				}
				if (intervening == "renewal") != want.Key.Equal(old.Key) {
					t.Fatal("the winning operation used the wrong identity")
				}
				if err := b.wal.Load().Checkpoint(t.Context()); err != nil {
					t.Fatal(err)
				}
				a.Close()
				b.Close()
				cold := storedNode(t, f, store)
				if err := cold.ConfirmRead(); err != nil || !bytes.Equal(cold.fsm.CA().Cert.Raw, want.Cert.Raw) {
					t.Fatalf("cold replay changed the winning CA: %v", err)
				}
			})
		}
	}
}

func TestConcurrentRotationAndReplayInstallOneKey(t *testing.T) {
	for _, backend := range []string{"object", "metadata"} {
		t.Run(backend, func(t *testing.T) {
			f := newFixture(t)
			store := lifecycleStore(t, f, backend)
			a, b := storedNode(t, f, store), storedNode(t, f, store)
			f.genesis(t, a)
			original := a.fsm.CA()
			version := a.ClusterState().Version
			signed := signedRotation(t, f, version)
			type outcome struct {
				delivered cdsha.Delivered
				err       error
			}
			results := make(chan outcome, 2)
			for _, n := range []*Node{a, b} {
				go func() { r, err := n.TakeDecree(signed); results <- outcome{r, err} }()
			}
			winners := 0
			for range 2 {
				r := <-results
				if r.err != nil {
					t.Fatal(r.err)
				}
				if r.delivered.Refused == "" {
					winners++
				}
			}
			if winners != 1 {
				t.Fatalf("one signed rotation installed %d keys", winners)
			}
			for _, n := range []*Node{a, b} {
				if err := n.ConfirmRead(); err != nil {
					t.Fatal(err)
				}
				if n.ClusterState().Version != version+1 || n.fsm.CA().Key.Equal(original.Key) {
					t.Fatal("rotation did not advance exactly one decree version and key")
				}
			}
			want := a.fsm.CA()
			if !bytes.Equal(b.fsm.CA().Cert.Raw, want.Cert.Raw) {
				t.Fatal("replicas chose different rotation keys")
			}
			if err := a.wal.Load().Checkpoint(t.Context()); err != nil {
				t.Fatal(err)
			}
			a.Close()
			b.Close()
			cold := storedNode(t, f, store)
			if err := cold.ConfirmRead(); err != nil {
				t.Fatal(err)
			}
			if r, err := cold.TakeDecree(signed); err != nil || r.Refused == "" || !bytes.Equal(cold.fsm.CA().Cert.Raw, want.Cert.Raw) {
				t.Fatalf("replayed rotation after cold recovery: %+v %v", r, err)
			}
		})
	}
}

func TestRenewalStorageFailureLeavesCurrentCAUnchanged(t *testing.T) {
	f := newFixture(t)
	n := f.node(t)
	n.candidate = agingCA(t, n.candidate)
	f.genesis(t, n)
	original := n.fsm.CA()
	f.bucket.outage.Store(true)
	if err := n.renewMeshCA(time.Now()); err == nil || !bytes.Equal(n.fsm.CA().Cert.Raw, original.Cert.Raw) {
		t.Fatal("renewal published without durable commitment")
	}
	if n.Serving().OK {
		t.Fatal("storage failure left stale readiness")
	}
	f.bucket.outage.Store(false)
	if err := n.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if err := n.renewMeshCA(time.Now()); err != nil || bytes.Equal(n.fsm.CA().Cert.Raw, original.Cert.Raw) {
		t.Fatalf("renewal did not recover: %v", err)
	}
}
