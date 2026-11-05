package cdsobject

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func (f *fixture) operatorCommand(t *testing.T, path, body string) cdsha.OperatorCommand {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(f.operator)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := signer.Authorization(http.MethodPut, path, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return cdsha.OperatorCommand{Token: strings.TrimPrefix(auth, "Bearer "), Path: path, Body: []byte(body), AtMS: time.Now().UnixMilli()}
}

func atomicNode(t *testing.T, f *fixture, store objectwal.Store) *Node {
	return f.nodeConfig(t, func(c *Config) {
		c.Storage.AtomicOperatorWrites = true
		c.OpenStore = func(objectwal.Credentials) (objectwal.Store, error) { return store, nil }
	})
}

func TestAtomicOperatorSingleUseAcrossWritersAndColdSnapshot(t *testing.T) {
	for _, backend := range []string{"object", "metadata"} {
		t.Run(backend, func(t *testing.T) {
			f := newFixture(t)
			store := lifecycleStore(t, f, backend)
			nodes := []*Node{atomicNode(t, f, store), atomicNode(t, f, store), atomicNode(t, f, store)}
			f.genesis(t, nodes[0])
			for _, n := range nodes {
				if err := n.ConfirmRead(); err != nil {
					t.Fatal(err)
				}
			}
			ca := nodes[0].Status().CAFingerprint
			cmd := f.operatorCommand(t, "/secrets/atomic", `{"value":"c2FtZQ=="}`)
			var created, replayed atomic.Int32
			var workers sync.WaitGroup
			for i := range 12 {
				workers.Go(func() {
					result, err := nodes[i%3].WriteOperator(cmd)
					if err != nil {
						t.Error(err)
						return
					}
					switch result.Code {
					case http.StatusCreated:
						created.Add(1)
					case http.StatusConflict:
						if result.JSON || string(result.Body) != operatorauth.ErrTokenReused.Error() {
							t.Errorf("wrong replay response: %+v", result)
						}
						replayed.Add(1)
					default:
						t.Errorf("unexpected response: %+v", result)
					}
				})
			}
			workers.Wait()
			if created.Load() != 1 || replayed.Load() != 11 {
				t.Fatalf("created=%d replayed=%d", created.Load(), replayed.Load())
			}
			invalid := f.operatorCommand(t, "/secrets/rejected", `{"value":""}`)
			if result, err := nodes[0].WriteOperator(invalid); err != nil || result.Code != http.StatusUnprocessableEntity {
				t.Fatalf("invalid body: %+v %v", result, err)
			}
			if err := nodes[0].wal.Load().Checkpoint(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, n := range nodes {
				n.Close()
			}
			recovered := atomicNode(t, f, store)
			if err := recovered.ConfirmRead(); err != nil {
				t.Fatal(err)
			}
			if recovered.Status().CAFingerprint != ca {
				t.Fatal("cold recovery changed the CA")
			}
			value, err := recovered.Secrets().Get(t.Context(), "/atomic")
			if err != nil || string(value) != "same" {
				t.Fatalf("recovered value: %q %v", value, err)
			}
			for _, c := range []cdsha.OperatorCommand{cmd, invalid} {
				if result, err := recovered.WriteOperator(c); err != nil || result.Code != http.StatusConflict || string(result.Body) != operatorauth.ErrTokenReused.Error() {
					t.Fatalf("cold replay: %+v %v", result, err)
				}
			}
			if _, err := recovered.Secrets().Get(t.Context(), "/rejected"); !errors.Is(err, secrets.ErrNotFound) {
				t.Fatalf("invalid mutation created a value: %v", err)
			}
		})
	}
}

// A head publication can succeed while its reply and all subsequent reads are
// lost. A replacement must recover both effects or neither, never just a spend.
type operatorPublicationFailure struct {
	objectwal.Store
	enabled atomic.Bool
	lost    atomic.Bool
	after   bool
}

func (s *operatorPublicationFailure) Get(ctx context.Context, key string) (objectwal.Object, error) {
	if s.lost.Load() {
		return objectwal.Object{}, errors.New("injected outage")
	}
	return s.Store.Get(ctx, key)
}

func (s *operatorPublicationFailure) Put(ctx context.Context, key string, data []byte, expected string) (string, error) {
	if strings.HasSuffix(key, "/head") && s.enabled.Load() {
		if s.after {
			if _, err := s.Store.Put(ctx, key, data, expected); err != nil {
				return "", err
			}
		}
		s.lost.Store(true)
		return "", errors.New("injected lost publication reply")
	}
	return s.Store.Put(ctx, key, data, expected)
}

func TestAtomicOperatorUnknownCommitRecoversBothEffectsOrNeither(t *testing.T) {
	for _, backend := range []string{"object", "metadata"} {
		t.Run(backend, func(t *testing.T) {
			testUnknownOperatorCommit(t, backend)
		})
	}
}

func testUnknownOperatorCommit(t *testing.T, backend string) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-publication", true: "after-publication"}[after], func(t *testing.T) {
			f := newFixture(t)
			bucket := lifecycleStore(t, f, backend)
			store := &operatorPublicationFailure{Store: bucket, after: after}
			n := f.nodeConfig(t, func(c *Config) {
				c.Storage.AtomicOperatorWrites = true
				c.OpenStore = func(objectwal.Credentials) (objectwal.Store, error) { return store, nil }
			})
			f.genesis(t, n)
			cmd := f.operatorCommand(t, "/secrets/unknown", `{"value":"c2FtZQ=="}`)
			store.enabled.Store(true)
			if _, err := n.WriteOperator(cmd); err == nil {
				t.Fatal("lost publication was acknowledged")
			}
			n.Close()
			recovered := atomicNode(t, f, bucket)
			if err := recovered.ConfirmRead(); err != nil {
				t.Fatal(err)
			}
			value, err := recovered.Secrets().Get(t.Context(), "/unknown")
			if after && (err != nil || string(value) != "same") {
				t.Fatalf("durable mutation lost: %q %v", value, err)
			}
			if !after && !errors.Is(err, secrets.ErrNotFound) {
				t.Fatalf("uncommitted mutation applied: %q %v", value, err)
			}
			result, err := recovered.WriteOperator(cmd)
			want := http.StatusCreated
			if after {
				want = http.StatusConflict
			}
			if err != nil || result.Code != want {
				t.Fatalf("token/mutation split: %+v %v", result, err)
			}
		})
	}
}
