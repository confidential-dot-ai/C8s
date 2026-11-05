package directstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type testObjects struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *testObjects) Get(_ context.Context, key string) (objectwal.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.values[key]
	if !ok {
		return objectwal.Object{}, objectwal.ErrNotFound
	}
	return objectwal.Object{Data: bytes.Clone(b), ETag: key}, nil
}
func (s *testObjects) Put(_ context.Context, key string, b []byte, expected string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.values[key]; ok || expected != "" {
		return "", objectwal.ErrConflict
	}
	s.values[key] = bytes.Clone(b)
	return key, nil
}

func metadataAt(t *testing.T, path, namespace string) (*metadatapilot.Service, *metadatapilot.Client) {
	t.Helper()
	s, err := metadatapilot.Open(path, namespace, "test-current-state-metadata-credential")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	h := httptest.NewTLSServer(s)
	t.Cleanup(h.Close)
	c, err := metadatapilot.NewClient(h.URL, namespace, "test-current-state-metadata-credential", h.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return s, c
}

func newTestStore(t *testing.T, m Metadata, o objectwal.Store, scope string) *Store {
	t.Helper()
	s, err := New(t.Context(), m, o, bytes.Repeat([]byte{42}, 32), "test", scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func set(t *testing.T, s *Store, key string, value []byte) {
	t.Helper()
	_, err := s.Update(t.Context(), key, []string{key}, func(*View) (map[string][]byte, any, error) {
		return map[string][]byte{key: bytes.Clone(value)}, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOneTokenAndMutationCommitTogetherAfterAllClientsAndMetadataRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	m, client := metadataAt(t, path, "test")
	objects := &testObjects{values: map[string][]byte{}}
	nodes := []*Store{newTestStore(t, client, objects, "cluster/launch"), newTestStore(t, client, objects, "cluster/launch"), newTestStore(t, client, objects, "cluster/launch")}
	identity := bytes.Repeat([]byte("encrypted CA input stays private"), 100)
	set(t, nodes[0], "identity", identity)
	set(t, nodes[0], "policy", []byte("approved"))
	var created, replayed atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			result, err := nodes[i%3].Update(t.Context(), "secret/a", []string{"identity", "policy", "token/a", "secret/a"}, func(v *View) (map[string][]byte, any, error) {
				if _, spent := v.Get("token/a"); spent {
					return nil, false, nil
				}
				return map[string][]byte{"token/a": []byte("spent"), "secret/a": bytes.Repeat([]byte("secret"), 1000)}, true, nil
			})
			if err != nil {
				t.Error(err)
			} else if result.(bool) {
				created.Add(1)
			} else {
				replayed.Add(1)
			}
		})
	}
	wg.Wait()
	if created.Load() != 1 || replayed.Load() != 11 {
		t.Fatalf("created=%d replayed=%d", created.Load(), replayed.Load())
	}
	for _, n := range nodes {
		n.Close()
	}
	m.Close()
	_, recoveredMetadata := metadataAt(t, path, "test")
	fresh := newTestStore(t, recoveredMetadata, objects, "cluster/launch")
	v, err := fresh.Read(t.Context(), "identity", "policy", "token/a", "secret/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Clear()
	if b, _ := v.Get("identity"); !bytes.Equal(b, identity) {
		t.Fatal("identity changed")
	}
	if _, ok := v.Get("token/a"); !ok {
		t.Fatal("spent token lost")
	}
	if b, _ := v.Get("secret/a"); !bytes.Equal(b, bytes.Repeat([]byte("secret"), 1000)) {
		t.Fatal("acknowledged value lost")
	}
	for _, b := range objects.values {
		if bytes.Contains(b, []byte("secret")) || bytes.Contains(b, []byte("CA input")) {
			t.Fatal("plaintext persisted")
		}
	}
}

type lostReply struct {
	Metadata
	after bool
	calls atomic.Int32
}

func (m *lostReply) Commit(ctx context.Context, tx metadatapilot.Transaction) error {
	m.calls.Add(1)
	if m.after {
		if err := m.Metadata.Commit(ctx, tx); err != nil {
			return err
		}
	}
	return objectwal.ErrInDoubt
}

func TestUnknownOutcomeIsNeverRetriedAndRecoversBothEffectsOrNeither(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
			objects := &testObjects{values: map[string][]byte{}}
			broken := &lostReply{Metadata: client, after: after}
			n := newTestStore(t, broken, objects, "cluster/launch")
			_, err := n.Update(t.Context(), "secret/a", []string{"token/a", "secret/a"}, func(*View) (map[string][]byte, any, error) {
				return map[string][]byte{"token/a": []byte("spent"), "secret/a": bytes.Repeat([]byte{31}, 4096)}, nil, nil
			})
			if !errors.Is(err, objectwal.ErrInDoubt) || broken.calls.Load() != 1 {
				t.Fatalf("error=%v calls=%d", err, broken.calls.Load())
			}
			n.Close()
			recovered := newTestStore(t, client, objects, "cluster/launch")
			v, err := recovered.Read(t.Context(), "token/a", "secret/a")
			if err != nil {
				t.Fatal(err)
			}
			defer v.Clear()
			_, token := v.Get("token/a")
			_, secret := v.Get("secret/a")
			if token != after || secret != after {
				t.Fatalf("token=%v secret=%v after=%v", token, secret, after)
			}
		})
	}
}

type beforeCommit struct {
	Metadata
	entered, resume chan struct{}
	once            sync.Once
}

func (m *beforeCommit) Commit(ctx context.Context, tx metadatapilot.Transaction) error {
	m.once.Do(func() {
		close(m.entered)
		select {
		case <-ctx.Done():
		case <-m.resume:
		}
	})
	return m.Metadata.Commit(ctx, tx)
}

func TestRevocationBetweenPreparationAndCommitInvalidatesTheReadSet(t *testing.T) {
	_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
	objects := &testObjects{values: map[string][]byte{}}
	other := newTestStore(t, client, objects, "cluster/launch")
	set(t, other, "policy", []byte("approved"))
	barrier := &beforeCommit{Metadata: client, entered: make(chan struct{}), resume: make(chan struct{})}
	n := newTestStore(t, barrier, objects, "cluster/launch")
	done := make(chan error, 1)
	go func() {
		_, err := n.Update(t.Context(), "secret/a", []string{"policy", "secret/a"}, func(v *View) (map[string][]byte, any, error) {
			policy, _ := v.Get("policy")
			if string(policy) != "approved" {
				return nil, nil, errors.New("revoked")
			}
			return map[string][]byte{"secret/a": []byte("secret")}, nil, nil
		})
		done <- err
	}()
	<-barrier.entered
	set(t, other, "policy", []byte("revoked"))
	close(barrier.resume)
	if err := <-done; err == nil || err.Error() != "revoked" {
		t.Fatalf("revocation result=%v", err)
	}
	v, err := other.Read(t.Context(), "secret/a")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Clear()
	if _, exists := v.Get("secret/a"); exists {
		t.Fatal("stale policy authorized a commit")
	}
}

func TestUnrelatedKeysDoNotConflictOnSharedPolicy(t *testing.T) {
	_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
	objects := &testObjects{values: map[string][]byte{}}
	a, b := newTestStore(t, client, objects, "cluster/launch"), newTestStore(t, client, objects, "cluster/launch")
	set(t, a, "policy", []byte("approved"))
	var wg sync.WaitGroup
	for i := range 48 {
		wg.Go(func() {
			n := []*Store{a, b}[i%2]
			key := fmt.Sprintf("secret/%d", i)
			_, err := n.Update(t.Context(), key, []string{"policy", key}, func(*View) (map[string][]byte, any, error) { return map[string][]byte{key: []byte("value")}, nil, nil })
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if a.Stats().Conflicts+b.Stats().Conflicts != 0 {
		t.Fatal("independent writes conflicted")
	}
}

func TestHotShardIsBoundedAndOtherShardsProgress(t *testing.T) {
	_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
	n := newTestStore(t, client, &testObjects{values: map[string][]byte{}}, "cluster/launch")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = n.Update(ctx, "hot", []string{"hot"}, func(*View) (map[string][]byte, any, error) { close(entered); <-resume; return nil, nil, nil })
	})
	<-entered
	for range ShardCapacity - 1 {
		wg.Go(func() {
			_, _ = n.Update(ctx, "hot", []string{"hot"}, func(*View) (map[string][]byte, any, error) { return nil, nil, nil })
		})
	}
	deadline := time.Now().Add(time.Second)
	for n.Stats().Admitted < ShardCapacity && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n.Stats().Admitted != ShardCapacity {
		t.Fatal("queue did not fill")
	}
	if _, err := n.Update(ctx, "hot", []string{"hot"}, nil); err == nil {
		t.Fatal("overflow admitted")
	}
	other := "cold"
	hotHash := sha256.Sum256([]byte("hot"))
	for i := 0; ; i++ {
		h := sha256.Sum256([]byte(other))
		if h[0]%Shards != hotHash[0]%Shards {
			break
		}
		other = fmt.Sprint("cold", i)
	}
	set(t, n, other, []byte("still progressing"))
	close(resume)
	wg.Wait()
	if s := n.Stats(); s.Admitted != 0 || s.Rejected != 1 {
		t.Fatalf("admission did not drain: %+v", s)
	}
}

type alteredRead struct {
	Metadata
	alter func([]metadatapilot.Record)
}

func (m alteredRead) Read(ctx context.Context, keys []string) ([]metadatapilot.Record, error) {
	r, err := m.Metadata.Read(ctx, keys)
	if err == nil {
		m.alter(r)
	}
	return r, err
}

func TestCiphertextCannotMoveAcrossKeysVersionsOrClusters(t *testing.T) {
	_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
	objects := &testObjects{values: map[string][]byte{}}
	s := newTestStore(t, client, objects, "cluster/launch")
	set(t, s, "a", []byte("private-a"))
	set(t, s, "b", []byte("private-b"))
	rows, err := client.Read(t.Context(), []string{s.name("a"), s.name("b")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"key", "version", "cluster"} {
		t.Run(name, func(t *testing.T) {
			m := alteredRead{Metadata: client, alter: func(out []metadatapilot.Record) {
				switch name {
				case "key":
					out[0].Value, out[0].Version = rows[1].Value, rows[1].Version
				case "version":
					out[0].Version = rows[1].Version
				case "cluster":
					out[0].Value, out[0].Version = rows[0].Value, rows[0].Version
				}
			}}
			scope := "cluster/launch"
			if name == "cluster" {
				scope = "another-cluster/launch"
			}
			n := newTestStore(t, m, objects, scope)
			if v, err := n.Read(t.Context(), "a"); !errors.Is(err, objectwal.ErrCorrupt) {
				if v != nil {
					v.Clear()
				}
				t.Fatalf("accepted substitution: %v", err)
			}
		})
	}
}

type offlineMetadata struct {
	Metadata
	offline atomic.Bool
}

func (m *offlineMetadata) Read(ctx context.Context, keys []string) ([]metadatapilot.Record, error) {
	if m.offline.Load() {
		return nil, errors.New("metadata offline")
	}
	return m.Metadata.Read(ctx, keys)
}

func TestCiphertextCacheNeverSubstitutesForCurrentMetadata(t *testing.T) {
	_, client := metadataAt(t, filepath.Join(t.TempDir(), "state.db"), "test")
	objects := &testObjects{values: map[string][]byte{}}
	m := &offlineMetadata{Metadata: client}
	s := newTestStore(t, m, objects, "cluster/launch")
	set(t, s, "policy", bytes.Repeat([]byte("approved"), 1024))
	v, err := s.Read(t.Context(), "policy")
	if err != nil {
		t.Fatal(err)
	}
	v.Clear()
	m.offline.Store(true)
	if v, err := s.Read(t.Context(), "policy"); err == nil {
		v.Clear()
		t.Fatal("served cached policy without freshness authority")
	}
	m.offline.Store(false)
	other := newTestStore(t, client, objects, "cluster/launch")
	set(t, other, "policy", bytes.Repeat([]byte("revoked"), 1024))
	v, err = s.Read(t.Context(), "policy")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Clear()
	b, _ := v.Get("policy")
	if !bytes.Equal(b, bytes.Repeat([]byte("revoked"), 1024)) {
		t.Fatal("served superseded immutable object")
	}
}
