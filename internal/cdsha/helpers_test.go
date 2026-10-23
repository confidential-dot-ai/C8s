package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Shared test helpers and fakes.

func mkWorkload(t *testing.T) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}

func operatorKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

// signDecree signs d for the test cluster, with a fresh intent and an hour
// to live unless d sets them.
func signDecree(t *testing.T, key *ecdsa.PrivateKey, d Decree) SignedDecree {
	t.Helper()
	d.ClusterID = testCluster
	if d.IntentID == "" {
		d.IntentID = fmt.Sprintf("i%d", time.Now().UnixNano())
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = time.Now().Add(time.Hour)
	}
	sd, err := SignDecree(d, key)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

// memDecrees stands in for the decree ConfigMaps. failList and failStatus
// make reads and status writes fail, as an API outage would.
type memDecrees struct {
	mu         sync.Mutex
	items      map[string]SignedDecree
	status     map[string]DecreeStatus
	failList   atomic.Bool
	failStatus atomic.Bool
	statusErrs atomic.Int32
}

func newMemDecrees() *memDecrees {
	return &memDecrees{items: map[string]SignedDecree{}, status: map[string]DecreeStatus{}}
}

// put stores a decree object and returns its name.
func (m *memDecrees) put(sd SignedDecree) string {
	name := DecreeName(testCluster, sd.Decree.IntentID)
	m.mu.Lock()
	m.items[name] = sd
	m.mu.Unlock()
	return name
}

func (m *memDecrees) PendingDecrees(context.Context) ([]PendingDecree, error) {
	if m.failList.Load() {
		return nil, errors.New("api down")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PendingDecree
	for name, sd := range m.items {
		if _, done := m.status[name]; !done {
			out = append(out, PendingDecree{Name: name, Decree: sd})
		}
	}
	return out, nil
}

func (m *memDecrees) SetDecreeStatus(_ context.Context, name string, st DecreeStatus) error {
	if m.failStatus.Load() {
		m.statusErrs.Add(1)
		return errors.New("api down")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status[name] = st
	return nil
}

func (m *memDecrees) get(name string) (DecreeStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.status[name]
	return st, ok
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func digest(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 48)) }

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func failOn(verb string, match func(k8stesting.Action) bool) k8stesting.ReactionFunc {
	return func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetVerb() == verb && (match == nil || match(a)) {
			return true, nil, errors.New("api down")
		}
		return false, nil, nil
	}
}

func testStores(t *testing.T) (*allowlist.Store, *secrets.MemoryStore, *sandboxledger.Ledger) {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return &al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8)
}

type memSink struct {
	*bytes.Buffer
	fail bool
}

func (s *memSink) Write(p []byte) (int, error) {
	if s.fail {
		return 0, errors.New("disk full")
	}
	return s.Buffer.Write(p)
}
func (s *memSink) ID() string    { return "mem" }
func (s *memSink) Cancel() error { return nil }
func (s *memSink) Close() error  { return nil }

var _ raft.SnapshotSink = (*memSink)(nil)

// newTestFSM is a pre-Genesis FSM of the test cluster, with operator key
// pub, over fresh stores.
func newTestFSM(t *testing.T, pub []byte) *FSM {
	t.Helper()
	al, sec, led := testStores(t)
	return NewFSM(PreGenesis(testCluster, pub), al, sec, led)
}

// applyAt applies e to f as log entry i.
func applyAt(f *FSM, i uint64, e any) any {
	raw, _ := json.Marshal(e)
	return f.Apply(&raft.Log{Index: i, Type: raft.LogCommand, Data: raw})
}

// restoreCopy snapshots f and restores the snapshot into to.
func restoreCopy(t *testing.T, f, to *FSM) error {
	t.Helper()
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	return to.Restore(io.NopCloser(&buf))
}
