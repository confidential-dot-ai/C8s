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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Shared test helpers and fakes.

// mkWorkload is a one-container workload; i picks its digest.
func mkWorkload(t *testing.T, i int) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
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
	if d.TargetMember == "" && (d.Kind == Genesis || d.Kind == Recover || d.Kind == Restore) {
		d.TargetMember = d.BootstrapNode + "/0-unbound" // the tests that act on it name a real member
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
	// hang, when set, blocks every List until it closes or ctx ends, as a
	// hung API server does.
	hang atomic.Pointer[chan struct{}]
	hung atomic.Int32
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

func (m *memDecrees) ListDecrees(ctx context.Context) ([]PendingDecree, error) {
	if h := m.hang.Load(); h != nil {
		m.hung.Add(1)
		select {
		case <-*h:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.failList.Load() {
		return nil, errors.New("api down")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PendingDecree
	for name, sd := range m.items {
		p := PendingDecree{Name: name, Decree: sd}
		if st, done := m.status[name]; done {
			p.Status = &st
		}
		out = append(out, p)
	}
	return out, nil
}

// del removes a decree object and its status, as an operator would.
func (m *memDecrees) del(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, name)
	delete(m.status, name)
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
	f := NewFSM(PreGenesis(testCluster, pub), al, sec, led)
	f.core.Policy = f.LocalPolicy()
	return f
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

func mustCA(t *testing.T) *issuer.CA {
	t.Helper()
	mesh, err := issuer.NewMeshCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return mesh.Current().CA
}

// withDigests gives a hand-built snapshot the digests and chain a replica
// writes, so it is refused only for what a test changed. An image that is
// not a database gets a zero allowlist digest (its restore fails anyway).
func withDigests(t *testing.T, sn snapshot) snapshot {
	t.Helper()
	d, err := contentDigests(sn, func(image []byte) ([32]byte, error) {
		sum, err := allowlist.ImageDigest(image)
		if err != nil {
			return [32]byte{}, nil
		}
		return sum, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sn.Digests = d
	sn.Chain = Point{Index: sn.Index, Chain: strings.Repeat("0", 64)}
	return sn
}

// emptyImage is the database image of an empty allowlist.
func emptyImage(t *testing.T) []byte {
	t.Helper()
	al, _, _ := testStores(t)
	image, err := al.Dump()
	if err != nil {
		t.Fatal(err)
	}
	return image
}
