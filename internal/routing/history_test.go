package routing

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeHistory serves allowlist documents by digest and counts the fetches.
type fakeHistory struct {
	mu    sync.Mutex
	docs  map[[sha256.Size]byte]*allowlist.Allowlist
	calls map[[sha256.Size]byte]int
}

func (h *fakeHistory) Object(_ context.Context, digest [sha256.Size]byte) (*allowlist.Allowlist, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls[digest]++
	al, ok := h.docs[digest]
	if !ok {
		return nil, errors.New("404 not found")
	}
	return al, nil
}

func (h *fakeHistory) fetches(digest []byte) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[[sha256.Size]byte(digest)]
}

// entryOf is an allowlist entry admitting one image, distinct per b.
func entryOf(t testing.TB, b byte) allowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest("sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64))
	if err != nil {
		t.Fatal(err)
	}
	return allowlist.DigestEntry(d, "example.com/app")
}

// TestB8BackendEntry: with an allowlist history, a backend stamped under
// another document than the router's passes when its entry is the same in
// both, and is refused when the entry differs, is missing from either, or the
// stamped document cannot be fetched. Each document is fetched once.
func TestB8BackendEntry(t *testing.T) {
	web, api := entryOf(t, 1), entryOf(t, 2)
	doc := func(workloads map[string]allowlist.Workload) *allowlist.Allowlist {
		return &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: workloads}
	}
	hist := &fakeHistory{calls: map[[sha256.Size]byte]int{}, docs: map[[sha256.Size]byte]*allowlist.Allowlist{
		// The router's: testDigest.
		[sha256.Size]byte(testDigest): doc(map[string]allowlist.Workload{"web": web, "api": api}),
		// Another entry changed, web did not.
		[sha256.Size]byte(digestOf(0x43)): doc(map[string]allowlist.Workload{"web": web, "api": entryOf(t, 3)}),
		// web redefined.
		[sha256.Size]byte(digestOf(0x44)): doc(map[string]allowlist.Workload{"web": entryOf(t, 4), "api": api}),
		// web absent.
		[sha256.Size]byte(digestOf(0x45)): doc(map[string]allowlist.Workload{"api": api}),
	}}
	f := newFixture(t)
	f.transports = NewTransports(TransportConfig{MeshIdentity: f.identity.Credential, Allowlist: hist})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: newFakeBindings(nil), Timeout: 10 * time.Second})

	tests := []struct {
		name   string
		digest []byte
		want   int
	}{
		{"same digest", testDigest, http.StatusOK},
		{"other digest, entry unchanged", digestOf(0x43), http.StatusOK},
		{"other digest, entry unchanged, again", digestOf(0x43), http.StatusOK},
		{"entry redefined", digestOf(0x44), http.StatusBadGateway},
		{"entry not in the stamped document", digestOf(0x45), http.StatusBadGateway},
		{"stamped document not in history", digestOf(0x46), http.StatusBadGateway},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", tc.digest))
			f.apply(t, simpleManifest(uint64(i+1), b.addr()))
			if w := f.get("/"); w.Code != tc.want || (tc.want != http.StatusOK && !strings.Contains(w.Body.String(), backendDigestMismatch)) {
				t.Fatalf("GET / = %d %q, want %d", w.Code, w.Body.String(), tc.want)
			}
			// A session bound to the router digest (#1059) sees the same.
			f.proxy.log = slog.New(slog.DiscardHandler)
			sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
			resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, f.bound())
			if err != nil || resp.Status != tc.want {
				t.Fatalf("Forward(/) = %d %q, %v, want %d", resp.Status, resp.Body, err, tc.want)
			}
		})
	}
	if n := hist.fetches(testDigest); n != 1 {
		t.Errorf("router document fetched %d times, want 1", n)
	}
	if n := hist.fetches(digestOf(0x43)); n != 1 {
		t.Errorf("stamped document fetched %d times, want 1", n)
	}
}

// TestB8RouterEntryMissing: a backend whose entry the router's own document
// lacks is refused, even when the stamped document has it.
func TestB8RouterEntryMissing(t *testing.T) {
	hist := &fakeHistory{calls: map[[sha256.Size]byte]int{}, docs: map[[sha256.Size]byte]*allowlist.Allowlist{
		[sha256.Size]byte(testDigest):     {Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"api": entryOf(t, 2)}},
		[sha256.Size]byte(digestOf(0x43)): {Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"web": entryOf(t, 1)}},
	}}
	f := newFixture(t)
	f.transports = NewTransports(TransportConfig{MeshIdentity: f.identity.Credential, Allowlist: hist})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: newFakeBindings(nil), Timeout: 10 * time.Second})
	b := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, b.addr()))
	if w := f.get("/"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), backendDigestMismatch) {
		t.Fatalf("GET / = %d %q, want 502 %s", w.Code, w.Body.String(), backendDigestMismatch)
	}
}
