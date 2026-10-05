package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestJournalRoutes(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	r := newRouter(dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs},
		AllowlistHandler: allowlist.Handler{Store: &store},
		ReadyFn:          func() bool { return true },
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
		StateKey:         key,
	})

	nonce := strings.Repeat("ab", 16)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, wellKnown+"/state/challenge", strings.NewReader(`{"nonce":"`+nonce+`"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST state/challenge = %d: %s", w.Code, w.Body)
	}
	var signed types.SignedRolloutState
	if err := json.Unmarshal(w.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if !rolloutstate.Verify(&key.PublicKey, rolloutstate.ContextChallenge, signed.State, signed.Signature) {
		t.Fatal("state signature does not verify")
	}
	if rolloutstate.Verify(&key.PublicKey, rolloutstate.ContextState, signed.State, signed.Signature) {
		t.Fatal("a challenge state verifies under the state context")
	}
	var st allowlist.State
	if err := json.Unmarshal(signed.State, &st); err != nil {
		t.Fatal(err)
	}
	if st.Nonce != nonce || len(st.Bound) != 1 {
		t.Fatalf("state = %+v, want nonce %s and a single-policy bound", st, nonce)
	}
	if err := rolloutstate.CheckTime(&st, time.Now()); err != nil {
		t.Fatalf("served state validity window: %v", err)
	}

	for _, tc := range []struct {
		path string
		want int
	}{
		{wellKnown + "/objects/sha256/" + strings.TrimPrefix(st.Policy, "sha256:"), http.StatusOK},
		{wellKnown + "/objects/sha256/" + strings.TrimPrefix(st.Head, "sha256:"), http.StatusOK},
		{wellKnown + "/objects/sha256/" + strings.Repeat("0", 64), http.StatusNotFound},
		{wellKnown + "/objects/sha256/XYZ", http.StatusBadRequest},
		{wellKnown + "/allowlist/latest", http.StatusOK},
		{wellKnown + "/state", http.StatusOK},
	} {
		if code := get(t, r, http.MethodGet, tc.path); code != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, code, tc.want)
		}
	}
	if code := get(t, r, http.MethodPost, wellKnown+"/state/challenge"); code != http.StatusBadRequest {
		t.Errorf("POST state/challenge without nonce = %d, want 400", code)
	}
}

// The journal's policy digest is the one leaf stamps carry, so a client can
// compare a stamp against the rollout bound.
func TestJournalPolicyMatchesSnapshotDigest(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	snapshot, err := loadPolicySnapshot(&store)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.State()
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:" + hex.EncodeToString(snapshot.Digest); st.Policy != want {
		t.Fatalf("journal policy = %s, want snapshot digest %s", st.Policy, want)
	}
}

type fakeAcker map[string]workloadclaims.PolicyAck

func (f fakeAcker) PolicyAck(_ context.Context, host string) (workloadclaims.PolicyAck, error) {
	ack, ok := f[host]
	if !ok {
		return ack, errors.New("unreachable")
	}
	return ack, nil
}

func TestNodeAcks(t *testing.T) {
	clean := workloadclaims.PolicyAck{Policy: "sha256:q", Clean: true}
	for _, tc := range []struct {
		name  string
		hosts []string
		acks  fakeAcker
		ok    bool
	}{
		{"every node clean", []string{"10.0.0.1", "10.0.0.2"}, fakeAcker{"10.0.0.1": clean, "10.0.0.2": clean}, true},
		{"no nodes known", nil, fakeAcker{}, false},
		{"node unreachable", []string{"10.0.0.1", "10.0.0.2"}, fakeAcker{"10.0.0.1": clean}, false},
		{"node on another policy", []string{"10.0.0.1"}, fakeAcker{"10.0.0.1": {Policy: "sha256:p", Clean: true}}, false},
		{"node still running a denied container", []string{"10.0.0.1"}, fakeAcker{"10.0.0.1": {Policy: "sha256:q"}}, false},
	} {
		acks := nodeAcks{client: tc.acks, hosts: func() []string { return tc.hosts }}
		if ok, nodes := acks.acked(context.Background(), "sha256:q"); ok != tc.ok || (ok && !slices.Equal(nodes, tc.hosts)) {
			t.Errorf("%s: acked = %v, want %v", tc.name, ok, tc.ok)
		}
	}
}

// journalLoop drains a widened bound once every node acknowledges the
// enforced policy, and not before.
func TestJournalLoopDrainsOnAcks(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := startJournal(&store, "sha256:auth", config{}); err != nil {
		t.Fatal(err)
	}
	w := pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: digest(t, digestA)}}}
	if err := store.PutWorkload("a", w); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteWorkload("a"); err != nil {
		t.Fatal(err)
	}
	st, err := store.State()
	if err != nil || len(st.Bound) != 2 {
		t.Fatalf("state after a narrowing = %+v, %v; want a 2-entry bound", st, err)
	}
	var mu sync.Mutex
	acker := fakeAcker{"10.0.0.1": {Policy: st.Policy}}
	acks := &nodeAcks{client: lockedAcker{&mu, acker}, hosts: func() []string { return []string{"10.0.0.1"} }, every: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go journalLoop(ctx, &store, time.Millisecond, acks)

	time.Sleep(50 * time.Millisecond)
	if st, _ := store.State(); len(st.Bound) != 2 {
		t.Fatalf("bound = %v with a node not clean, want it kept", st.Bound)
	}
	mu.Lock()
	acker["10.0.0.1"] = workloadclaims.PolicyAck{Policy: st.Policy, Clean: true}
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, _ := store.State(); len(st.Bound) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("bound not drained after every node acknowledged the enforced policy")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type lockedAcker struct {
	mu *sync.Mutex
	f  fakeAcker
}

func (l lockedAcker) PolicyAck(ctx context.Context, host string) (workloadclaims.PolicyAck, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.PolicyAck(ctx, host)
}
