package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/types"
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
	sum := sha512.Sum384(signed.State)
	if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], signed.Signature) {
		t.Fatal("state signature does not verify")
	}
	var st allowlist.State
	if err := json.Unmarshal(signed.State, &st); err != nil {
		t.Fatal(err)
	}
	if st.Nonce != nonce || len(st.Bound) != 1 {
		t.Fatalf("state = %+v, want nonce %s and a single-policy bound", st, nonce)
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
