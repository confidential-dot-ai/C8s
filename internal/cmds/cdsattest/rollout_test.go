package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeCDSState serves /state and /state/challenge with a settable bound.
type fakeCDSState struct {
	mu    sync.Mutex
	bound []string
	key   *ecdsa.PrivateKey
}

func (f *fakeCDSState) setKey(key *ecdsa.PrivateKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = key
}

func (f *fakeCDSState) setBound(bound ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound = bound
}

func (f *fakeCDSState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	st := types.RolloutState{Bound: f.bound, Lease: 30}
	key := f.key
	f.mu.Unlock()
	if r.Method == http.MethodPost {
		var req struct{ Nonce string }
		json.NewDecoder(r.Body).Decode(&req)
		st.Nonce = req.Nonce
	}
	body, _ := json.Marshal(st)
	sum := sha512.Sum384(body)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	json.NewEncoder(w).Encode(types.SignedRolloutState{State: body, Signature: sig})
}

func TestRolloutFencesSessions(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		CDSStateURL:          cdsSrv.URL,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, nonce)
	if bundle.CDSState == nil {
		t.Fatal("bundle carries no CDS state")
	}
	var st types.RolloutState
	if err := json.Unmarshal(bundle.CDSState.State, &st); err != nil || st.Nonce != hex.EncodeToString(nonce) {
		t.Fatalf("bundle state = %+v (%v), want nonce %x", st, err, nonce)
	}
	channel, sessionID := clientChannelFromBundle(t, bundle, ck, nonce)
	status := func() int {
		resp := postSealedTunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/"})
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := status(); code != http.StatusOK {
		t.Fatalf("tunnel inside the envelope = %d, want 200", code)
	}

	srv.rollout.mu.Lock()
	srv.rollout.seenAt = time.Now().Add(-time.Minute)
	srv.rollout.mu.Unlock()
	if code := status(); code != http.StatusUnauthorized {
		t.Fatalf("tunnel on a state older than the lease = %d, want 401", code)
	}
	if _, err := srv.rollout.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code := status(); code != http.StatusOK {
		t.Fatalf("tunnel after a fresh poll = %d, want 200", code)
	}

	foreign, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cds.setKey(foreign)
	if _, err := srv.rollout.poll(context.Background()); err == nil {
		t.Fatal("poll accepted a state the mesh CA did not sign")
	}
	cds.setKey(identity.caKey)

	cds.setBound("sha256:p", "sha256:q")
	if _, err := srv.rollout.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code := status(); code != http.StatusUnauthorized {
		t.Fatalf("tunnel after the bound widened = %d, want 401", code)
	}
	cds.setBound("sha256:p")
	if _, err := srv.rollout.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code := status(); code != http.StatusUnauthorized {
		t.Fatalf("widened-out session came back = %d, want 401", code)
	}
}
