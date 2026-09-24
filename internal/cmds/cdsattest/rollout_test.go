package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		Rollout:              newRollout(cdsSrv.URL, identity.caFile),
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

func TestRolloutVerifyPeer(t *testing.T) {
	stamped := writeStampedMeshIdentity(t, "model").leaf
	inBound := "sha256:" + strings.Repeat("42", 32)
	for _, tc := range []struct {
		name  string
		leaf  *x509.Certificate
		bound []string
		ok    bool
	}{
		{"stamp in bound", stamped, []string{"sha256:p", inBound}, true},
		{"stamp outside bound", stamped, []string{"sha256:p"}, false},
		{"no stamp", writeTestMeshIdentity(t).leaf, []string{inBound}, false},
	} {
		r := newRollout("", "")
		r.bound = tc.bound
		if err := r.verifyPeer(tc.leaf); (err == nil) != tc.ok {
			t.Errorf("%s: verifyPeer = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestHTTPBackendRunsVerifyPeer(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, refuse := range []bool{false, true} {
		backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{
			TrustedCAFile: caFile,
			ServerName:    "example.com",
			VerifyPeer: func(*x509.Certificate) error {
				if refuse {
					return errors.New("refused")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = backend.Forward(context.Background(), types.TunnelRequest{Method: http.MethodGet, Path: "/"})
		if (err != nil) != refuse {
			t.Errorf("Forward with VerifyPeer refusing=%v: %v", refuse, err)
		}
	}
}

func TestLBForwarderFencesConnections(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(connectionTimeHeader) != "" {
			t.Error("connection time header leaked upstream")
		}
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fence := newRollout("", "")
	forwarder, err := newLBForwarder(fence, backend, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(connectionTimeHeader, "0.001")
	w := httptest.NewRecorder()
	forwarder.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("request before the first state read = %d, want 503", w.Code)
	}
	fence.lease = 30 * time.Second
	fence.seenAt = time.Now()
	fence.widenedAt = time.Now().Add(-10 * time.Second)
	status := func(connectionTime string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		if connectionTime != "" {
			req.Header.Set(connectionTimeHeader, connectionTime)
		}
		w := httptest.NewRecorder()
		forwarder.ServeHTTP(w, req)
		return w.Code
	}

	for _, tc := range []struct {
		name           string
		connectionTime string
		want           int
	}{
		{"connection opened after the last widening", "1.500", http.StatusOK},
		{"connection older than the last widening", "20.000", http.StatusServiceUnavailable},
		{"no connection time", "", http.StatusForbidden},
		{"unrepresentable connection time", "1e20", http.StatusForbidden},
	} {
		if got := status(tc.connectionTime); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
	}
	fence.seenAt = time.Now().Add(-time.Minute)
	if got := status("1.500"); got != http.StatusServiceUnavailable {
		t.Errorf("stale state: status %d, want 503", got)
	}
}

func TestAttestLBCarriesRolloutState(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	certPath, _ := writeTestServingLeaf(t)
	srv := NewServer(Config{
		Evidence:             &capturingProvider{},
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Rollout:              newRollout(cdsSrv.URL, identity.caFile),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	var st types.RolloutState
	if b.CDSState == nil || json.Unmarshal(b.CDSState.State, &st) != nil || st.Nonce != hex.EncodeToString(nonce) {
		t.Fatalf("attest-lb bundle state = %+v, want the state bound to nonce %x", b.CDSState, nonce)
	}
}
