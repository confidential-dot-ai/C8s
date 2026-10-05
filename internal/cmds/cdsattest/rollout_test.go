package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeCDSState serves /state and /state/challenge with a settable bound.
type fakeCDSState struct {
	mu    sync.Mutex
	bound []string
	key   *ecdsa.PrivateKey
	age   time.Duration // shifts issued_at; negative issues stale states

	authority string
	position  uint64
	head      string

	protocol     int  // 0 serves protocol 1
	stateContext bool // signs GET /state under the challenge context
}

func (f *fakeCDSState) setJournal(authority string, position uint64, head string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authority, f.position, f.head = authority, position, head
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
	protocol := f.protocol
	if protocol == 0 {
		protocol = 1
	}
	st := types.RolloutState{Protocol: protocol, Authority: f.authority, Position: f.position, Head: f.head, Bound: f.bound, Lease: 30}
	rolloutstate.Stamp(&st, time.Now().Add(f.age))
	key := f.key
	f.mu.Unlock()
	sigContext := rolloutstate.ContextState
	if f.stateContext {
		sigContext = rolloutstate.ContextChallenge
	}
	if r.Method == http.MethodPost {
		var req struct{ Nonce string }
		json.NewDecoder(r.Body).Decode(&req)
		st.Nonce = req.Nonce
		sigContext = rolloutstate.ContextChallenge
	}
	body, _ := json.Marshal(st)
	sig, _ := rolloutstate.Sign(key, sigContext, body)
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
	policy := func(entries map[string]string) []byte {
		doc := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{}}
		for name, label := range entries {
			doc.Workloads[name] = pkgallowlist.Workload{Label: label, Containers: []pkgallowlist.Container{}}
		}
		b, err := doc.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p := policy(map[string]string{"model": "a", "other": "x"})
	q := policy(map[string]string{"model": "a", "other": "y"})
	r := policy(map[string]string{"model": "b"})
	objects := map[string][]byte{}
	digest := func(b []byte) (string, []byte) {
		sum := sha256.Sum256(b)
		d := "sha256:" + hex.EncodeToString(sum[:])
		objects["/.well-known/c8s/objects/sha256/"+hex.EncodeToString(sum[:])] = b
		return d, sum[:]
	}
	pd, pRaw := digest(p)
	qd, qRaw := digest(q)
	rd, _ := digest(r)
	tampered := sha256.Sum256([]byte("tampered"))
	objects["/.well-known/c8s/objects/sha256/"+hex.EncodeToString(tampered[:])] = p
	objSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, ok := objects[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(b)
	}))
	defer objSrv.Close()

	leaf := func(name string, d []byte) *x509.Certificate {
		ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{Name: name, AllowlistVersion: "1", AllowlistDigest: d})
		if err != nil {
			t.Fatal(err)
		}
		return writeTestMeshIdentityWithLeafExtensions(t, ext).leaf
	}
	for _, tc := range []struct {
		name     string
		leaf     *x509.Certificate
		bound    []string
		workload string
		ok       bool
	}{
		{"stamp in bound", leaf("model", qRaw), []string{qd}, "", true},
		{"entry unchanged since the stamp", leaf("model", pRaw), []string{qd}, "", true},
		{"entry changed since the stamp", leaf("other", pRaw), []string{qd}, "", false},
		{"entry changed in every bound policy", leaf("model", pRaw), []string{rd}, "", false},
		{"stamped policy does not match its digest", leaf("model", tampered[:]), []string{qd}, "", false},
		{"expected workload", leaf("model", qRaw), []string{qd}, "model", true},
		{"other workload", leaf("model", qRaw), []string{qd}, "other", false},
		{"no stamp", writeTestMeshIdentity(t).leaf, []string{pd}, "", false},
	} {
		fence := newRollout(objSrv.URL, "")
		fence.bound, fence.workload = tc.bound, tc.workload
		if err := fence.verifyPeer(tc.leaf); (err == nil) != tc.ok {
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
		if r.Header.Get(connectionTimeHeader) != "" || r.Header.Get(verifiedStateHeader) != "" {
			t.Error("fence header leaked upstream")
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
	fence.head = "sha256:h1"
	status := func(connectionTime string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		if connectionTime != "" {
			req.Header.Set(connectionTimeHeader, connectionTime)
		}
		req.Header.Set(verifiedStateHeader, "sha256:h1")
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
		{"NaN connection time", "NaN", http.StatusForbidden},
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

func TestRolloutZeroLeaseIsNotFreshForever(t *testing.T) {
	r := newRollout("", "")
	now := time.Now()
	if r.fresh(now) {
		t.Fatal("fresh before any state read")
	}
	r.seenAt = now
	if !r.fresh(now.Add(time.Second)) {
		t.Fatal("zero-lease state is stale one second after the read")
	}
	if r.fresh(now.Add(zeroLeaseMaxStateAge)) {
		t.Fatal("zero-lease state is still fresh after zeroLeaseMaxStateAge")
	}
	if r.fresh(now.Add(24 * time.Hour)) {
		t.Fatal("zero-lease state is fresh forever")
	}
	r.lease = time.Minute
	if !r.fresh(now.Add(29*time.Second)) || r.fresh(now.Add(30*time.Second)) {
		t.Fatal("a positive lease does not bound freshness to half of it")
	}
}

func TestRolloutExpireCancelsForwards(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	resets := 0
	fence.onBoundChange(func() { resets++ })
	ctx, cancel := fence.requestContext(context.Background())
	defer cancel()

	fence.expire(time.Now())
	if ctx.Err() != nil {
		t.Fatal("expire cancelled a request on a fresh state")
	}
	fence.expire(time.Now().Add(time.Hour))
	waitDone(t, ctx)
	if !errors.Is(context.Cause(ctx), errStateExpired) || resets != 1 {
		t.Fatalf("after expiry: cause %v, resets %d; want errStateExpired, 1", context.Cause(ctx), resets)
	}
	fence.expire(time.Now().Add(time.Hour))
	if resets != 1 {
		t.Fatalf("a second expire on the same stale state reset the pool again (%d resets)", resets)
	}
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	fresh, cancelFresh := fence.requestContext(context.Background())
	defer cancelFresh()
	fence.expire(time.Now().Add(time.Hour))
	waitDone(t, fresh)
	if !errors.Is(context.Cause(fresh), errStateExpired) {
		t.Fatal("a new read did not re-arm expiry")
	}
}

// waitDone waits for ctx, which context.AfterFunc cancels asynchronously.
func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("request context not cancelled")
	}
}

func TestRolloutRefusesExpiredState(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey, age: -(rolloutstate.Validity + rolloutstate.MaxClockSkew + time.Minute)}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	if _, err := fence.poll(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("poll of an expired state = %v, want an expiry error", err)
	}
	if fence.fresh(time.Now()) {
		t.Fatal("an expired state made the fence fresh")
	}
}

func TestRolloutRefusesJournalRegression(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	poll := func() error {
		_, err := fence.poll(context.Background())
		return err
	}

	cds.setJournal("sha256:a", 5, "sha256:h5")
	if err := poll(); err != nil {
		t.Fatal(err)
	}
	cds.setJournal("sha256:a", 6, "sha256:h6")
	if err := poll(); err != nil {
		t.Fatalf("forward progress refused: %v", err)
	}
	cds.setJournal("sha256:a", 6, "sha256:h6")
	if err := poll(); err != nil {
		t.Fatalf("an unchanged head refused: %v", err)
	}
	cds.setJournal("sha256:a", 3, "sha256:h3")
	if err := poll(); err == nil || !strings.Contains(err.Error(), "backwards") {
		t.Fatalf("a lower position under the same authority = %v, want refused", err)
	}
	cds.setJournal("sha256:a", 6, "sha256:other")
	goodRead := fence.seenAt
	if err := poll(); err == nil || !strings.Contains(err.Error(), "forked") {
		t.Fatalf("another head at the same position = %v, want refused", err)
	}
	// The refused read does not refresh the fence: it closes once the last
	// good read ages out.
	if !fence.seenAt.Equal(goodRead) || fence.fresh(goodRead.Add(30*time.Second)) {
		t.Fatal("a refused state kept the fence open")
	}
	// A refused state is not stored.
	if fence.position != 6 || fence.head != "sha256:h6" {
		t.Fatalf("fence journal = %d %s, want 6 sha256:h6", fence.position, fence.head)
	}
	// A new authority (a CDS restart) may start over.
	cds.setJournal("sha256:b", 0, "sha256:g0")
	if err := poll(); err != nil {
		t.Fatalf("a new authority's journal refused: %v", err)
	}
	if fence.authority != "sha256:b" || fence.position != 0 {
		t.Fatalf("fence journal = %s %d, want sha256:b 0", fence.authority, fence.position)
	}
}

func TestLBForwarderRequiresVerifiedState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer upstream.Close()
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cds.setJournal("sha256:a", 1, "sha256:h1")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	forwarder, err := newLBForwarder(fence, backend, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	send := func(state string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(connectionTimeHeader, "0")
		if state != "" {
			req.Header.Set(verifiedStateHeader, state)
		}
		w := httptest.NewRecorder()
		forwarder.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	if code, body := send("sha256:h1"); code != http.StatusOK || body != "ok" {
		t.Fatalf("matching state = %d %q, want 200 forwarded", code, body)
	}
	if code, body := send(""); code != http.StatusOK || body != "ok" {
		t.Fatalf("absent state header = %d %q, want 200 forwarded", code, body)
	}
	cds.setJournal("sha256:a", 2, "sha256:h2")
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, body := send("sha256:h1"); code != http.StatusServiceUnavailable || !strings.Contains(body, "state changed: re-verify") {
		t.Fatalf("stale state = %d %q, want 503 re-verify", code, body)
	}
}

// A challenge signature (over a caller-chosen nonce) served as GET /state,
// or a state with an unknown protocol, is refused and leaves the fence closed.
func TestRolloutRefusesWrongContextAndProtocol(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	for _, cds := range []*fakeCDSState{
		{key: identity.caKey, stateContext: true},
		{key: identity.caKey, protocol: 2},
	} {
		cds.setBound("sha256:p")
		cdsSrv := httptest.NewServer(cds)
		fence := newRollout(cdsSrv.URL, identity.caFile)
		if _, err := fence.poll(context.Background()); err == nil {
			t.Errorf("poll accepted state (context swapped %v, protocol %d)", cds.stateContext, cds.protocol)
		}
		if fence.fresh(time.Now()) {
			t.Error("a refused state opened the fence")
		}
		cdsSrv.Close()
	}
}
