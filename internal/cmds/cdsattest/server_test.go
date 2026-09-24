package cdsattest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence: FixtureEvidenceProvider{
			Raw:        json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`),
			Platform:   "snp",
			Generation: "genoa",
		},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	return httptest.NewServer(srv.Handler())
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// postAttestPQ POSTs the client-first attest-pq request and returns the raw
// HTTP response.
func postAttestPQ(t *testing.T, base string, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(base+"/.well-known/c8s/attest-pq", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// fetchBundle establishes an attest-pq exchange with the given client key and
// nonce and returns the decoded bundle.
func fetchBundle(t *testing.T, base string, ck *overenc.ClientKey, nonce []byte) types.AttestationBundle {
	t.Helper()
	body, err := json.Marshal(types.AttestPQRequest{
		Nonce:   b64url(nonce),
		XWingEK: b64url(ck.EncapsulationKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := postAttestPQ(t, base, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attestation status %d", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

// clientChannelFromBundle does what a real client does after verifying the
// bundle: recompute the identity transcript from the served chain, decapsulate
// the server's ciphertext, and derive the channel.
func clientChannelFromBundle(t *testing.T, bundle types.AttestationBundle, ck *overenc.ClientKey, nonce []byte) (*overenc.Channel, string) {
	t.Helper()
	ct, err := base64.RawURLEncoding.DecodeString(bundle.XWingCT)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := base64.RawURLEncoding.DecodeString(bundle.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certutil.ParsePEMCertificates([]byte(bundle.CDSCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("bundle chain has %d certs, want leaf + issuing CA", len(certs))
	}
	transcript, err := overenc.IdentityTranscriptHash(bundle.FrontDoorMode, ck.EncapsulationKey(), ct, sessionID, nonce, certs[0].Raw, certs[1].Raw, stateDigest(bundle.CDSState))
	if err != nil {
		t.Fatal(err)
	}
	ss, err := ck.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := overenc.NewClientChannel(ss, transcript, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return channel, bundle.SessionID
}

func establishSession(t *testing.T, base string, nonce []byte) (*overenc.Channel, string) {
	t.Helper()
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, base, ck, nonce)
	return clientChannelFromBundle(t, bundle, ck, nonce)
}

func TestFullFlowOverEncryptedEcho(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, nonce)

	if bundle.Version != types.BindingAttestPQ || bundle.Platform != "snp" || bundle.Generation != "genoa" {
		t.Fatalf("unexpected bundle header: %+v", bundle)
	}
	if bundle.IdentityProof == nil {
		t.Fatalf("bundle is not identity-bound: %+v", bundle)
	}
	if bundle.Nonce != b64url(nonce) {
		t.Fatal("nonce not echoed")
	}
	if bundle.XWingEK != b64url(ck.EncapsulationKey()) {
		t.Fatal("encapsulation key not echoed")
	}
	ct, _ := base64.RawURLEncoding.DecodeString(bundle.XWingCT)
	if len(ct) != overenc.XWingCTBytes {
		t.Fatalf("xwing_ct = %d bytes, want %d", len(ct), overenc.XWingCTBytes)
	}
	sessionID, _ := base64.RawURLEncoding.DecodeString(bundle.SessionID)
	if len(sessionID) != overenc.SessionIDBytes {
		t.Fatalf("session_id = %d bytes, want %d", len(sessionID), overenc.SessionIDBytes)
	}

	channel, id := clientChannelFromBundle(t, bundle, ck, nonce)

	// Over-encrypted tunnel: seal a full request envelope, open the response.
	resp := tunnel(t, ts.URL, channel, id, types.TunnelRequest{
		Method:  "POST",
		Path:    "/v1/echo",
		Headers: []types.HeaderField{{Name: "Content-Type", Value: "application/json"}},
		Body:    []byte("hi enclave"),
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("tunnel response status %d", resp.Status)
	}
	if !strings.Contains(string(resp.Body), "hi enclave") {
		t.Fatalf("echo did not round-trip: %q", resp.Body)
	}
}

// tunnel seals req, posts it to the tunnel endpoint, and opens the response,
// verifying the response echoes the request's sequence.
func tunnel(t *testing.T, base string, ch *overenc.Channel, sessionID string, req types.TunnelRequest) types.TunnelResponse {
	t.Helper()
	plain, _ := cbor.Marshal(req)
	rec, err := ch.SealRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	recBody, _ := cbor.Marshal(rec)
	httpReq, _ := http.NewRequest(http.MethodPost, base+"/.well-known/c8s/tunnel", bytes.NewReader(recBody))
	httpReq.Header.Set("X-C8s-Session", sessionID)
	httpReq.Header.Set("Content-Type", "application/cbor")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("tunnel HTTP status %d", httpResp.StatusCode)
	}
	outBytes, _ := io.ReadAll(httpResp.Body)
	var outRec overenc.Record
	if err := cbor.Unmarshal(outBytes, &outRec); err != nil {
		t.Fatal(err)
	}
	respCBOR, err := ch.OpenResponse(outRec, rec.Seq)
	if err != nil {
		t.Fatal(err)
	}
	var resp types.TunnelResponse
	if err := cbor.Unmarshal(respCBOR, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func postSealedTunnel(t *testing.T, base string, ch *overenc.Channel, sessionID string, req types.TunnelRequest) *http.Response {
	t.Helper()
	plain, _ := cbor.Marshal(req)
	rec, err := ch.SealRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	recBody, _ := cbor.Marshal(rec)
	httpReq, _ := http.NewRequest(http.MethodPost, base+"/.well-known/c8s/tunnel", bytes.NewReader(recBody))
	httpReq.Header.Set("X-C8s-Session", sessionID)
	httpReq.Header.Set("Content-Type", "application/cbor")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	return httpResp
}

func TestTunnelForwardsToUpstream(t *testing.T) {
	// A real backend the sidecar forwards decrypted traffic to.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Exporter", r.Header.Get(exporterHeader))
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("upstream saw: " + r.URL.Path + " / " + string(body)))
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Backend:              hb,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)

	resp := tunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{
		Method: "PUT",
		Path:   "/v1/data",
		Headers: []types.HeaderField{
			{Name: "Authorization", Value: "Bearer sekret"},
			// A client-supplied exporter header must be stripped, never trusted.
			{Name: exporterHeader, Value: "spoofed"},
		},
		Body: []byte("payload"),
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.Status)
	}
	if !strings.Contains(string(resp.Body), "upstream saw: /v1/data / payload") {
		t.Fatalf("unexpected upstream body: %q", resp.Body)
	}
	if got := headerValues(resp.Headers, "X-Echo-Method"); len(got) != 1 || got[0] != "PUT" {
		t.Fatalf("method not forwarded: %q", got)
	}
	if got := headerValues(resp.Headers, "X-Echo-Auth"); len(got) != 1 || got[0] != "Bearer sekret" {
		t.Fatalf("Authorization not forwarded confidentially: %q", got)
	}
	if got := headerValues(resp.Headers, "X-Echo-Exporter"); len(got) != 1 || got[0] != b64url(channel.Exporter()) {
		t.Fatalf("exporter header = %q, want the channel exporter (spoofed value stripped)", got)
	}
}

// TestTunnelPreservesDuplicateHeaders: repeated fields ride the pair-based
// envelope intact in both directions, through the sealed tunnel and the
// backend hop — the header map that collapsed Set-Cookie is gone.
func TestTunnelPreservesDuplicateHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("X-Multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
			t.Errorf("duplicate request header not forwarded intact: %v", got)
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA"}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Backend:              hb,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)

	resp := tunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{
		Method: "GET",
		Path:   "/",
		Headers: []types.HeaderField{
			{Name: "X-Multi", Value: "one"},
			{Name: "X-Multi", Value: "two"},
		},
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("tunnel response status %d", resp.Status)
	}
	if got := headerValues(resp.Headers, "Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Fatalf("duplicate response header collapsed: %v", got)
	}
}

// The pre-client-first GET shape returns the explicit 400.
func TestAttestPQGetReturns400(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-pq?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
		t.Fatalf("error code = %q", e.Error)
	}
}

func TestTunnelRejectsIdleExpiredSession(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		SessionTTL:           time.Millisecond,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)
	time.Sleep(5 * time.Millisecond)

	resp := postSealedTunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for idle-expired session, got %d", resp.StatusCode)
	}
}

// A busy session still dies at the absolute lifetime: activity refreshes the
// idle TTL but never the max age.
func TestTunnelRejectsOverAgeSession(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		SessionTTL:           time.Minute,
		SessionMaxAge:        50 * time.Millisecond,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)

	// Keep the session busy past its absolute lifetime.
	deadline := time.Now().Add(120 * time.Millisecond)
	sawExpiry := false
	for time.Now().Before(deadline) {
		resp := postSealedTunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/"})
		code := resp.StatusCode
		resp.Body.Close()
		if code == http.StatusUnauthorized {
			sawExpiry = true
			break
		}
		if code != http.StatusOK {
			t.Fatalf("unexpected tunnel status %d", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawExpiry {
		t.Fatal("session survived its absolute max age under constant use")
	}
}

func TestAppRequiresSession(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/.well-known/c8s/tunnel", "application/json", strings.NewReader(`{"seq":1,"ct":"BB"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", resp.StatusCode)
	}
}

func TestHTTPBackendRejectsOversizedUpstreamResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), maxUpstreamResponseBytes+1))
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "GET", Path: "/"}); err == nil {
		t.Fatal("expected oversized upstream response error")
	}
}

// failingProvider always fails, to exercise the evidence-unavailable paths.
type failingProvider struct{}

func (failingProvider) Evidence(context.Context, []byte) (json.RawMessage, string, string, error) {
	return nil, "", "", errors.New("no TEE here")
}

func decodeErr(t *testing.T, resp *http.Response) types.ErrorResponse {
	t.Helper()
	defer resp.Body.Close()
	var e types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAttestPQRejectsBadRequests(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	validEK := b64url(make([]byte, overenc.XWingEKBytes))
	tests := []struct {
		name string
		body string
	}{
		{"not JSON", "{nope"},
		{"missing nonce", `{"xwing_ek":"` + validEK + `"}`},
		{"nonce not base64url", `{"nonce":"!!!","xwing_ek":"` + validEK + `"}`},
		{"nonce too short", `{"nonce":"` + b64url(make([]byte, nonceBytes-1)) + `","xwing_ek":"` + validEK + `"}`},
		{"nonce too long", `{"nonce":"` + b64url(make([]byte, nonceBytes+1)) + `","xwing_ek":"` + validEK + `"}`},
		{"missing ek", `{"nonce":"` + b64url(make([]byte, nonceBytes)) + `"}`},
		{"ek not base64url", `{"nonce":"` + b64url(make([]byte, nonceBytes)) + `","xwing_ek":"!!!"}`},
		{"ek too short", `{"nonce":"` + b64url(make([]byte, nonceBytes)) + `","xwing_ek":"` + b64url(make([]byte, overenc.XWingEKBytes-1)) + `"}`},
		{"ek too long", `{"nonce":"` + b64url(make([]byte, nonceBytes)) + `","xwing_ek":"` + b64url(make([]byte, overenc.XWingEKBytes+1)) + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := postAttestPQ(t, ts.URL, []byte(tc.body))
			if resp.StatusCode != http.StatusBadRequest {
				resp.Body.Close()
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if e := decodeErr(t, resp); e.Error != types.ErrorCodeInvalidRequest {
				t.Fatalf("error code = %q", e.Error)
			}
		})
	}
}

// TestCDSCertRouteAbsentWithoutCert: the optional cds-cert endpoint must not be
// mounted when no cert was supplied.
func TestCDSCertRouteAbsentWithoutCert(t *testing.T) {
	srv := NewServer(Config{Evidence: failingProvider{}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/c8s/cds-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when no cds cert is configured", resp.StatusCode)
	}
}

// An evidence provider that cannot produce a quote is a 502 with the versioned
// unavailable code on both split endpoints.
func TestAttestationEvidenceUnavailable(t *testing.T) {
	certPath, _ := writeTestServingLeaf(t)
	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             failingProvider{},
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(types.AttestPQRequest{Nonce: b64url(nonce), XWingEK: b64url(ck.EncapsulationKey())})
	pqResp := postAttestPQ(t, ts.URL, body)
	if pqResp.StatusCode != http.StatusBadGateway {
		pqResp.Body.Close()
		t.Fatalf("attest-pq: status = %d, want 502", pqResp.StatusCode)
	}
	if e := decodeErr(t, pqResp); e.Error != types.ErrorCodeAttestationUnavailable {
		t.Fatalf("attest-pq: error code = %q", e.Error)
	}

	lbResp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	if lbResp.StatusCode != http.StatusBadGateway {
		lbResp.Body.Close()
		t.Fatalf("attest-lb: status = %d, want 502", lbResp.StatusCode)
	}
	if e := decodeErr(t, lbResp); e.Error != types.ErrorCodeAttestationUnavailable {
		t.Fatalf("attest-lb: error code = %q", e.Error)
	}
}

func TestTunnelRejectsMalformedRecords(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	post := func(t *testing.T, sessionID string, body []byte) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader(body))
		req.Header.Set("X-C8s-Session", sessionID)
		req.Header.Set("Content-Type", "application/cbor")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("body is not CBOR", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		_, sessionID := establishSession(t, ts.URL, nonce)
		resp := post(t, sessionID, []byte("notcbor"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})

	t.Run("record does not decrypt", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		_, sessionID := establishSession(t, ts.URL, nonce)
		garbage, _ := cbor.Marshal(overenc.Record{Seq: 1, CT: []byte("garbage-ciphertext")})
		resp := post(t, sessionID, garbage)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})

	t.Run("replayed record", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		channel, sessionID := establishSession(t, ts.URL, nonce)
		plain, _ := cbor.Marshal(types.TunnelRequest{Method: "GET", Path: "/"})
		rec, err := channel.SealRequest(plain)
		if err != nil {
			t.Fatal(err)
		}
		recBody, _ := cbor.Marshal(rec)
		first := post(t, sessionID, recBody)
		first.Body.Close()
		if first.StatusCode != http.StatusOK {
			t.Fatalf("first submission status = %d", first.StatusCode)
		}
		replay := post(t, sessionID, recBody)
		if replay.StatusCode != http.StatusBadRequest {
			t.Fatalf("replay status = %d, want 400", replay.StatusCode)
		}
		if e := decodeErr(t, replay); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})

	t.Run("plaintext is not a request envelope", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		channel, sessionID := establishSession(t, ts.URL, nonce)
		plain, _ := cbor.Marshal(42) // decrypts fine, but is not a TunnelRequest
		rec, err := channel.SealRequest(plain)
		if err != nil {
			t.Fatal(err)
		}
		recBody, _ := cbor.Marshal(rec)
		resp := post(t, sessionID, recBody)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		if e := decodeErr(t, resp); e.Error != types.ErrorCodeChannelError {
			t.Fatalf("error code = %q", e.Error)
		}
	})
}

func TestTunnelSealsBackendErrorAs502(t *testing.T) {
	// An upstream that is already gone: Forward errors, and the sidecar must
	// seal a 502 back rather than fail the tunnel HTTP exchange.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	hb, err := NewHTTPBackend(deadURL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	identity := writeTestMeshIdentity(t)
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA"}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		Backend:              hb,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	channel, sessionID := establishSession(t, ts.URL, nonce)

	resp := tunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/v1/x"})
	if resp.Status != http.StatusBadGateway {
		t.Fatalf("sealed status = %d, want 502", resp.Status)
	}
}

func TestServingLeafErrors(t *testing.T) {
	dir := t.TempDir()
	notCert := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(notCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600); err != nil {
		t.Fatal(err)
	}
	badDER := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		file string
	}{
		{"missing file", filepath.Join(dir, "nope.pem")},
		{"not a certificate PEM", notCert},
		{"garbage certificate DER", badDER},
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(Config{Evidence: &capturingProvider{}, FrontDoorMode: types.FrontDoorModeCDS, ServingCertFile: tc.file})
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			resp, err := http.Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", resp.StatusCode)
			}
			if e := decodeErr(t, resp); e.Error != types.ErrorCodeBindingUnavailable {
				t.Fatalf("error code = %q", e.Error)
			}
		})
	}
}
