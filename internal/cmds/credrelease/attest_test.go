package credrelease

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type evidenceGeneratorFunc func(context.Context, []byte) (teetypes.AttestationEvidence, error)

func (f evidenceGeneratorFunc) GenerateEvidence(ctx context.Context, nonce []byte) (teetypes.AttestationEvidence, error) {
	return f(ctx, nonce)
}

func newAttestHandler(t *testing.T) (*Handler, *operatorauth.Signer) {
	t.Helper()
	signer, pub := newOperatorAuth(t)
	handler, err := NewHandler(pub, nil, defaultRoles())
	if err != nil {
		t.Fatal(err)
	}
	return handler, signer
}

func attestBody(t *testing.T, n int) []byte {
	t.Helper()
	body, err := json.Marshal(AttestRequest{Nonce: bytes.Repeat([]byte{0x7a}, n)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedAttestRequest(t *testing.T, ctx context.Context, url string, body []byte, signer *operatorauth.Signer) *http.Request {
	t.Helper()
	req, err := operatorauth.NewRequest(ctx, http.MethodPost, url, body, signer)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// Every refused request must fail before accessing the guest's attester.
func TestAttestRefusesInvalidRequests(t *testing.T) {
	h, signer := newAttestHandler(t)
	otherSigner, _ := newOperatorAuth(t)
	validBody := attestBody(t, 32)
	for _, tc := range []struct {
		name, method, path string
		body, signedBody   []byte
		signer             *operatorauth.Signer
		want               int
	}{
		{name: "missing authorization", body: validBody, want: http.StatusUnauthorized},
		{name: "wrong operator", body: validBody, signer: otherSigner, want: http.StatusUnauthorized},
		{name: "token bound to different nonce", body: validBody, signedBody: attestBody(t, 31), signer: signer, want: http.StatusUnauthorized},
		{name: "short nonce", body: attestBody(t, 31), signer: signer, want: http.StatusBadRequest},
		{name: "long nonce", body: attestBody(t, 33), signer: signer, want: http.StatusBadRequest},
		{name: "missing nonce", body: []byte("{}"), signer: signer, want: http.StatusBadRequest},
		{name: "null nonce", body: []byte(`{"nonce":null}`), signer: signer, want: http.StatusBadRequest},
		{name: "invalid base64", body: []byte(`{"nonce":"!"}`), signer: signer, want: http.StatusBadRequest},
		{name: "bad JSON", body: []byte("{"), signer: signer, want: http.StatusBadRequest},
		{name: "trailing JSON", body: append(bytes.Clone(validBody), []byte("{}")...), signer: signer, want: http.StatusBadRequest},
		{name: "trailing garbage", body: append(bytes.Clone(validBody), 'x'), signer: signer, want: http.StatusBadRequest},
		{name: "caller platform", body: bytes.Replace(validBody, []byte("{"), []byte(`{"platform":"snp",`), 1), signer: signer, want: http.StatusBadRequest},
		{name: "caller upstream", body: bytes.Replace(validBody, []byte("{"), []byte(`{"url":"http://other",`), 1), signer: signer, want: http.StatusBadRequest},
		{name: "oversize", body: append(bytes.Clone(validBody), bytes.Repeat([]byte(" "), maxBodyBytes)...), signer: signer, want: http.StatusRequestEntityTooLarge},
		{name: "GET", method: http.MethodGet, body: validBody, signer: signer, want: http.StatusMethodNotAllowed},
		{name: "other API", path: "/verify", body: validBody, signer: signer, want: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h.attester = evidenceGeneratorFunc(func(context.Context, []byte) (teetypes.AttestationEvidence, error) {
				called = true
				return teetypes.AttestationEvidence{}, nil
			})
			method, path := tc.method, tc.path
			if method == "" {
				method = http.MethodPost
			}
			if path == "" {
				path = AttestPath
			}
			req := httptest.NewRequest(method, path, bytes.NewReader(tc.body))
			if tc.signer != nil {
				signedBody := tc.signedBody
				if signedBody == nil {
					signedBody = tc.body
				}
				auth, err := tc.signer.Authorization(method, path, signedBody)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if called {
				t.Error("refused request reached attester")
			}
		})
	}
}

func TestAttestPreservesNonceAndEvidence(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			h, signer := newAttestHandler(t)
			want := teetypes.AttestationEvidence{
				Platform: platform,
				Evidence: json.RawMessage(`{"quote":"bm9uY2UtYm91bmQ="}`),
			}
			h.attester = evidenceGeneratorFunc(func(ctx context.Context, nonce []byte) (teetypes.AttestationEvidence, error) {
				if !bytes.Equal(nonce, bytes.Repeat([]byte{0x7a}, 32)) {
					t.Errorf("attester nonce = %x", nonce)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > attestTimeout {
					t.Error("attester context has no bounded timeout")
				}
				return want, nil
			})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, signedAttestRequest(t, context.Background(), AttestPath, attestBody(t, 32), signer))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			var got teetypes.AttestationEvidence
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Platform != want.Platform || !bytes.Equal(got.Evidence, want.Evidence) {
				t.Errorf("evidence was changed or wrapped twice: %s", rec.Body.String())
			}
			if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("response headers = %v", rec.Header())
			}
		})
	}
}

func TestAttestUpstreamFailureAndCancellation(t *testing.T) {
	for _, mode := range []string{"unconfigured", "failure", "canceled", "invalid evidence"} {
		t.Run(mode, func(t *testing.T) {
			h, signer := newAttestHandler(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantStatus := http.StatusBadGateway
			switch mode {
			case "unconfigured":
				wantStatus = http.StatusServiceUnavailable
			case "failure":
				h.attester = evidenceGeneratorFunc(func(context.Context, []byte) (teetypes.AttestationEvidence, error) {
					return teetypes.AttestationEvidence{}, errors.New("private upstream failure detail")
				})
			case "canceled":
				cancel()
				h.attester = evidenceGeneratorFunc(func(ctx context.Context, _ []byte) (teetypes.AttestationEvidence, error) {
					if !errors.Is(ctx.Err(), context.Canceled) {
						t.Errorf("upstream context = %v, want canceled", ctx.Err())
					}
					return teetypes.AttestationEvidence{}, ctx.Err()
				})
			case "invalid evidence":
				h.attester = evidenceGeneratorFunc(func(context.Context, []byte) (teetypes.AttestationEvidence, error) {
					return teetypes.AttestationEvidence{Evidence: json.RawMessage("{")}, nil
				})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, signedAttestRequest(t, ctx, AttestPath, attestBody(t, 32), signer))
			if rec.Code != wantStatus || rec.Body.String() != "attestation unavailable\n" {
				t.Errorf("response = %d %q, want generic error %d", rec.Code, rec.Body.String(), wantStatus)
			}
		})
	}
}

// Exercise the actual Run wiring and local HTTP client for both platforms.
// The stub has unsigned evidence, so TLS trust is intentionally bypassed only
// in this server-routing test; operator authorization remains fully checked.
func TestRunServesAuthenticatedBootstrap(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			signer, pub := newOperatorAuth(t)
			stageMeasuredOperatorKey(t, pub)
			binding := tdxBinding(pub)
			if platform == teetypes.PlatformSNP {
				binding = snpBinding(pub)
			}
			stub := stubAttester(t, selfReport{platform: platform, binding: binding})
			dir := t.TempDir()
			clientCert, clientKey, _ := namedCA(t, dir, "client-ca")
			serverCert, _, _ := namedCA(t, dir, "server-ca")
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()
			cfg := Config{
				ListenAddr: addr, AttestationAPIURL: stub.URL(), Platform: string(platform),
				ClientCACert: clientCert, ClientCAKey: clientKey, ServerCACert: serverCert,
				CertTTL: defaultCertTTL, CertOrg: defaultCertOrg, CertCN: defaultCertCN,
				LogCertTTL: defaultLogCertTTL, LogCertOrg: defaultLogCertOrg, LogCertCN: defaultLogCertCN,
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("Run: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("Run did not stop")
				}
			})
			client := &http.Client{
				Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
				Timeout:   time.Second,
			}
			defer client.CloseIdleConnections()
			deadline := time.Now().Add(10 * time.Second)
			var resp *http.Response
			for {
				req := signedAttestRequest(t, ctx, "https://"+addr+AttestPath, attestBody(t, 32), signer)
				resp, err = client.Do(req)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("bootstrap service never became reachable: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d: %s", resp.StatusCode, data)
			}
			var envelope teetypes.AttestationEvidence
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Platform != platform || len(envelope.Evidence) == 0 {
				t.Errorf("bad evidence envelope: %s", data)
			}
			found := 0
			for _, req := range stub.AttestRequests() {
				if bytes.Equal(req.ReportData, bytes.Repeat([]byte{0x7a}, 32)) {
					found++
					if req.Platform != remote.PlatformAuto {
						t.Errorf("upstream platform = %q, want automatic detection", req.Platform)
					}
				}
			}
			if found != 1 {
				t.Errorf("bootstrap nonce forwarded %d times, want once", found)
			}

			stub.Close()
			req := signedAttestRequest(t, ctx, "https://"+addr+AttestPath, attestBody(t, 32), signer)
			failed, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer failed.Body.Close()
			detail, _ := io.ReadAll(failed.Body)
			if failed.StatusCode != http.StatusBadGateway || strings.TrimSpace(string(detail)) != "attestation unavailable" {
				t.Errorf("upstream failure response = %d %s", failed.StatusCode, detail)
			}
		})
	}
}

// The response lists the journal as read after the quote, and omits it when
// the node journals nothing.
func TestAttestCarriesMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	for _, tc := range []struct {
		name, journal string
		want          []string
	}{
		{name: "journal", journal: p + "\n", want: []string{p}},
		{name: "no journal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setMeasuredPolicies(t, tc.journal)
			h, signer := newAttestHandler(t)
			h.attester = evidenceGeneratorFunc(func(context.Context, []byte) (teetypes.AttestationEvidence, error) {
				return teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)}, nil
			})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, signedAttestRequest(t, context.Background(), AttestPath, attestBody(t, 32), signer))
			var got AttestResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("response = %d %s, %v", rec.Code, rec.Body, err)
			}
			if !slices.Equal(got.RuntimeExtensions, tc.want) {
				t.Errorf("runtime_extensions = %v, want %v", got.RuntimeExtensions, tc.want)
			}
		})
	}
}
