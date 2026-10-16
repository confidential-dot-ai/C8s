package attestclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("http://example.com/api/")
	if c.baseURL != "http://example.com/api" {
		t.Fatalf("expected trailing slash trimmed, got %q", c.baseURL)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.ChallengeResponse{
			Challenge: "dGVzdC1jaGFsbGVuZ2U=",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	resp, err := c.Authenticate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Challenge != "dGVzdC1jaGFsbGVuZ2U=" {
		t.Fatalf("expected challenge 'dGVzdC1jaGFsbGVuZ2U=', got %q", resp.Challenge)
	}
}

func TestObtainCertificateWithEvidenceReturnsAttestationMaterial(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	const certPEM = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"

	csrPEM := testCSRPEM(t)
	challengeBytes := []byte("test-challenge")
	expectedReportData, err := reportDataForCSR(csrPEM, challengeBytes)
	if err != nil {
		t.Fatalf("reportDataForCSR: %v", err)
	}

	var attestationApiSawReportData []byte
	attestationApi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Fatalf("attestation-api path = %s, want /attest", r.URL.Path)
		}
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode attestation request: %v", err)
		}
		attestationApiSawReportData = append([]byte(nil), req.ReportData...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"platform":"snp","evidence":{"quote":"abc"}}`)
	}))
	defer attestationApi.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: challenge})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		var req attestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode cds attest request: %v", err)
		}
		if req.Challenge != challenge {
			t.Fatalf("challenge = %q, want %q", req.Challenge, challenge)
		}
		if req.Evidence.Platform != "snp" {
			t.Fatalf("platform = %q, want snp", req.Evidence.Platform)
		}
		if !strings.Contains(string(req.Evidence.Evidence), `"quote":"abc"`) {
			t.Fatalf("evidence = %s, want quote", req.Evidence.Evidence)
		}
		_, _ = io.WriteString(w, certPEM)
	})
	cds := httptest.NewServer(mux)
	defer cds.Close()

	client := NewClientWithHTTP(cds.URL, cds.Client())
	result, err := client.ObtainCertificateWithEvidence(attestationApi.URL, csrPEM)
	if err != nil {
		t.Fatalf("ObtainCertificateWithEvidence: %v", err)
	}

	if result.Certificate != certPEM {
		t.Fatalf("certificate = %q, want %q", result.Certificate, certPEM)
	}
	if result.Challenge != challenge {
		t.Fatalf("challenge = %q, want %q", result.Challenge, challenge)
	}
	if result.Platform != "snp" {
		t.Fatalf("platform = %q, want snp", result.Platform)
	}
	if !strings.Contains(string(result.Evidence), `"quote":"abc"`) {
		t.Fatalf("evidence = %s, want quote", result.Evidence)
	}
	if !bytes.Equal(attestationApiSawReportData, expectedReportData) {
		t.Fatalf("report_data = %x, want key-bound challenge %x", attestationApiSawReportData, expectedReportData)
	}
}

func testCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-node"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestObtainCertificateWithEvidenceContextCanceled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("authenticate handler should not be called after context cancellation")
	})
	cds := httptest.NewServer(mux)
	defer cds.Close()

	client := NewClientWithHTTP(cds.URL, cds.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ObtainCertificateWithEvidenceContext(ctx, "http://127.0.0.1:1", "csr")
	if err == nil {
		t.Fatal("ObtainCertificateWithEvidenceContext succeeded with canceled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestHealthzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Healthz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected healthz to return true")
	}
}

func TestReadyzSuccess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())
	ok, err := c.Readyz()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected readyz to return true")
	}
}

// A proxy the caller's client would use, as http.DefaultTransport does from
// HTTP_PROXY, must not see /attest.
func TestGenerateEvidenceBypassesProxy(t *testing.T) {
	proxied := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied = true
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"platform":"snp","evidence":{"quote":"abc"}}`)
	}))
	defer api.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	c := NewClientWithHTTP("", &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}})
	if _, err := c.GenerateEvidenceContext(context.Background(), api.URL, make([]byte, 48)); err != nil {
		t.Fatalf("GenerateEvidenceContext: %v", err)
	}
	if proxied {
		t.Fatal("evidence request went through the proxy")
	}
}
