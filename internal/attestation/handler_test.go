package attestation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testApp mounts the challenge endpoint used by certificate issuance.
func testApp() http.Handler {
	challengeStore := attestation.NewLocalChallenges(60 * time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", attestation.HandleAuthenticate(challengeStore))
	return mux
}

func authenticate(t *testing.T, appURL string) string {
	t.Helper()
	resp, err := http.Post(appURL+"/authenticate", "application/json", nil)
	if err != nil {
		t.Fatalf("authenticate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticate status = %d, want 200", resp.StatusCode)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return out.Challenge
}

func TestAuthenticateReturnsBase64Challenge(t *testing.T) {
	app := httptest.NewServer(testApp())
	defer app.Close()

	challenge := authenticate(t, app.URL)

	decoded, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("challenge is not valid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("challenge decoded to %d bytes, want 32", len(decoded))
	}
}

func TestAuthenticateReturnsUniqueChallenges(t *testing.T) {
	app := httptest.NewServer(testApp())
	defer app.Close()

	c1 := authenticate(t, app.URL)
	c2 := authenticate(t, app.URL)
	if c1 == c2 {
		t.Fatal("two authenticate calls returned the same challenge")
	}
}

func TestAuthenticateRejectsGetMethod(t *testing.T) {
	app := httptest.NewServer(testApp())
	defer app.Close()

	resp, err := http.Get(app.URL + "/authenticate")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want 405", resp.StatusCode)
	}
}

func ecdsaCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func rsaCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestParseAndVerifyCSRValid(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(ecdsaCSRPEM(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if csr == nil {
		t.Fatal("expected non-nil CSR")
	}
	if csr.Subject.CommonName != "test" {
		t.Fatalf("CN = %q, want test", csr.Subject.CommonName)
	}
}

func TestParseAndVerifyCSRNotPEM(t *testing.T) {
	if _, err := attestation.ParseAndVerifyCSR("not a pem block"); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestParseAndVerifyCSRWrongPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("xx")})
	if _, err := attestation.ParseAndVerifyCSR(string(block)); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestParseAndVerifyCSRMalformedBody(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")})
	if _, err := attestation.ParseAndVerifyCSR(string(block)); err == nil {
		t.Fatal("expected error for malformed CSR body")
	}
}

func TestParseAndVerifyCSRBadSignature(t *testing.T) {
	// Take a valid CSR and tamper with the signed CertificationRequestInfo
	// (TBS) region so the self-signature no longer verifies. ParseCertificate-
	// Request still succeeds structurally, but CheckSignature fails.
	valid := ecdsaCSRPEM(t)
	block, _ := pem.Decode([]byte(valid))
	raw := make([]byte, len(block.Bytes))
	copy(raw, block.Bytes)

	// Mutate a byte well inside the TBS portion (the subject/key region near the
	// front) rather than the trailing signature, so ParseCertificateRequest
	// still accepts the structure but the signature check fails.
	raw[40] ^= 0xff
	corrupted := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})

	// Either parsing fails outright or the signature check fails; both are
	// error returns from ParseAndVerifyCSR, which is what we assert.
	if _, err := attestation.ParseAndVerifyCSR(string(corrupted)); err == nil {
		t.Fatal("expected error for corrupted CSR")
	}
}

func TestECDSAPublicKeyFromCSRSuccess(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(ecdsaCSRPEM(t))
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	pub, err := attestation.ECDSAPublicKeyFromCSR(csr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	if !pub.Equal(csr.PublicKey) {
		t.Fatal("returned key does not match the CSR public key")
	}
}

func TestECDSAPublicKeyFromCSRNonECDSA(t *testing.T) {
	csr, err := attestation.ParseAndVerifyCSR(rsaCSRPEM(t))
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if _, err := attestation.ECDSAPublicKeyFromCSR(csr); err == nil {
		t.Fatal("expected error for non-ECDSA CSR public key")
	}
}

// A replica that holds no cluster key answers /authenticate with a retryable
// 503 rather than a nonce nothing will redeem.
func TestAuthenticateUnavailableWithoutAChallengeKey(t *testing.T) {
	h := attestation.HandleAuthenticate(attestation.NewSharedChallenges(
		"issuance",
		time.Minute,
		func() []byte { return nil },
	))
	rec := httptest.NewRecorder()

	h(rec, httptest.NewRequest(http.MethodPost, "/authenticate", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if retry := rec.Header().Get("Retry-After"); retry == "" {
		t.Fatal("503 carries no Retry-After, so a client has nothing to wait for")
	}
}

func TestHandleReadyzReady(t *testing.T) {
	h := attestation.HandleReadyz(func() bool { return true })
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHandleReadyzNotReady(t *testing.T) {
	h := attestation.HandleReadyz(func() bool { return false })
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	attestation.WriteError(rec, http.StatusTeapot, "some_code", "some message")
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var out types.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if out.Error != "some_code" || out.Message != "some message" {
		t.Fatalf("unexpected error envelope: %+v", out)
	}
}
