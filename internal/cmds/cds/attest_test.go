package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newStubAttestationApi(t *testing.T, launchDigest string) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(launchDigest))
	return stub
}

func generateCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	return generateCSRWith(t, pkix.Name{CommonName: "test-node"}, nil, nil)
}

func generateCSRWith(t *testing.T, subject pkix.Name, dnsNames []string, ips []net.IP) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames, IPAddresses: ips}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

const (
	// testLaunchDigest is the launch measurement the stub attestation-api
	// reports and the handler helper pins, since issuance refuses a CDS whose
	// pins name no guest.
	testLaunchDigest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	testOtherDigest  = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"
)

func newTestAttestHandler(t *testing.T, stubURL string) AttestHandler {
	t.Helper()
	return newPinnedAttestHandler(t, stubURL, pinsForDigests(t, testLaunchDigest))
}

func newPinnedAttestHandler(t *testing.T, stubURL string, pins armtls.Pins) AttestHandler {
	t.Helper()
	ca, err := issuer.NewCA("test ca", 2*issuer.MaxLeafTTL)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	store := attestation.NewChallengeStore(30 * time.Second)
	return AttestHandler{
		Challenges:        &store,
		AttestationClient: remote.NewClient(stubURL),
		CA:                ca,
		CAChainPEM:        certutil.EncodeCertPEM(ca.Cert.Raw),
		CertTTL:           time.Hour,
		Pins:              pins,
		Platforms:         guestMeasuredOnly{},
	}
}

// pinsForDigests pins launch measurements, the shape --measurements gives.
func pinsForDigests(t *testing.T, hexDigests ...string) armtls.Pins {
	t.Helper()
	var pins armtls.Pins
	for _, h := range hexDigests {
		pins.Measurements = append(pins.Measurements, mustDecode(t, h))
	}
	return pins
}

func issueChallenge(t *testing.T, h AttestHandler) string {
	t.Helper()
	c := h.Challenges.Create()
	return base64.StdEncoding.EncodeToString(c[:])
}

func postAttest(t *testing.T, h AttestHandler, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

func leafFromAttestResponse(t *testing.T, w *httptest.ResponseRecorder) *x509.Certificate {
	t.Helper()
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatalf("empty certificate chain")
	}
	return chain[0]
}

func TestAttest_InProcessSignAndReturnsChain(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content-type: got %q, want application/x-pem-file", ct)
	}
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length: got %d, want leaf + CA", len(chain))
	}
	leaf := chain[0]
	ca := chain[1]
	if !bytes.Equal(ca.Raw, h.CA.Cert.Raw) {
		t.Fatalf("CA bundle cert does not match handler CA")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("leaf not signed by handler CA: %v", err)
	}
	if leaf.Subject.CommonName != "test-node" {
		t.Errorf("CN: got %q, want test-node", leaf.Subject.CommonName)
	}
}

func TestAttest_ClampsCertTTLBeforeSigning(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	base := newTestAttestHandler(t, stub.URL())
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"above max", issuer.MaxLeafTTL + time.Hour, issuer.MaxLeafTTL},
		{"zero", 0, issuer.DefaultLeafTTL},
		{"negative", -time.Hour, issuer.DefaultLeafTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			h.CertTTL = tc.configured
			challenge := issueChallenge(t, h)
			csrPEM, _ := generateCSR(t)

			w := postAttest(t, h, challenge, csrPEM)
			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
			}

			leaf := leafFromAttestResponse(t, w)
			got := leaf.NotAfter.Sub(leaf.NotBefore)
			if got < tc.want-time.Minute || got > tc.want+time.Minute {
				t.Fatalf("leaf TTL = %v, want ~%v", got, tc.want)
			}
		})
	}
}

func TestAttest_LaunchDigestAllowlistAllowed(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_LaunchDigestAllowlistCaseInsensitive(t *testing.T) {
	stub := newStubAttestationApi(t, strings.ToUpper(testLaunchDigest))
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("uppercase digest with lowercase allowlist: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_LaunchDigestAllowlistDenied(t *testing.T) {
	stub := newStubAttestationApi(t, testOtherDigest)
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "measurement_denied") {
		t.Errorf("body should mention measurement_denied; got %s", w.Body.String())
	}
}

func TestAttest_TimeoutBeforeSigningReturns504(t *testing.T) {
	h := newTestAttestHandler(t, "http://attestation.test")
	ctx, cancel := context.WithCancel(context.Background())
	h.AttestationClient = remote.NewClientWithHTTP("http://attestation.test", &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cancel()
			match := true
			resp := remote.VerifyResponse{
				Result: teetypes.VerificationResult{
					Platform:        "snp",
					SignatureValid:  true,
					ReportDataMatch: &match,
					Claims:          teetypes.Claims{LaunchDigest: testLaunchDigest},
				},
			}
			var body bytes.Buffer
			if err := json.NewEncoder(&body).Encode(resp); err != nil {
				t.Fatalf("encode verify response: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(&body),
				Request:    req,
			}, nil
		}),
	})
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status: got %d, want 504; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), types.ErrorCodeTimeout) {
		t.Errorf("body should mention timeout; got %s", w.Body.String())
	}
}

func TestAttest_ConsumedChallengeRejectsReplay(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	if w := postAttest(t, h, challenge, csrPEM); w.Code != http.StatusOK {
		t.Fatalf("first attest: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replayed challenge: got %d, want 400", w.Code)
	}
}

// The verify request must bind this request's CSR key and challenge:
// anything weaker signs a leaf for whoever holds any verifiable TEE report.
func TestAttest_BindsReportDataToCSRKeyAndChallenge(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, csrKey := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify called %d times, want 1", len(reqs))
	}
	if reqs[0].Params == nil || len(reqs[0].Params.ExpectedReportData) == 0 {
		t.Fatal("/verify carried no expected_report_data")
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	want, err := armtls.ReportDataForKey(&csrKey.PublicKey, challengeBytes)
	if err != nil {
		t.Fatalf("ReportDataForKey: %v", err)
	}
	if got := reqs[0].Params.ExpectedReportData; !bytes.Equal(got, want[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x (%d bytes), want SHA-384(key||challenge) %x",
			got, len(got), want[:sha512.Size384])
	}
	// The caller's evidence envelope must reach the verifier intact.
	if reqs[0].Platform != "snp" {
		t.Fatalf("/verify platform = %q, want the submitted envelope's snp", reqs[0].Platform)
	}
	if got := string(reqs[0].Evidence); got != `{"test":true}` {
		t.Fatalf(`/verify evidence = %s, want the submitted envelope's {"test":true}`, got)
	}
}

// A verifier reporting that the evidence binds different report data must
// deny issuance: the report attests some other key or challenge. Defensive:
// non-production shape (mockapi.Verdict) — production refuses a mismatch
// with a 422; the 401 pins CDS's own fail-closed gate.
func TestAttest_ReportDataMismatchReturns401(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	verdict := mockapi.PassingVerdict("deadbeef")
	match := false
	verdict.ReportDataMatch = &match
	stub.SetVerdict(verdict)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), types.ErrorCodeVerificationFailed) {
		t.Errorf("body should mention %s; got %s", types.ErrorCodeVerificationFailed, w.Body.String())
	}
}

func TestAttest_BadCSRRejected(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)

	w := postAttest(t, h, challenge, "not a pem")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestAttest_RejectsCSRWithUnconfiguredDNSSAN(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, []string{"foo.mesh.svc"}, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "DNS SAN") {
		t.Errorf("body should mention DNS SAN; got %s", w.Body.String())
	}
}

func TestAttest_AcceptsCSRWithAllowedDNSSAN(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	h.Policy.DNSSANPatterns = []*regexp.Regexp{regexp.MustCompile(`^[a-z]+\.mesh\.svc$`)}
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, []string{"foo.mesh.svc"}, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithBadCN(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	h.Policy.AllowedCNPattern = regexp.MustCompile(`^armtls-mesh-[0-9.]+$`)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "evil"}, nil, nil)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithMismatchedSourceIP(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	h.SANValidation = true
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, nil, []net.IP{net.ParseIP("10.0.0.99")})

	// httptest.NewRequest defaults RemoteAddr to "192.0.2.1:1234"; the CSR's
	// 10.0.0.99 IP SAN should not match.
	body, _ := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsCSRWithIPSANWhenSANValidationDisabled(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	// SANValidation defaults to false, leaving Policy.SourceIP empty.
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSRWith(t, pkix.Name{CommonName: "node"}, nil, []net.IP{net.ParseIP("10.0.0.99")})

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_AttestationApiFailureReturns502(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(down.Close)
	h := newTestAttestHandler(t, down.URL)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502; body=%s", w.Code, w.Body.String())
	}
}

// A 4xx from the attestation-api means it judged the evidence bad — a client
// error, not an outage. It must not be reported as attestation_api_unreachable.
func TestAttest_RejectedEvidenceReturns4xxNotUnreachable(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(types.ErrorResponse{
			Error:   types.ErrorCodeInvalidRequest,
			Message: "malformed evidence",
		})
	}))
	t.Cleanup(bad.Close)
	h := newTestAttestHandler(t, bad.URL)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422; body=%s", w.Code, w.Body.String())
	}
	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, w.Body.String())
	}
	if resp.Error == types.ErrorCodeAttestationApiUnreachable {
		t.Fatalf("bad evidence mislabeled as %q", resp.Error)
	}
	if resp.Error != types.ErrorCodeVerificationFailed {
		t.Fatalf("error code: got %q, want %q", resp.Error, types.ErrorCodeVerificationFailed)
	}
}

// A 4xx whose body is not the api's JSON envelope — an axum extractor
// rejection, or an on-path proxy — is still terminal for this request, so it
// must not be reported as attestation_api_unreachable and retried.
func TestAttest_NonJSONRejectionReturns422NotUnreachable(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	t.Cleanup(bad.Close)
	h := newTestAttestHandler(t, bad.URL)
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422; body=%s", w.Code, w.Body.String())
	}
	var resp types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, w.Body.String())
	}
	if resp.Error != types.ErrorCodeVerificationFailed {
		t.Fatalf("error code: got %q, want %q", resp.Error, types.ErrorCodeVerificationFailed)
	}
}

const (
	msgEvidenceRejected = "attestation evidence rejected by attestation-api"
	msgRequestRejected  = "attestation-api rejected the request"
	msgUnreachable      = "failed to reach attestation-api: "
)

// anyUnreachableMsg is the wantMsg for the outage arm, whose message
// interpolates the error and so is pinned by prefix.
const anyUnreachableMsg = ""

func TestClassifyVerifyError(t *testing.T) {
	// VerifyEnforced wraps, so the call site never sees a bare error.
	wrapped := func(err error) error { return fmt.Errorf("verify enforced: %w", err) }

	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantMsg    string
	}{
		{
			name:       "signature invalid",
			err:        wrapped(remote.ErrSignatureInvalid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    "attestation signature invalid",
		},
		{
			name:       "report data mismatch",
			err:        wrapped(remote.ErrReportDataMismatch),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    "challenge mismatch in attestation evidence",
		},
		{
			name:       "api 400 is client fault",
			err:        wrapped(&remote.APIError{Status: http.StatusBadRequest}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgEvidenceRejected,
		},
		{
			name:       "api 403 is client fault",
			err:        wrapped(&remote.APIError{Status: http.StatusForbidden}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgEvidenceRejected,
		},
		{
			// Deliberately bare: the sentinel arms above are wrapped, so this
			// is the one row that would still pass a plain type assertion.
			name:       "api 400 unwrapped is client fault",
			err:        &remote.APIError{Status: http.StatusBadRequest},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgEvidenceRejected,
		},
		{
			name:       "api 500 is upstream outage",
			err:        wrapped(&remote.APIError{Status: http.StatusInternalServerError}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "api 408 is retryable unavailability",
			err:        wrapped(&remote.APIError{Status: http.StatusRequestTimeout}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "api 429 is retryable unavailability",
			err:        wrapped(&remote.APIError{Status: http.StatusTooManyRequests}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "api 399 is not a refusal",
			err:        wrapped(&remote.APIError{Status: 399}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "api 302 is not a refusal",
			err:        wrapped(&remote.APIError{Status: http.StatusFound}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 400 is a request rejection",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusBadRequest, Text: "Failed to parse the request body as JSON"}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgRequestRejected,
		},
		{
			name:       "non-json 415 is a request rejection",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusUnsupportedMediaType, Text: "Expected request with `Content-Type: application/json`"}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgRequestRejected,
		},
		{
			name:       "non-json 422 is a request rejection",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusUnprocessableEntity, Text: "Failed to deserialize the JSON body into the target type"}),
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
			wantMsg:    msgRequestRejected,
		},
		{
			// A body cut mid-response names nothing, so it is not a rejection.
			name:       "non-json 400 with no body is an outage",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusBadRequest}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			// The api has no 403; an on-path proxy does.
			name:       "non-json 403 is an outage",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusForbidden, Text: "<html>403 Forbidden</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 404 is an outage",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusNotFound, Text: "<html>404 Not Found</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 413 is an outage",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusRequestEntityTooLarge, Text: "<html>413 Request Entity Too Large</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 500 is upstream outage",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusInternalServerError, Text: "<html>500 Internal Server Error</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 408 is retryable unavailability",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusRequestTimeout, Text: "<html>408 Request Timeout</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 429 is retryable unavailability",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusTooManyRequests, Text: "<html>429 Too Many Requests</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 399 is not a rejection",
			err:        wrapped(&remote.UnexpectedError{Status: 399, Text: "unknown"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "non-json 302 is not a rejection",
			err:        wrapped(&remote.UnexpectedError{Status: http.StatusFound, Text: "<html>302 Found</html>"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "transport failure is unreachable",
			err:        wrapped(&remote.RequestError{Err: errors.New("dial tcp: connection refused")}),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
		{
			name:       "deadline exceeded is unreachable",
			err:        wrapped(context.DeadlineExceeded),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
			wantMsg:    anyUnreachableMsg,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, code, msg := classifyVerifyError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			switch {
			case tc.wantMsg != anyUnreachableMsg:
				if msg != tc.wantMsg {
					t.Errorf("message = %q, want %q", msg, tc.wantMsg)
				}
			case !strings.HasPrefix(msg, msgUnreachable):
				t.Errorf("message = %q, want prefix %q", msg, msgUnreachable)
			}
		})
	}
}

// refusesEvidence and rejectsRequest are what the two arms are gated on, and
// the statuses either side of each boundary are not all reachable from
// classifyVerifyError's table, so the predicates are pinned directly.
func TestStatusPredicates(t *testing.T) {
	t.Run("refusesEvidence", func(t *testing.T) {
		for status, want := range map[int]bool{
			399: false, 400: true, 407: true, 408: false, 409: true,
			428: true, 429: false, 430: true, 499: true, 500: false, 501: false,
		} {
			if got := refusesEvidence(status); got != want {
				t.Errorf("refusesEvidence(%d) = %v, want %v", status, got, want)
			}
		}
	})
	t.Run("rejectsRequest", func(t *testing.T) {
		for status, want := range map[int]bool{
			399: false, 400: true, 403: false, 408: false, 413: false,
			414: false, 415: true, 421: false, 422: true, 429: false, 500: false,
		} {
			if got := rejectsRequest(status); got != want {
				t.Errorf("rejectsRequest(%d) = %v, want %v", status, got, want)
			}
		}
	})
}

// UnexpectedError.Text is untrusted upstream body and classifyVerifyError's
// message is written to the remote peer, so the rejection arm must not carry it.
func TestClassifyVerifyErrorDoesNotEchoUpstreamBody(t *testing.T) {
	const leak = "s3cret-internal-hostname.cluster.local"
	_, _, msg := classifyVerifyError(fmt.Errorf("verify enforced: %w",
		&remote.UnexpectedError{Status: http.StatusBadRequest, Text: leak}))
	if strings.Contains(msg, leak) {
		t.Fatalf("message echoes upstream body: %q", msg)
	}
	if msg != msgRequestRejected {
		t.Fatalf("message = %q, want %q", msg, msgRequestRejected)
	}
}

// caChainPEM has three branches: prefer CAChainPEM, fall back to CA.Cert, or
// return nil.
func TestAttestHandler_caChainPEM(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}

	t.Run("prefers explicit CAChainPEM", func(t *testing.T) {
		h := AttestHandler{CAChainPEM: []byte("explicit"), CA: ca}
		if got := string(h.caChainPEM()); got != "explicit" {
			t.Fatalf("got %q, want explicit", got)
		}
	})

	t.Run("derives from CA cert when chain empty", func(t *testing.T) {
		h := AttestHandler{CA: ca}
		want := certutil.EncodeCertPEM(ca.Cert.Raw)
		if !bytes.Equal(h.caChainPEM(), want) {
			t.Fatal("derived chain does not match CA cert PEM")
		}
	})

	t.Run("nil when no chain and no CA", func(t *testing.T) {
		h := AttestHandler{}
		if got := h.caChainPEM(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("nil when CA has nil cert", func(t *testing.T) {
		h := AttestHandler{CA: &issuer.CA{}}
		if got := h.caChainPEM(); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}

func TestAttest_RejectsUnknownJSONFields(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())

	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader([]byte(`{"unknown":true}`)))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsMalformedChallengeEncoding(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: "!!!not-base64!!!",
		Evidence:  teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_RejectsValidBase64UnknownChallenge(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	// Valid base64 but never issued, so Consume returns false.
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: "AAAAAAAAAAAAAAAAAAAAAA==",
		Evidence:  teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// A CSR whose public key is not ECDSA must be rejected before verification.
func TestAttest_RejectsNonECDSACSR(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-node"},
	}, rsaKey)
	if err != nil {
		t.Fatalf("create rsa csr: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// An unloaded CA makes in-process signing fail after all validation passed.
// Also exercises the RequestTimeout>0 wrapping.
func TestAttest_SignFailureReturns500(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	h.CA = &issuer.CA{} // no cert/key loaded: SignCSR fails
	h.RequestTimeout = time.Second
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), types.ErrorCodeSignFailed) {
		t.Errorf("body should mention %s; got %s", types.ErrorCodeSignFailed, w.Body.String())
	}
}

// The issuance record is the only durable trace that a mesh identity was
// granted: a forged verdict or a compromised verifier still produces a real
// leaf, and this line is what an operator reconciles against expected
// workloads afterwards. The serial has to match the leaf actually returned.
func TestAttest_IssuanceIsRecorded(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL())
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "certificate issued") {
		t.Fatalf("no issuance record: %s", logs)
	}
	// Names the certificate, so the record can be matched to a leaf in hand.
	if want := fmt.Sprintf("%X", chain[0].SerialNumber); !strings.Contains(logs, want) {
		t.Errorf("issuance record omits the leaf serial %s: %s", want, logs)
	}
	// Names what attested for it.
	if !strings.Contains(logs, testLaunchDigest) {
		t.Errorf("issuance record omits the launch digest: %s", logs)
	}
	if !strings.Contains(logs, "launch_digest") || !strings.Contains(logs, "remote_addr") {
		t.Errorf("issuance record missing expected keys: %s", logs)
	}
}

// A denial and the issuance that follows it have to be correlatable, or a run
// of probes against CDS cannot be tied to the leaf that eventually succeeded.
func TestAttest_MeasurementDenialRecordsPeer(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testOtherDigest))
	challenge := issueChallenge(t, h)
	csrPEM, _ := generateCSR(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := postAttest(t, h, challenge, csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", w.Code)
	}
	logs := buf.String()
	if !strings.Contains(logs, "guest identity does not match policy") {
		t.Fatalf("no denial record: %s", logs)
	}
	if !strings.Contains(logs, "remote_addr") {
		t.Errorf("denial record omits the peer: %s", logs)
	}
}
