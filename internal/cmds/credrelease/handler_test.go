package credrelease

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// TestHandlerReleasesServerCA drives POST /release-credential end to end and
// checks the wire response: CAPEM is the serving-CA PEM verbatim and the
// issued cert chains to the client CA.
func TestHandlerReleasesServerCA(t *testing.T) {
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opKeyPEM, err := certutil.MarshalECKeyPEM(opKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(opKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	ca := testCA(t)
	serverCA, err := issuer.NewCA("server-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca.pem = certutil.EncodeCertPEM(serverCA.Cert.Raw)

	h, err := NewHandler(pubPEM, ca, defaultRoles())
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().Truncate(time.Second).Add(5 * time.Minute)
	h.clock = fixedClock{now: issuedAt}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-signer"},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(ReleaseRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := signer.Authorization(http.MethodPost, "/release-credential", body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}

	var resp ReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.CAPEM != string(ca.pem) {
		t.Error("released CA is not the serving-CA PEM")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	leaf := parseLeaf(t, []byte(resp.CertPEM))
	if !leaf.NotBefore.Equal(issuedAt.Add(-time.Minute)) || !leaf.NotAfter.Equal(issuedAt.Add(defaultCertTTL)) {
		t.Errorf("certificate validity = %v..%v, want injected clock %v with one-minute backdate and the default TTL", leaf.NotBefore, leaf.NotAfter, issuedAt)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: issuedAt,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("released cert does not chain to the client CA: %v", err)
	}
}

// The token's pbh binds it to the exact body it was minted over: a token
// captured from one release must not authorize a different CSR, on the
// endpoint that issues cluster-admin credentials.
func TestReleaseRefusesATokenBoundToAnotherCSR(t *testing.T) {
	signer, pubPEM := newOperatorAuth(t)
	h, err := NewHandler(pubPEM, testCA(t), defaultRoles())
	if err != nil {
		t.Fatal(err)
	}

	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bodyA, err := json.Marshal(ReleaseRequest{CSRPEM: string(csrPEMFromKey(t, keyA))})
	if err != nil {
		t.Fatal(err)
	}
	bodyB, err := json.Marshal(ReleaseRequest{CSRPEM: string(csrPEMFromKey(t, keyB))})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := signer.Authorization(http.MethodPost, "/release-credential", bodyA)
	if err != nil {
		t.Fatal(err)
	}

	// The token signed over bodyA is replayed against bodyB.
	req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(bodyB))
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token bound to another CSR = %d, body %q; want 401", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("a refused request issued a certificate: %s", rec.Body.String())
	}

	// The same token against the body it was minted over succeeds, so the
	// refusal above is the body binding and nothing else.
	req = httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(bodyA))
	req.Header.Set("Authorization", authz)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the unswapped body = %d, body %q; want 200", rec.Code, rec.Body.String())
	}
}

// newOperatorAuth generates a fresh operator keypair, returning a token signer
// (the operator side) and the PKIX public-key PEM (the measured side).
func newOperatorAuth(t *testing.T) (*operatorauth.Signer, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// csrPEMFromKey builds a PEM CERTIFICATE REQUEST self-signed by key.
func csrPEMFromKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-signer"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestNewHandlerRejectsBadPubkey: the measured key must be an ECDSA PKIX PEM.
func TestNewHandlerRejectsBadPubkey(t *testing.T) {
	if _, err := NewHandler([]byte("not a key"), testCA(t), defaultRoles()); err == nil {
		t.Error("expected error for non-PEM operator pubkey")
	}
}

// TestHandlerToleratesTokenClockSkew: a token stamped slightly ahead of the
// guest clock (operator clock skew) must still authorize; the verifier's
// bounded leeway absorbs it.
func TestHandlerToleratesTokenClockSkew(t *testing.T) {
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	h, err := NewHandler(pubPEM, testCA(t), defaultRoles())
	if err != nil {
		t.Fatal(err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ReleaseRequest{CSRPEM: string(csrPEMFromKey(t, csrKey))})
	if err != nil {
		t.Fatal(err)
	}

	// Mint the token by hand with iat 30s in the future: within the verifier's
	// leeway, but ahead of the guest clock.
	sum := sha256.Sum256(body)
	iat := time.Now().Add(30 * time.Second)
	claims := jwt.MapClaims{
		"iat": iat.Unix(),
		"exp": iat.Add(time.Minute).Unix(),
		"htm": http.MethodPost,
		"htu": "/release-credential",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(opKey)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q; want 200 for a token within clock-skew leeway", rec.Code, rec.Body.String())
	}
}

// stubSigner is a crypto.Signer whose public key x509 cannot sign for, forcing
// the certificate-signing step to fail after auth and CSR validation pass.
type stubSigner struct{}

func (stubSigner) Public() crypto.PublicKey { return struct{}{} }
func (stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("stub signer")
}

// TestHandlerSigningFailureIsServerError: a signing failure on a valid,
// authorized request is a 500 with the sign error surfaced.
func TestHandlerSigningFailureIsServerError(t *testing.T) {
	signer, pubPEM := newOperatorAuth(t)
	ca := testCA(t)
	ca.key = stubSigner{}
	h, err := NewHandler(pubPEM, ca, defaultRoles())
	if err != nil {
		t.Fatal(err)
	}

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ReleaseRequest{CSRPEM: string(csrPEMFromKey(t, csrKey))})
	if err != nil {
		t.Fatal(err)
	}
	authz, err := signer.Authorization(http.MethodPost, "/release-credential", body)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %q; want 500", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Body.String(), "sign: ") {
		t.Fatalf("body = %q, want a sign error", rec.Body.String())
	}
}

// errReader fails mid-body, driving the read-body error branch.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// TestServeHTTPErrorPaths drives every refusal branch of the handler: routing,
// method, authorization, body decoding, CSR validation, and signing.
func TestServeHTTPErrorPaths(t *testing.T) {
	signer, pubPEM := newOperatorAuth(t)
	h, err := NewHandler(pubPEM, testCA(t), defaultRoles())
	if err != nil {
		t.Fatal(err)
	}

	// authorized wraps a body with a valid operatorauth token for POST
	// /release-credential, so the test reaches the branch after AUTHORIZE.
	authorized := func(body []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader(body))
		authz, err := signer.Authorization(http.MethodPost, "/release-credential", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", authz)
		return req
	}
	mustJSON := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCSR := csrPEMFromKey(t, ecKey)
	// Flip the final signature byte: still parses, fails CheckSignature at
	// CSR validation time — a client fault, the 400 branch.
	der := decodeOnePEM(t, tamperedCSR, "CERTIFICATE REQUEST")
	der[len(der)-1] ^= 0xFF
	tamperedCSR = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	tests := []struct {
		name       string
		req        *http.Request
		wantStatus int
	}{
		{
			name:       "unknown path",
			req:        httptest.NewRequest(http.MethodPost, "/other", nil),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "wrong method",
			req:        httptest.NewRequest(http.MethodGet, "/release-credential", nil),
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "body read error",
			req:        httptest.NewRequest(http.MethodPost, "/release-credential", errReader{}),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing authorization",
			req:        httptest.NewRequest(http.MethodPost, "/release-credential", bytes.NewReader([]byte("{}"))),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authorized but not JSON",
			req:        authorized([]byte("{not json")),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "CSR not PEM",
			req:        authorized(mustJSON(ReleaseRequest{CSRPEM: "garbage"})),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "CSR PEM with garbage DER",
			req: authorized(mustJSON(ReleaseRequest{CSRPEM: string(pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("junk")}))})),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "CSR with RSA key",
			req:        authorized(mustJSON(ReleaseRequest{CSRPEM: string(csrPEMFromKey(t, rsaKey))})),
			wantStatus: http.StatusBadRequest,
		},
		{
			// Client fault: a tampered CSR is the caller's garbage, not a
			// server-side signing failure.
			name:       "CSR with tampered self-signature is a client fault",
			req:        authorized(mustJSON(ReleaseRequest{CSRPEM: string(tamperedCSR)})),
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestHandlerIssuesPerRoleIdentity: the role in the (token-bound) body
// selects the Subject and TTL; "" is the operator for the pre-role wire
// format; anything else is a 400, never a fallback to the operator identity.
func TestHandlerIssuesPerRoleIdentity(t *testing.T) {
	signer, pubPEM := newOperatorAuth(t)
	ca := testCA(t)
	h, err := NewHandler(pubPEM, ca, defaultRoles())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	h.clock = fixedClock{now: now}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(csrPEMFromKey(t, csrKey))

	release := func(t *testing.T, role string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(ReleaseRequest{CSRPEM: csrPEM, Role: role})
		if err != nil {
			t.Fatal(err)
		}
		authz, err := signer.Authorization(http.MethodPost, ReleasePath, body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, ReleasePath, bytes.NewReader(body))
		req.Header.Set("Authorization", authz)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, tt := range []struct {
		role    string
		wantOrg string
		wantCN  string
		wantTTL time.Duration
	}{
		{"", defaultCertOrg, defaultCertCN, defaultCertTTL},
		{RoleOperator, defaultCertOrg, defaultCertCN, defaultCertTTL},
		{RoleLogReader, defaultLogCertOrg, defaultLogCertCN, defaultLogCertTTL},
	} {
		t.Run("role="+tt.role, func(t *testing.T) {
			rec := release(t, tt.role)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
			}
			var resp ReleaseResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			leaf := parseLeaf(t, []byte(resp.CertPEM))
			if got := leaf.Subject.Organization; len(got) != 1 || got[0] != tt.wantOrg {
				t.Errorf("O = %v, want [%s]", got, tt.wantOrg)
			}
			if leaf.Subject.CommonName != tt.wantCN {
				t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, tt.wantCN)
			}
			if !leaf.NotAfter.Equal(now.Add(tt.wantTTL)) {
				t.Errorf("NotAfter = %v, want %v", leaf.NotAfter, now.Add(tt.wantTTL))
			}
		})
	}
	t.Run("unknown role", func(t *testing.T) {
		rec := release(t, "cluster-admin")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown role") {
			t.Fatalf("status = %d, body %q; want 400 unknown role", rec.Code, rec.Body.String())
		}
	})
}

// TestNewHandlerRejectsIncompleteRoles: a role with an empty Subject or a
// non-positive TTL would mint an unbindable or instantly-expired cert; refuse
// it at startup.
func TestNewHandlerRejectsIncompleteRoles(t *testing.T) {
	_, pubPEM := newOperatorAuth(t)
	for name, roles := range map[string]Roles{
		"missing log-reader": {RoleOperator: defaultRoles()[RoleOperator]},
		"zero ttl":           {RoleOperator: defaultRoles()[RoleOperator], RoleLogReader: {Org: "g", CN: "u"}},
		"no operator org":    {RoleOperator: {CN: "u", TTL: time.Hour}, RoleLogReader: defaultRoles()[RoleLogReader]},
	} {
		if _, err := NewHandler(pubPEM, testCA(t), roles); err == nil {
			t.Errorf("%s: NewHandler accepted incomplete roles", name)
		}
	}
}
