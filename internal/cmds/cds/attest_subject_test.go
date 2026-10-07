package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The subject of a leaf with no DNS or IP SAN comes from the verified token, so
// a requester cannot choose the name its leaf carries, and a leaf that nothing
// names is refused as a CSR-policy failure rather than signed.
func TestAttest_LeafSubject(t *testing.T) {
	sandboxDigest := sha256.Sum256([]byte(testSandboxID))

	cases := []struct {
		name       string
		csr        func(*testing.T) string
		withToken  bool
		wantStatus int
		wantCN     string
	}{
		{
			name:       "verified sandbox names a subjectless SAN-less CSR",
			csr:        sandboxCSR,
			withToken:  true,
			wantStatus: http.StatusOK,
			wantCN:     hex.EncodeToString(sandboxDigest[:]),
		},
		{
			name:       "a DNS SAN keeps the CSR CN",
			csr:        dnsSANCSR,
			withToken:  true,
			wantStatus: http.StatusOK,
			wantCN:     "foo.mesh.svc",
		},
		{
			name:       "a subjectless SAN-less CSR without a token is refused",
			csr:        sandboxCSR,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a URI SAN names nothing, so the CSR is refused",
			csr:        uriSANCSR,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, stub.URL())
			h.Policy.DNSSANPatterns = []*regexp.Regexp{regexp.MustCompile(`[a-z]+\.mesh\.svc`)}
			csrPEM := tc.csr(t)

			challenge := issueChallenge(t, h)
			var token json.RawMessage
			if tc.withToken {
				token = signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID)
			}
			w := postAttestSandbox(t, h, challenge, csrPEM, token)
			if w.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				if code := errorCode(t, w.Body.Bytes()); code != types.ErrorCodeCSRDenied {
					t.Errorf("error code = %q, want %q", code, types.ErrorCodeCSRDenied)
				}
				return
			}
			if cn := leafFromAttestResponse(t, w).Subject.CommonName; cn != tc.wantCN {
				t.Errorf("leaf CN = %q, want %q", cn, tc.wantCN)
			}
		})
	}
}

func dnsSANCSR(t *testing.T) string {
	t.Helper()
	return csrPEMFor(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "foo.mesh.svc"},
		DNSNames: []string{"foo.mesh.svc"},
	})
}

func uriSANCSR(t *testing.T) string {
	t.Helper()
	return csrPEMFor(t, &x509.CertificateRequest{
		URIs: []*url.URL{{
			Scheme: "spiffe",
			Host:   "cluster.local",
			Path:   "/ns/default/sa/api",
		}},
	})
}

func csrPEMFor(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}))
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error body %s: %v", body, err)
	}
	return resp.Error
}
