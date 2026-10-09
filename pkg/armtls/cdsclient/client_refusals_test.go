package cdsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// recordingLogger collects what a Provider reports.
type recordingLogger struct {
	infos []string
	warns []string
}

func (l *recordingLogger) Info(msg string, _ ...any) {
	l.infos = append(l.infos, msg)
}

func (l *recordingLogger) Warn(msg string, _ ...any) {
	l.warns = append(l.warns, msg)
}

func (l *recordingLogger) sawInfo(substr string) bool {
	for _, msg := range l.infos {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}

// cdsServerReturning answers the authenticate/attest flow with a caller-chosen
// certificate response, which is how a test drives what CDS hands back.
func cdsServerReturning(t *testing.T, certResponse string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			challenge := make([]byte, 32)
			if _, err := rand.Read(challenge); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			response := types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(challenge)}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("encode challenge: %v", err)
			}
		case "/attest":
			w.Header().Set("Content-Type", "application/x-pem-file")
			if _, err := w.Write([]byte(certResponse)); err != nil {
				t.Errorf("write certificate response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

// leafOnlyPEM is a certificate response with no CA behind it.
func leafOnlyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "lonely-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func clientForCDS(t *testing.T, cdsURL, attestURL, caURL string) *Client {
	t.Helper()
	return NewClient(&Config{
		CDSURL:            cdsURL,
		AttestationApiURL: attestURL,
		CDSCAURL:          caURL,
		NodeIP:            "10.0.0.9",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	})
}

// The CA bundle in the issuance response is the authenticated trust seed every
// later refresh is checked against. A response without one leaves nothing to
// anchor trust on, so issuance must fail rather than proceed unanchored.
func TestRequestCertRefusesResponseWithoutCABundle(t *testing.T) {
	attestSvc := mockapi.New(t)
	defer attestSvc.Close()
	cdsSrv := cdsServerReturning(t, leafOnlyPEM(t))
	defer cdsSrv.Close()

	client := clientForCDS(t, cdsSrv.URL, attestSvc.URL(), cdsSrv.URL)
	_, _, _, err := client.RequestCert(context.Background())
	if err == nil {
		t.Fatal("issuance accepted a response carrying no CA bundle")
	}
	if !strings.Contains(err.Error(), "missing CA bundle") {
		t.Fatalf("error = %v, want it to name the missing CA bundle", err)
	}
}

// A response that is not a certificate chain at all must be reported as such,
// not treated as an empty chain.
func TestRequestCertRefusesUnparsableResponse(t *testing.T) {
	attestSvc := mockapi.New(t)
	defer attestSvc.Close()
	cdsSrv := cdsServerReturning(t, "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
	defer cdsSrv.Close()

	client := clientForCDS(t, cdsSrv.URL, attestSvc.URL(), cdsSrv.URL)
	_, _, _, err := client.RequestCert(context.Background())
	if err == nil {
		t.Fatal("issuance accepted an unparsable certificate response")
	}
	if !strings.Contains(err.Error(), "parse CDS certificate response") {
		t.Fatalf("error = %v, want it to name the unparsable response", err)
	}
}

// The /ca endpoint is unauthenticated, so a refresh must surface what went
// wrong instead of dropping the trusted bundle it already holds.
func TestRefreshCABundleSurfacesEndpointFailures(t *testing.T) {
	_, caCert := testCA(t)

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "ca unavailable", http.StatusInternalServerError)
			},
			wantErr: "returned 500",
		},
		{
			name: "not a bundle",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte("certainly not PEM")); err != nil {
					t.Errorf("write body: %v", err)
				}
			},
			wantErr: "CA bundle",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			client := clientForCDS(t, srv.URL, srv.URL, srv.URL)
			seedTrustedCABundle(t, client, caCert)

			_, err := client.refreshCABundle(context.Background())
			if err == nil {
				t.Fatal("refresh accepted a bundle the endpoint never served")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if len(client.TrustedCABundle()) != 1 {
				t.Fatal("a failed refresh changed the trusted bundle")
			}
		})
	}
}

// Issuance is the step an operator needs in the log when a node fails to join,
// so a provider with a logger reports the request and the credential it got.
func TestProviderProvisionReportsIssuance(t *testing.T) {
	caKey, caCert := testCA(t)
	cdsSrv, attestSvc, issuer := mockServers(t, caKey, caCert)
	defer cdsSrv.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	logger := &recordingLogger{}
	p, err := NewProvider(&Config{
		CDSURL:            cdsSrv.URL,
		AttestationApiURL: attestSvc.URL(),
		CDSCAURL:          issuer.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        plainHTTPClient(),
		NodeName:          "test-node",
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := p.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !logger.sawInfo("requesting CDS-issued certificate") {
		t.Fatal("the issuance request was not reported")
	}
	if !logger.sawInfo("certificate provisioned") {
		t.Fatal("the provisioned certificate was not reported")
	}
}

// A provider without a client or a configuration cannot attest anything; both
// are construction-time refusals rather than a provider that fails later.
func TestProviderConstructionRefusals(t *testing.T) {
	_, err := newProviderWithClient(nil, nil)
	if err == nil {
		t.Fatal("a provider was built without a client")
	}
	if !strings.Contains(err.Error(), "client is required") {
		t.Fatalf("error = %v, want it to name the missing client", err)
	}

	_, err = NewProvider(nil, nil)
	if err == nil {
		t.Fatal("a provider was built without a configuration")
	}
	if !strings.Contains(err.Error(), "Config is required") {
		t.Fatalf("error = %v, want it to name the missing configuration", err)
	}
}

// The key check is what ties an issued certificate to the key generated in
// this TEE, so missing inputs are a mismatch, never a pass.
func TestCertificateMatchesPrivateKeyRefusesMissingInputs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if certificateMatchesPrivateKey(nil, key) {
		t.Fatal("a nil certificate matched a key")
	}
	if certificateMatchesPrivateKey(&x509.Certificate{}, nil) {
		t.Fatal("a nil key matched a certificate")
	}
}

// The continuity check compares candidates by public key, so a missing
// certificate must not compare equal to anything.
func TestSamePublicKeyRefusesMissingCertificate(t *testing.T) {
	_, caCert := testCA(t)
	if samePublicKey(nil, caCert) {
		t.Fatal("a nil certificate shared a public key")
	}
	if samePublicKey(caCert, nil) {
		t.Fatal("a nil certificate shared a public key")
	}
}

// The accepted bundle is handed to armTLS as a trust list: a duplicate or a
// missing entry in CDS's response must not reach it.
func TestDedupeCertsDropsRepeatsAndGaps(t *testing.T) {
	_, first := testCA(t)
	_, second := testCAWithValidity(t, "Second CA", time.Now(), time.Now().Add(time.Hour))

	deduped := dedupeCerts([]*x509.Certificate{first, nil, second, first})
	if len(deduped) != 2 {
		t.Fatalf("deduped = %d certs, want 2", len(deduped))
	}
	if !sameCertificate(deduped[0], first) || !sameCertificate(deduped[1], second) {
		t.Fatal("dedupe did not keep the first occurrence of each CA")
	}
}

// Published order is the order CDS wants the bundle used in; a CA that is
// trusted but no longer published is kept, after the published ones.
func TestOrderLikePublishedKeepsUnpublishedTrustedCA(t *testing.T) {
	_, published := testCA(t)
	_, retired := testCAWithValidity(t, "Retired CA", time.Now(), time.Now().Add(time.Hour))

	ordered := orderLikePublished([]*x509.Certificate{retired, published}, []*x509.Certificate{published})
	if len(ordered) != 2 {
		t.Fatalf("ordered = %d certs, want both accepted CAs", len(ordered))
	}
	if !sameCertificate(ordered[0], published) {
		t.Fatal("the published CA is not first")
	}
	if !sameCertificate(ordered[1], retired) {
		t.Fatal("the trusted but unpublished CA was dropped")
	}
}

// Signature continuity must come from a different, usable CA: a candidate's
// own copy, an expired CA or one reusing its public key proves nothing.
func TestUsableCASignatureLinkIgnoresUselessCandidates(t *testing.T) {
	rootKey, rootCert := testCA(t)
	_, child := testCAWithParent(t, rootKey, rootCert, "Rotation CA")
	expiredKey, expiredCert := testCAWithValidity(t, "Expired CA", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	clone := testCAForPublicKey(t, expiredKey, expiredCert, child.PublicKey, pkix.Name{CommonName: "Key Clone CA"})
	now := time.Now()

	others := []*x509.Certificate{nil, child, expiredCert, clone}
	if hasUsableCASignatureLink(child, others, now, certSignedByOther) {
		t.Fatal("a CA was linked without a usable, distinct signer")
	}
	if !hasUsableCASignatureLink(child, append(others, rootCert), now, certSignedByOther) {
		t.Fatal("a CA signed by its usable parent was not linked")
	}
}
