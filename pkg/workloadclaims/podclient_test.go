package workloadclaims

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// podIssuanceServers is a CDS that hands out challenge and records the
// /attest body it receives, beside an attestation-api that records the
// report data it is asked to quote and answers with platform.
func podIssuanceServers(t *testing.T, challenge, platform, certPEM string) (cdsURL, apiURL string, quoted *[]byte, attested *types.AttestRequestBody) {
	t.Helper()
	quoted, attested = new([]byte), new(types.AttestRequestBody)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attestation-api request: %v", err)
		}
		*quoted = append([]byte(nil), req.ReportData...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"` + platform + `","evidence":{"q":1}}`))
	}))
	t.Cleanup(api.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: challenge})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(attested); err != nil {
			t.Errorf("decode CDS attest request: %v", err)
		}
		_, _ = w.Write([]byte(certPEM))
	})
	cds := httptest.NewServer(mux)
	t.Cleanup(cds.Close)
	return cds.URL, api.URL, quoted, attested
}

func testPodCSR(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), &key.PublicKey
}

// The pod profile quotes PodReportData over the CSR key, the challenge and
// the canonical claims, and carries the claims to CDS in place of a sandbox
// token and a top-level runtime extension list.
func TestObtainPodCertificateBindsTheClaimsIntoTheQuote(t *testing.T) {
	const certPEM = "-----BEGIN CERTIFICATE-----\npod\n-----END CERTIFICATE-----\n"
	claims := testPodClaims(t)
	canonical, err := claims.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, pub := testPodCSR(t)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenge := base64.StdEncoding.EncodeToString(nonce)
	cdsURL, apiURL, quoted, attested := podIssuanceServers(t, challenge, "tdx", certPEM)

	result, err := ObtainPodCertificateContext(context.Background(), attestclient.NewClient(cdsURL), apiURL, csrPEM, claims)
	if err != nil {
		t.Fatalf("ObtainPodCertificateContext: %v", err)
	}
	want, err := PodReportData(pub, nonce, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(*quoted, want) {
		t.Fatalf("quoted report data %x, want PodReportData %x", *quoted, want)
	}
	if attested.Challenge != challenge || attested.CSR != csrPEM || !bytes.Equal(attested.PodClaims, canonical) {
		t.Fatalf("CDS saw challenge %q, claims %s", attested.Challenge, attested.PodClaims)
	}
	if len(attested.SandboxToken) != 0 || attested.RuntimeExtensions != nil {
		t.Fatalf("pod profile sent a sandbox token (%s) or a top-level extension list (%v)", attested.SandboxToken, attested.RuntimeExtensions)
	}
	if result.Certificate != certPEM || result.Challenge != challenge || !result.Platform.IsTDX() || !slices.Equal(result.RuntimeExtensions, claims.RuntimeExtensions) {
		t.Fatalf("result = %+v", result)
	}
}

// Evidence from any platform but TDX ends the round before CDS is asked.
func TestObtainPodCertificateRefusesNonTDXEvidenceBeforeCDS(t *testing.T) {
	claims := testPodClaims(t)
	csrPEM, _ := testPodCSR(t)
	challenge := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cdsURL, apiURL, _, attested := podIssuanceServers(t, challenge, "snp", "cert")

	_, err := ObtainPodCertificateContext(context.Background(), attestclient.NewClient(cdsURL), apiURL, csrPEM, claims)
	if err == nil || !strings.Contains(err.Error(), "TDX") {
		t.Fatalf("err = %v, want a TDX refusal", err)
	}
	if attested.Challenge != "" || attested.CSR != "" {
		t.Fatal("a refused round reached CDS")
	}
}
