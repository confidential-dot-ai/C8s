package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func discoveryDocWith(t *testing.T, certPEM string, challenge []byte, evidence string) []byte {
	t.Helper()
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString(challenge),
			"platform":  "snp",
			"evidence":  json.RawMessage(evidence),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery doc: %v", err)
	}
	return data
}

// attestedTLSServer starts an httptest TLS server whose serving certificate is
// a (fake-report) ARmTLS attested cert, so cert-mode gathering succeeds.
func attestedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestGatherFromARMTLSCert(t *testing.T) {
	t.Run("attested serving cert", func(t *testing.T) {
		srv := attestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := strings.TrimPrefix(srv.URL, "https://")
		ev, err := gatherFromARMTLSCert(context.Background(), addr, "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatalf("gatherFromARMTLSCert: %v", err)
		}
		if ev.platform != "snp" || ev.fresh {
			t.Errorf("platform=%q fresh=%t, want snp / not fresh", ev.platform, ev.fresh)
		}
		if ev.certSHA256 == "" {
			t.Error("certSHA256 not recorded")
		}
		if !strings.Contains(ev.source, addr) {
			t.Errorf("source = %q, want the dialed address", ev.source)
		}
	})

	t.Run("plain cert without ARmTLS extension", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer srv.Close()
		_, err := gatherFromARMTLSCert(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "", 5*time.Second, leafTrust{})
		if err == nil || isConnectError(err) {
			t.Fatalf("non-attested cert must fail as a non-connect error, got %v", err)
		}
	})

	t.Run("dial failure is a connectError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := strings.TrimPrefix(srv.URL, "https://")
		srv.Close()
		_, err := gatherFromARMTLSCert(context.Background(), addr, "", time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("expected connectError on refused dial, got %v", err)
		}
	})
}

func TestEvidenceFromEndpointJSON_Malformed(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	sess := fakeSession(0x02)
	// A genuine attest-pq body, so the only thing wrong in each case below is
	// the one field the mutation corrupts.
	id := mintEndpointIdentity(t)

	mutate := func(field, value string) []byte {
		var obj map[string]any
		if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, report, []byte("vcek"), sess), &obj); err != nil {
			t.Fatal(err)
		}
		obj[field] = value
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	if _, err := evidenceFromEndpointJSON([]byte("not json"), nonce, sess.ek, "t"); err == nil {
		t.Error("non-JSON must fail")
	}
	if _, err := evidenceFromEndpointJSON([]byte(`{"nonce":"AA"}`), nonce, sess.ek, "t"); err == nil {
		t.Error("missing evidence must fail")
	}
	// "!!!" is outside the base64url alphabet in every position.
	for field, want := range map[string]string{
		"nonce":      "decode nonce",
		"xwing_ek":   "decode xwing_ek",
		"xwing_ct":   "decode xwing_ct",
		"session_id": "decode session_id",
	} {
		if _, err := evidenceFromEndpointJSON(mutate(field, "!!!"), nonce, sess.ek, "t"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("bad %s base64 should fail decoding, got %v", field, err)
		}
	}
}

func TestJoinAttestationURL(t *testing.T) {
	got, err := joinAttestationURL("https://lb.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	// The challenge travels in the POST body now, so the URL carries no query.
	if want := "https://lb.example.com:443" + attestationPath; got != want {
		t.Errorf("joined URL = %q, want %q", got, want)
	}
	if _, err := joinAttestationURL("https://\x7f"); err == nil {
		t.Error("unparseable base URL must fail")
	}
}

func TestGatherFromEndpoint_BadBaseURL(t *testing.T) {
	if _, err := gatherFromEndpoint(context.Background(), "https://\x7f", "", time.Second); err == nil {
		t.Fatal("unparseable base URL must fail before any dial")
	}
}

func TestGatherFromFile(t *testing.T) {
	t.Run("attested certificate PEM", func(t *testing.T) {
		cert := attestedCert(t, "")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		ev, err := gatherFromFile(pemBytes, nil, "file", leafTrust{})
		if err != nil {
			t.Fatalf("gatherFromFile: %v", err)
		}
		wantSum := sha256.Sum256(cert.Raw)
		if ev.certSHA256 != hex.EncodeToString(wantSum[:]) {
			t.Errorf("certSHA256 = %q, want the cert digest", ev.certSHA256)
		}
	})

	t.Run("unparseable certificate DER", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
		if _, err := gatherFromFile(pemBytes, nil, "file", leafTrust{}); err == nil || !strings.Contains(err.Error(), "parse certificate") {
			t.Errorf("expected a parse error, got %v", err)
		}
	})

	t.Run("override falls through to endpoint parsing", func(t *testing.T) {
		// Not bare evidence (no evidence object), so the bare path fails and the
		// endpoint parser reports its own error. The version tag has to be the
		// attest-pq binding or the parser stops at the version check instead.
		payload := []byte(`{"version":"` + types.BindingAttestPQ + `"}`)
		if _, err := gatherFromFile(payload, []byte{0x01}, "file", leafTrust{}); err == nil || !strings.Contains(err.Error(), "no evidence") {
			t.Errorf("expected the endpoint parser's error, got %v", err)
		}
	})
}

func TestEvidenceFromBareJSON_Errors(t *testing.T) {
	if _, err := evidenceFromBareJSON([]byte("not json"), []byte{0x01}, "t"); err == nil {
		t.Error("non-JSON must fail")
	}
	if _, err := evidenceFromBareJSON([]byte(`{"platform":"snp"}`), []byte{0x01}, "t"); err == nil {
		t.Error("missing evidence must fail")
	}
	ev, err := evidenceFromBareJSON([]byte(`{"evidence":{"attestation_report":"AAAA"}}`), []byte{0x01}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want the snp default", ev.platform)
	}
}
