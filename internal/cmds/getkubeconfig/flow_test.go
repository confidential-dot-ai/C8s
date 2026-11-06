package getkubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// newAttestedTLSServer starts a TLS httptest server whose serving cert is a
// genuine armTLS attested cert (quote envelope embedded, self-signed), the
// same shape the cred-release endpoint serves.
func newAttestedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return newPlatformAttestedTLSServer(t, teetypes.PlatformTDX, handler)
}

func newPlatformAttestedTLSServer(t *testing.T, platform teetypes.PlatformType, handler http.Handler) *httptest.Server {
	t.Helper()
	return newAttestedTLSServerWithExtensions(t, platform, nil, handler)
}

// newAttestedTLSServerWithExtensions serves a leaf whose TDX attestation
// carries extensions as its runtime extension list.
func newAttestedTLSServerWithExtensions(t *testing.T, platform teetypes.PlatformType, extensions []string, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := unstartedAttestedTLSServer(t, platform, extensions, handler)
	srv.StartTLS()
	return srv
}

// unstartedAttestedTLSServer is newAttestedTLSServerWithExtensions before
// StartTLS, so a test can choose its listener.
func unstartedAttestedTLSServer(t *testing.T, platform teetypes.PlatformType, extensions []string, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeTDX, Report: []byte(tdxEnvelope), RuntimeExtensions: extensions}
	if platform == teetypes.PlatformSNP {
		rd, err := armtls.ReportDataForKey(&key.PublicKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		report := make([]byte, 1184)
		copy(report[0x50:], rd[:])
		att = &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: report}
	}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	t.Cleanup(srv.Close)
	return srv
}

// releaseHandler serves POST /release-credential with the given status; on 200
// it checks the operator JWT + CSR shape and returns cert/ca PEMs. gotRole,
// when non-nil, records the role the request body carried.
func releaseHandler(t *testing.T, status int, respBody string, gotRole *atomic.Value) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != credrelease.ReleasePath {
			t.Errorf("release path = %s, want %s", r.URL.Path, credrelease.ReleasePath)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("release Authorization = %q, want Bearer JWT", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var req credrelease.ReleaseRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("release body: %v", err)
		}
		if !strings.Contains(req.CSRPEM, "CERTIFICATE REQUEST") {
			t.Errorf("release csr = %q, want a CSR PEM", req.CSRPEM)
		}
		if gotRole != nil {
			gotRole.Store(req.Role)
		}
		if status != http.StatusOK {
			http.Error(w, "release boom", status)
			return
		}
		fmt.Fprint(w, respBody)
	})
}

// testEnv wires up a full fake node: operator key + image manifest on disk,
// an armTLS cred-release endpoint, and a stubbed verifier that accepts iff the
// claims satisfy the full measured-identity policy.
type testEnv struct {
	keyPath      string
	manifestPath string
	releaseURL   string
	outPath      string
	exp          guestverify.Policy
	// operatorPubPEM is the public half of the key at keyPath.
	operatorPubPEM []byte
	// releaseRole holds the role the fake cred-release last received.
	releaseRole *atomic.Value
}

func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := mustKeyPEM(t, key)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "op.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := writeTestManifest(t, tdxManifest())
	policy, err := guestverify.PolicyFor(manifestPath, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := policy
	stubVerify(t, verifiedResultFor(pub), nil)

	releaseRole := new(atomic.Value)
	release := newAttestedTLSServer(t, releaseHandler(t, http.StatusOK, goodRelease, releaseRole))

	return testEnv{
		keyPath:        keyPath,
		manifestPath:   manifestPath,
		releaseURL:     release.URL,
		outPath:        filepath.Join(dir, "kubeconfig"),
		exp:            exp,
		operatorPubPEM: pub,
		releaseRole:    releaseRole,
	}
}

const goodRelease = `{"cert":"CERTPEM","ca":"CAPEM"}`

func (e testEnv) config() Config {
	return Config{
		ReleaseBaseURL:    e.releaseURL,
		APIServerURL:      "https://node:6443",
		OperatorKeyPath:   e.keyPath,
		ImageManifestPath: e.manifestPath,
		ContextName:       "c8s",
		TLSServerName:     "c8s-cvm",
		OutPath:           e.outPath,
		Timeout:           10 * time.Second,
	}
}

// TestRunRejectsWrongRTMR3 covers the trust gate end to end: the node's quote
// verifies but rtmr_3 doesn't match the operator-key chain, so Run must stop
// before ever contacting cred-release.
func TestRunRejectsWrongRTMR3(t *testing.T) {
	env := newTestEnv(t)
	res := verifiedResultFor(env.operatorPubPEM)
	res.Claims.PlatformData["rtmr_3"] = strings.Repeat("00", 48)
	stubVerify(t, res, nil) // overrides the env's stub

	// The gate must fail before any request reaches cred-release.
	var releaseHits atomic.Int32
	release := newAttestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releaseHits.Add(1)
		releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
	}))
	t.Cleanup(release.Close)
	cfg := env.config()
	cfg.ReleaseBaseURL = release.URL

	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "not bound to the expected launch binding") {
		t.Fatalf("want a launch-binding refusal, got %v", err)
	}
	if n := releaseHits.Load(); n != 0 {
		t.Fatalf("cred-release hits = %d, want 0 (Run must stop at the trust gate)", n)
	}
}

// TestARMTLSClientRejectsPlainCert confirms the armTLS dial fails closed
// against a server whose cert carries no attestation envelope (a host MITM).
func TestARMTLSClientRejectsPlainCert(t *testing.T) {
	env := newTestEnv(t)
	plain := httptest.NewTLSServer(releaseHandler(t, http.StatusOK, goodRelease, nil))
	t.Cleanup(plain.Close)

	cfg := env.config()
	cfg.ReleaseBaseURL = plain.URL
	err := Run(context.Background(), cfg)
	if !errors.Is(err, armtls.ErrNoAttestation) {
		t.Fatalf("want armTLS handshake failure (no armTLS extension), got %v", err)
	}
}

func TestRequestCredentialErrors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := mustKeyPEM(t, key)
	id, err := newClientIdentity()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.csrPEM()
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	t.Run("bad operator key", func(t *testing.T) {
		_, err := requestCredential(ctx, client, "http://127.0.0.1:0", []byte("junk"), csr, "")
		if err == nil || !strings.Contains(err.Error(), "operator key") {
			t.Fatalf("want operator-key error, got %v", err)
		}
	})

	serve := func(status int, body string) *httptest.Server {
		srv := httptest.NewServer(releaseHandler(t, status, body, nil))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("release refused", func(t *testing.T) {
		srv := serve(http.StatusForbidden, goodRelease)
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr, "")
		if err == nil || !strings.Contains(err.Error(), "release HTTP 403") {
			t.Fatalf("want release HTTP 403 error, got %v", err)
		}
	})

	t.Run("bad response JSON", func(t *testing.T) {
		srv := serve(http.StatusOK, "not json")
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr, "")
		if err == nil || !strings.Contains(err.Error(), "parse release response") {
			t.Fatalf("want parse error, got %v", err)
		}
	})

	t.Run("missing ca", func(t *testing.T) {
		srv := serve(http.StatusOK, `{"cert":"CERTPEM"}`)
		_, err := requestCredential(ctx, client, srv.URL, keyPEM, csr, "")
		if err == nil || !strings.Contains(err.Error(), "missing cert or ca") {
			t.Fatalf("want missing-field error, got %v", err)
		}
	})
}

func TestPublicKeyPEMFromPrivateErrors(t *testing.T) {
	t.Run("not PEM", func(t *testing.T) {
		_, err := publicKeyPEMFromPrivate([]byte("garbage"))
		if err == nil || !strings.Contains(err.Error(), "not PEM") {
			t.Fatalf("want not-PEM error, got %v", err)
		}
	})

	t.Run("unsupported PEM type", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
		_, err := publicKeyPEMFromPrivate(blob)
		if err == nil || !strings.Contains(err.Error(), "unsupported key PEM type") {
			t.Fatalf("want unsupported-type error, got %v", err)
		}
	})

	t.Run("PKCS8 non-ECDSA", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			t.Fatal(err)
		}
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		_, err = publicKeyPEMFromPrivate(blob)
		if err == nil || !strings.Contains(err.Error(), "want ECDSA") {
			t.Fatalf("want non-ECDSA error, got %v", err)
		}
	})

	t.Run("bad SEC1 body", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}})
		if _, err := publicKeyPEMFromPrivate(blob); err == nil {
			t.Fatal("want SEC1 parse error, got nil")
		}
	})

	t.Run("bad PKCS8 body", func(t *testing.T) {
		blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
		if _, err := publicKeyPEMFromPrivate(blob); err == nil {
			t.Fatal("want PKCS8 parse error, got nil")
		}
	})
}
