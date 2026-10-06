package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// tdxEnvelope is a minimal self-describing evidence envelope; the actual
// verification verdict comes from the stubbed verifyEnvelope.
const tdxEnvelope = `{"platform":"tdx","evidence":{}}`

// newAttestedTLSServer starts a TLS httptest server whose serving cert is a
// genuine ARmTLS attested cert (quote envelope embedded, self-signed), the
// same shape the cred-release endpoint serves.
func newAttestedTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return newPlatformAttestedTLSServer(t, teetypes.PlatformTDX, handler)
}

func newPlatformAttestedTLSServer(t *testing.T, platform teetypes.PlatformType, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeTDX, Report: []byte(tdxEnvelope)}
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
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newAttestStub starts the shared fake attestation-api (remote/mockapi)
// reporting the TDX platform the trust gate requires; the recorded requests
// let tests pin what production code sent.
func newAttestStub(t *testing.T) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformTDX)
	return stub
}

// failingAttest serves POST /attest with the given status — the attest gate's
// HTTP failure path.
func failingAttest(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "attest boom", status)
	}))
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
// the caller's attest endpoint URL, ARmTLS cred-release endpoint, and a
// stubbed verifier that accepts iff the claims satisfy the full
// measured-identity policy.
type testEnv struct {
	keyPath      string
	manifestPath string
	attestURL    string
	releaseURL   string
	outPath      string
	exp          measuredPolicy
	// releaseRole holds the role the fake cred-release last received.
	releaseRole *atomic.Value
}

func newTestEnv(t *testing.T, attestURL string, releaseStatus int, releaseBody string) testEnv {
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
	policy, err := policyFor(manifestPath, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := policy
	stubVerify(t, verifiedResultFor(exp), nil)

	releaseRole := new(atomic.Value)
	release := newAttestedTLSServer(t, releaseHandler(t, releaseStatus, releaseBody, releaseRole))

	return testEnv{
		keyPath:      keyPath,
		manifestPath: manifestPath,
		attestURL:    attestURL,
		releaseURL:   release.URL,
		outPath:      filepath.Join(dir, "kubeconfig"),
		exp:          exp,
		releaseRole:  releaseRole,
	}
}

const goodRelease = `{"cert":"CERTPEM","ca":"CAPEM"}`

func (e testEnv) config() Config {
	return Config{
		AttestURL:         e.attestURL,
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

// TestRunEndToEnd drives the full client flow against fake endpoints: attest
// gate, ARmTLS dial (verified via the stub), operator-signed CSR exchange, and
// kubeconfig assembly on disk.
func TestRunEndToEnd(t *testing.T) {
	env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)

	if err := Run(context.Background(), env.config()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	kc, err := os.ReadFile(env.outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server: https://node:6443",
		"tls-server-name: c8s-cvm",
		"client-certificate-data: " + base64.StdEncoding.EncodeToString([]byte("CERTPEM")),
		"certificate-authority-data: " + base64.StdEncoding.EncodeToString([]byte("CAPEM")),
	} {
		if !strings.Contains(string(kc), want) {
			t.Errorf("kubeconfig missing %q", want)
		}
	}
}

// TestAttestNonceIsFreshPerRun pins the attest gate's freshness: each run
// sends a fresh random nonce to /attest and asks the verifier to bind exactly
// those bytes. Replacing rand.Read(nonce) with a constant fails this — the
// gate would accept one recorded genuine quote replayed forever.
func TestAttestNonceIsFreshPerRun(t *testing.T) {
	attest := newAttestStub(t)
	exp := testPolicy(t, operatorPub(t))
	rec := stubVerify(t, verifiedResultFor(exp), nil)

	for i := range 2 {
		if err := attestAndVerify(context.Background(), attest.URL()+"/attest", exp); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	reqs := attest.AttestRequests()
	calls := rec.all()
	if len(reqs) != 2 || len(calls) != 2 {
		t.Fatalf("attest requests = %d, verifier calls = %d, want 2 each", len(reqs), len(calls))
	}
	for i := range reqs {
		nonce := reqs[i].ReportData
		if len(nonce) != 32 {
			t.Errorf("run %d: /attest nonce is %d bytes, want 32", i, len(nonce))
		}
		if !bytes.Equal(calls[i].params.ExpectedReportData, nonce) {
			t.Errorf("run %d: verifier asked to bind %x, but /attest was sent %x",
				i, calls[i].params.ExpectedReportData, nonce)
		}
	}
	if bytes.Equal(reqs[0].ReportData, reqs[1].ReportData) {
		t.Error("the attest nonce is constant across runs — a recorded genuine quote replays forever")
	}
}

func TestRunErrors(t *testing.T) {
	t.Run("attest gate HTTP failure", func(t *testing.T) {
		cfg := newTestEnv(t, failingAttest(t, http.StatusInternalServerError).URL+"/attest", http.StatusOK, goodRelease).config()
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "attestation gate") ||
			!strings.Contains(err.Error(), "attest HTTP 500") {
			t.Fatalf("want attest-gate HTTP 500 error, got %v", err)
		}
	})

	t.Run("release failure", func(t *testing.T) {
		cfg := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusForbidden, goodRelease).config()
		err := Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "credential release") ||
			!strings.Contains(err.Error(), "release HTTP 403") {
			t.Fatalf("want release HTTP 403 error, got %v", err)
		}
	})
}

// TestRunRejectsWrongRTMR3 covers the trust gate end to end: the node's quote
// verifies but rtmr_3 doesn't match the operator-key chain, so Run must stop
// before ever contacting cred-release.
func TestRunRejectsWrongRTMR3(t *testing.T) {
	env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
	res := verifiedResultFor(env.exp)
	res.Claims.PlatformData["rtmr_3"] = strings.Repeat("00", 48)
	stubVerify(t, res, nil) // overrides the env's stub

	// A failure of the explicit nonce gate must prevent the release request.
	var releaseHits atomic.Int32
	release := newAttestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releaseHits.Add(1)
		releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
	}))
	t.Cleanup(release.Close)
	cfg := env.config()
	cfg.ReleaseBaseURL = release.URL

	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "not bound to the expected anchor") {
		t.Fatalf("want an anchor-binding refusal, got %v", err)
	}
	if n := releaseHits.Load(); n != 0 {
		t.Fatalf("cred-release hits = %d, want 0 (Run must stop at the trust gate)", n)
	}
}

// TestARMTLSClientRejectsPlainCert confirms the ARmTLS dial fails closed
// against a server whose cert carries no attestation envelope (a host MITM).
func TestARMTLSClientRejectsPlainCert(t *testing.T) {
	env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
	plain := httptest.NewTLSServer(releaseHandler(t, http.StatusOK, goodRelease, nil))
	t.Cleanup(plain.Close)

	cfg := env.config()
	cfg.ReleaseBaseURL = plain.URL
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "carries no ARmTLS attestation extension") {
		t.Fatalf("want ARmTLS handshake failure (no ARmTLS extension), got %v", err)
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

func TestVerifyEvidenceErrors(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))

	t.Run("bad envelope JSON", func(t *testing.T) {
		_, err := verifyEvidence([]byte("not json"), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "parse evidence envelope") {
			t.Fatalf("want parse error, got %v", err)
		}
	})

	t.Run("empty evidence object", func(t *testing.T) {
		_, err := verifyEvidence([]byte(`{"platform":"tdx"}`), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "no evidence object") {
			t.Fatalf("want empty-evidence error, got %v", err)
		}
	})

	// The envelope shape is single-wrap on both gates; a double-wrapped
	// envelope must fail loudly rather than reach the verifier as evidence it
	// misparses or ignores.
	t.Run("double-wrapped envelope", func(t *testing.T) {
		stubVerify(t, verifiedResultFor(exp), nil) // must not be reached
		double := `{"platform":"tdx","evidence":` + tdxEnvelope + `}`
		_, err := verifyEvidence([]byte(double), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "double-wrapped") {
			t.Fatalf("want double-wrap rejection, got %v", err)
		}
	})

	t.Run("verifier error", func(t *testing.T) {
		stubVerify(t, nil, fmt.Errorf("boom"))
		_, err := verifyEvidence([]byte(tdxEnvelope), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "verify evidence: boom") {
			t.Fatalf("want wrapped verifier error, got %v", err)
		}
	})

	t.Run("signature invalid", func(t *testing.T) {
		res := verifiedResultFor(exp)
		res.SignatureValid = false
		stubVerify(t, res, nil)
		_, err := verifyEvidence([]byte(tdxEnvelope), nil, exp)
		if err == nil || !strings.Contains(err.Error(), "quote signature invalid") {
			t.Fatalf("want signature error, got %v", err)
		}
	})
}

func TestCheckMeasuredIdentityNoRTMR3Claim(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	res := verifiedResultFor(exp)
	res.Claims.PlatformData["rtmr_3"] = ""
	err := exp.checkIdentity(res)
	if err == nil || !strings.Contains(err.Error(), "no rtmr_3") {
		t.Fatalf("want no-rtmr_3 error, got %v", err)
	}
}

// --workload-image extends the expected RTMR[3] from the operator-key seed in
// the given (first-extend) order; tags never pass, and order changes the
// register.
func TestPolicyForWorkloadImages(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	digA := "sha256:" + strings.Repeat("aa", 32)
	digB := "ghcr.io/acme/api@sha256:" + strings.Repeat("bb", 32)

	bare, err := policyFor(manifest, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := bare.workloadDigests; len(got) != 0 {
		t.Errorf("workloadDigests = %v, want none so the expected register is the bare operator-key seed", got)
	}

	chained, err := policyFor(manifest, pub, []string{digA, digB})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{digA, "sha256:" + strings.Repeat("bb", 32)}
	if got := chained.workloadDigests; !slices.Equal(got, want) {
		t.Errorf("workloadDigests = %v, want %v (canonicalized, in first-extend order)", got, want)
	}

	reversed, err := policyFor(manifest, pub, []string{digB, digA})
	if err != nil {
		t.Fatal(err)
	}
	if got := reversed.workloadDigests; slices.Equal(got, want) {
		t.Error("extend order must reach the chain unchanged — the register is ordered")
	}

	for _, bad := range []string{"nginx:latest", "ghcr.io/acme/api:v1", "sha256:" + strings.Repeat("AB", 32)} {
		if _, err := policyFor(manifest, pub, []string{bad}); err == nil {
			t.Errorf("policyFor accepted non-canonical workload image %q", bad)
		}
	}
}

// The node's measurer extends each image once, so repeating one here would
// extend the EXPECTED register an extra time and build a gate no node can ever
// satisfy — a permanently red, silently wrong policy. It has to be a usage
// error, including when the two spellings differ but the digest does not.
func TestPolicyForRejectsDuplicateWorkloadImages(t *testing.T) {
	pub := operatorPub(t)
	manifest := writeTestManifest(t, tdxManifest())
	dig := "sha256:" + strings.Repeat("aa", 32)

	for _, tc := range []struct {
		name string
		refs []string
	}{
		{"identical refs", []string{dig, dig}},
		{"same digest, different spelling", []string{dig, "ghcr.io/acme/api@" + dig}},
		{"repeat separated by another image", []string{dig, "sha256:" + strings.Repeat("bb", 32), dig}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policyFor(manifest, pub, tc.refs); err == nil {
				t.Fatal("a repeated workload image must be rejected, not silently doubled into the chain")
			}
		})
	}

	// Sanity: the single-occurrence policy this rejection protects is exactly
	// the one a node with that image can satisfy.
	single, err := policyFor(manifest, pub, []string{dig})
	if err != nil {
		t.Fatal(err)
	}
	if got := single.workloadDigests; !slices.Equal(got, []string{dig}) {
		t.Errorf("workloadDigests = %v, want [%s]", got, dig)
	}
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
