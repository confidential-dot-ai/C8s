package getkubeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// newBootstrapEnv exposes only the credential service. Hardware verification is
// stubbed, while TLS, the operator signature, nonce round-trip, and policy
// enforcement use the production code.
func newBootstrapEnv(t *testing.T, platform teetypes.PlatformType, mutateFresh func(*teetypes.VerificationResult)) (testEnv, <-chan []byte, *atomic.Int32) {
	t.Helper()
	env := newTestEnv(t, "", http.StatusOK, goodRelease)
	if platform == teetypes.PlatformSNP {
		env.manifestPath = writeTestManifest(t, snpManifest())
		var err error
		env.exp, err = policyFor(env.manifestPath, env.exp.operatorPubPEM, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	verify := func(evidence []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		var result *teetypes.VerificationResult
		if platform == teetypes.PlatformSNP {
			result = snpResultFor(t, env.exp, 4)
		} else {
			result = verifiedResultFor(env.exp)
		}
		if len(params.ExpectedReportData) == 32 {
			var reported credrelease.AttestRequest
			if err := json.Unmarshal(evidence, &reported); err != nil {
				return nil, err
			}
			result.ReportDataMatch = teetypes.Ptr(bytes.Equal(reported.Nonce, params.ExpectedReportData))
			if mutateFresh != nil {
				mutateFresh(result)
			}
		}
		return result, nil
	}
	if platform == teetypes.PlatformSNP {
		restore := verifySNPARMTLS
		verifySNPARMTLS = func(_ context.Context, _ string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
			return verify(evidence, params.VerifyParams)
		}
		t.Cleanup(func() { verifySNPARMTLS = restore })
	} else {
		restore := verifyEnvelope
		verifyEnvelope = func(envelope []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
			var evidence teetypes.AttestationEvidence
			if err := json.Unmarshal(envelope, &evidence); err != nil {
				return nil, err
			}
			return verify(evidence.Evidence, params)
		}
		t.Cleanup(func() { verifyEnvelope = restore })
	}
	keys, err := operatorauth.ParsePublicKeysPEM(env.exp.operatorPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	verifier := operatorauth.Verifier{Keys: keys, ClockSkew: time.Minute}
	nonces := make(chan []byte, 8)
	releases := &atomic.Int32{}
	srv := newPlatformAttestedTLSServer(t, platform, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		if err := verifier.Authorize(r, body); err != nil {
			t.Errorf("operator authorization: %v", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case credrelease.AttestPath:
			var req credrelease.AttestRequest
			if err := json.Unmarshal(body, &req); err != nil || len(req.Nonce) != 32 {
				t.Errorf("invalid nonce request: %s", body)
				http.Error(w, "nonce", http.StatusBadRequest)
				return
			}
			nonces <- append([]byte(nil), req.Nonce...)
			_ = json.NewEncoder(w).Encode(teetypes.AttestationEvidence{Platform: platform, Evidence: body})
		case credrelease.ReleasePath:
			releases.Add(1)
			r.Body = io.NopCloser(bytes.NewReader(body))
			releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	env.releaseURL = srv.URL
	return env, nonces, releases
}

func TestDefaultBootstrapFreshness(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		t.Run(string(platform), func(t *testing.T) {
			env, nonces, releases := newBootstrapEnv(t, platform, nil)
			for i := 0; i < 2; i++ {
				if err := Run(context.Background(), env.config()); err != nil {
					t.Fatalf("Run %d: %v", i, err)
				}
			}
			first, second := <-nonces, <-nonces
			if bytes.Equal(first, second) {
				t.Fatal("nonce reused across bootstrap runs")
			}
			if releases.Load() != 2 {
				t.Fatalf("release requests = %d, want 2", releases.Load())
			}
			kc, err := os.ReadFile(env.outPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(kc, []byte("server: https://node:6443")) {
				t.Fatalf("wrong kubeconfig server: %s", kc)
			}
		})
	}
}

func TestDefaultBootstrapRejectsFreshEvidence(t *testing.T) {
	for _, platform := range []teetypes.PlatformType{teetypes.PlatformTDX, teetypes.PlatformSNP} {
		cases := map[string]func(*teetypes.VerificationResult){
			"nonce mismatch":    func(r *teetypes.VerificationResult) { r.ReportDataMatch = teetypes.Ptr(false) },
			"invalid signature": func(r *teetypes.VerificationResult) { r.SignatureValid = false },
			"wrong image":       func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("ab", 48) },
			"wrong operator binding": func(r *teetypes.VerificationResult) {
				if platform == teetypes.PlatformSNP {
					r.Claims.InitData = teetypes.HexBytes(make([]byte, 32))
				} else {
					r.Claims.PlatformData["rtmr_3"] = strings.Repeat("00", 48)
				}
			},
		}
		for name, mutate := range cases {
			t.Run(string(platform)+"/"+name, func(t *testing.T) {
				env, _, releases := newBootstrapEnv(t, platform, mutate)
				err := Run(context.Background(), env.config())
				if err == nil || !strings.Contains(err.Error(), "attestation gate") {
					t.Fatalf("want fresh-evidence gate failure, got %v", err)
				}
				if releases.Load() != 0 {
					t.Fatal("credential requested after failed fresh attestation")
				}
				if _, err := os.Stat(env.outPath); !os.IsNotExist(err) {
					t.Fatalf("failed bootstrap wrote a kubeconfig: %v", err)
				}
			})
		}
	}
}

func TestNewCmdDefaultBootstrap(t *testing.T) {
	for _, mode := range []string{"explicit URLs", "node", "vmi"} {
		t.Run(mode, func(t *testing.T) {
			env, _, releases := newBootstrapEnv(t, teetypes.PlatformTDX, nil)
			args := []string{
				"--release-url", env.releaseURL,
				"--apiserver-url", "https://127.0.0.1:26443",
				"--operator-key", env.keyPath,
				"--image-manifest", env.manifestPath,
				"--out", env.outPath,
				"--release-wait", "0",
			}
			switch mode {
			case "node":
				args = append(args, "--node", "127.0.0.1")
			case "vmi":
				restore := resolveVMIAddress
				resolveVMIAddress = func(context.Context, string) (string, error) { return "127.0.0.1", nil }
				t.Cleanup(func() { resolveVMIAddress = restore })
				args = append(args, "--vmi", "test/server")
			}
			if err := execCmd(t, args...); err != nil {
				t.Fatalf("Execute without a raw attester: %v", err)
			}
			if releases.Load() != 1 {
				t.Fatalf("release requests = %d, want 1", releases.Load())
			}
		})
	}
}

func TestBootstrapTransportFailsClosed(t *testing.T) {
	env, _, _ := newBootstrapEnv(t, teetypes.PlatformTDX, nil)
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, goodRelease)
	}))
	t.Cleanup(plain.Close)
	t.Run("HTTP release URL", func(t *testing.T) {
		cfg := env.config()
		cfg.ReleaseBaseURL = plain.URL
		if err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("want HTTPS requirement, got %v", err)
		}
	})
	t.Run("redirect to HTTP", func(t *testing.T) {
		redirect := newAttestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+credrelease.AttestPath, http.StatusTemporaryRedirect)
		}))
		cfg := env.config()
		cfg.ReleaseBaseURL = redirect.URL
		if err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
			t.Fatalf("want redirect refusal, got %v", err)
		}
	})
	if hits.Load() != 0 {
		t.Fatalf("signed request reached HTTP: %d requests", hits.Load())
	}
}
