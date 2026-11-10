package workerauthorization

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestCheckWorkerAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name        string
		measurement string
		launch      string
		eligible    bool
	}{
		{"matches", testutil.TestMeasurement, testutil.CDSLaunchFile, true},
		{"image changed", testutil.NextCDSImage, testutil.CDSLaunchFile, false},
		{"launch changed", testutil.TestMeasurement, "another launch file", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := mockapi.New(t)
			verdict := mockapi.PassingVerdict(tc.measurement)
			binding := runtimemeasure.HostData([]byte(tc.launch))
			verdict.Claims.InitData = binding[:]
			api.SetVerdict(verdict)
			cds := servePolicy(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))
			checker := newTestChecker(cds, api)
			eligible, err := checker.Check(t.Context())
			if err != nil || eligible != tc.eligible {
				t.Fatalf("eligible=%v, err=%v; want %v", eligible, err, tc.eligible)
			}
			if len(api.AttestRequests()) != 1 || len(api.VerifyRequests()) != 1 {
				t.Fatal("check must acquire and verify fresh evidence")
			}
		})
	}
}

func TestCheckDistinguishesEmptyPolicyFromInvalidPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		unknown bool
	}{
		{"empty", `{"schema_version":"1","tee":"sev-snp","measurements":[]}`, false},
		{"missing", `{"schema_version":"1","tee":"sev-snp"}`, true},
		{"null", `{"schema_version":"1","tee":"sev-snp","measurements":null}`, true},
		{"wrong type", `{"schema_version":"1","tee":"sev-snp","measurements":{}}`, true},
		{"duplicate", `{"schema_version":"1","tee":"sev-snp","measurements":[],"measurements":[]}`, true},
		{"unknown schema", `{"schema_version":"unknown","tee":"sev-snp","measurements":[]}`, true},
		{"unknown platform", `{"schema_version":"1","tee":"unknown","measurements":[]}`, true},
		{"truncated", `{"measurements":[`, true},
		{"trailing", `{"schema_version":"1","tee":"sev-snp","measurements":[]} {}`, true},
		{"oversized", strings.Repeat(" ", maxPolicyBytes+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := mockapi.New(t)
			checker := newTestChecker(servePolicy(t, tc.body), api)
			eligible, err := checker.Check(t.Context())
			if eligible || (err != nil) != tc.unknown {
				t.Fatalf("eligible=%v, err=%v; unknown=%v", eligible, err, tc.unknown)
			}
			if len(api.AttestRequests()) != 0 {
				t.Fatal("policy must be validated before acquiring evidence")
			}
		})
	}
}

func TestCheckAcquiresFreshEvidenceForUnchangedPolicy(t *testing.T) {
	api := mockapi.New(t)
	verdict := mockapi.PassingVerdict(testutil.TestMeasurement)
	binding := runtimemeasure.HostData([]byte(testutil.CDSLaunchFile))
	verdict.Claims.InitData = binding[:]
	api.SetVerdict(verdict)
	checker := newTestChecker(servePolicy(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)), api)
	if eligible, err := checker.Check(t.Context()); err != nil || !eligible {
		t.Fatalf("first check: %v, %v", eligible, err)
	}
	verdict.Claims.InitData = nil
	api.SetVerdict(verdict)
	if eligible, err := checker.Check(t.Context()); err != nil || eligible {
		t.Fatalf("second check: %v, %v", eligible, err)
	}
	if len(api.AttestRequests()) != 2 {
		t.Fatal("unchanged policy reused old evidence")
	}
}

func TestCheckFailuresRemainUnknown(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*httptest.Server, *mockapi.Stub)
	}{
		{"CDS unavailable", stopCDS},
		{"invalid evidence", refuseEvidence},
		{"verifier unavailable", stopVerification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := mockapi.New(t)
			cds := servePolicy(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))
			checker := newTestChecker(cds, api)
			tc.fail(cds, api)
			requireUnknown(t, checker, t.Context())
		})
	}
	t.Run("HTTP forbidden", func(t *testing.T) {
		denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
		t.Cleanup(denied.Close)
		requireUnknown(t, newTestChecker(denied, mockapi.New(t)), t.Context())
	})
	t.Run("canceled", func(t *testing.T) {
		checker := newTestChecker(servePolicy(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)), mockapi.New(t))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		requireUnknown(t, checker, ctx)
	})
}

func stopCDS(cds *httptest.Server, _ *mockapi.Stub) { cds.Close() }
func refuseEvidence(_ *httptest.Server, api *mockapi.Stub) {
	api.SetVerifyError(mockapi.VerificationFailed("bad signature"))
}
func stopVerification(_ *httptest.Server, api *mockapi.Stub) {
	api.SetVerifyError(mockapi.ErrorReply{Status: http.StatusServiceUnavailable, Code: "unavailable"})
}
func requireUnknown(t *testing.T, checker *Checker, ctx context.Context) {
	t.Helper()
	if eligible, err := checker.Check(ctx); eligible || err == nil {
		t.Fatalf("failure became a decision: %v, %v", eligible, err)
	}
}

func TestCheckRejectsChangedRuntimeUnderUnchangedPolicy(t *testing.T) {
	api := mockapi.New(t)
	api.SetPlatform(teetypes.PlatformTDX)
	verdict := mockapi.PassingVerdict(testutil.TestMeasurement)
	verdict.Claims.PlatformData = map[string]any{"rtmr_1": testutil.TestMeasurement}
	api.SetVerdict(verdict)
	policy := `{"schema_version":"1","tee":"tdx","measurements":[{"name":"worker","mrtd":"` + testutil.TestMeasurement + `","rtmr":[null,"` + testutil.TestMeasurement + `"]}]}`
	cds := servePolicy(t, policy)
	provider := &armtls.SelfSignedProvider{
		Platform: "tdx",
		Opts:     &armtls.CertOptions{},
		AttestFunc: func(context.Context, string) (string, error) {
			return `{"platform":"tdx","evidence":{"quote":"fake"}}`, nil
		},
	}
	checker := New(cds.Client(), cds.URL, provider, api.URL())
	if eligible, err := checker.Check(t.Context()); !eligible || err != nil {
		t.Fatalf("matching runtime: %v, %v", eligible, err)
	}
	verdict.Claims.PlatformData = map[string]any{"rtmr_1": strings.Repeat("0", 96)}
	api.SetVerdict(verdict)
	if eligible, err := checker.Check(t.Context()); eligible || err != nil {
		t.Fatalf("changed runtime: %v, %v", eligible, err)
	}
	if len(api.VerifyRequests()) != 2 {
		t.Fatal("unchanged policy reused an earlier verdict")
	}
}

func TestCheckReplaysFreshWorkerJournal(t *testing.T) {
	api := mockapi.New(t)
	api.SetPlatform(teetypes.PlatformTDX)
	extension := "sha256:" + strings.Repeat("a", 64)
	journal := filepath.Join(t.TempDir(), "measured-policies")
	if err := os.WriteFile(journal, []byte(extension+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := runtimemeasure.Seed([]byte(testutil.CDSLaunchFile))
	register := runtimemeasure.FromDigestsSeeded(seed, []string{extension})
	verdict := mockapi.PassingVerdict(testutil.TestMeasurement)
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": hex.EncodeToString(register[:])}
	api.SetVerdict(verdict)
	launchDigest := sha512.Sum384([]byte(testutil.CDSLaunchFile))
	policy := `{"schema_version":"2","tee":"tdx","measurements":[{"name":"worker","mrtd":"` + testutil.TestMeasurement + `","launch_file_digest":"` + hex.EncodeToString(launchDigest[:]) + `"}]}`
	cds := servePolicy(t, policy)
	provider := &armtls.SelfSignedProvider{
		Platform:         "tdx",
		Opts:             &armtls.CertOptions{},
		MeasuredPolicies: armtls.NewJournal(journal),
		AttestFunc: func(context.Context, string) (string, error) {
			return `{"platform":"tdx","evidence":{"quote":"fake"}}`, nil
		},
	}
	checker := New(cds.Client(), cds.URL, provider, api.URL())
	if eligible, err := checker.Check(t.Context()); !eligible || err != nil {
		t.Fatalf("replaying journal: %v, %v", eligible, err)
	}
	if err := os.WriteFile(journal, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if eligible, err := checker.Check(t.Context()); eligible || err != nil {
		t.Fatalf("quote/journal mismatch: %v, %v", eligible, err)
	}
	register = runtimemeasure.FromDigestsSeeded(seed, nil)
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": hex.EncodeToString(register[:])}
	api.SetVerdict(verdict)
	if eligible, err := checker.Check(t.Context()); !eligible || err != nil {
		t.Fatalf("coherent fresh evidence: %v, %v", eligible, err)
	}
}

func servePolicy(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/measurements" {
			t.Errorf("unexpected policy request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func newTestChecker(cds *httptest.Server, api *mockapi.Stub) *Checker {
	provider := &armtls.SelfSignedProvider{
		Platform:   "sev-snp",
		Opts:       &armtls.CertOptions{},
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), api.URL()),
	}
	return New(cds.Client(), cds.URL, provider, api.URL())
}
