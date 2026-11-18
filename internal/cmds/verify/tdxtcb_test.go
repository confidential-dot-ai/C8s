package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

// tdxFixtureReportData is the REPORTDATA the vendored TDX quote carries,
// without the zero padding the verifier restores.
const tdxFixtureReportData = "b8b9e582d1efb326120f7215e75a2ac2327da81aa5b44209f69460ae5af99e00"

// tdxFixtureConfig verifies the vendored real TDX quote as bare evidence.
func tdxFixtureConfig(output string, statuses ...string) config {
	return config{
		fromFile:       "testdata/tdx-evidence.json",
		expectedRDHex:  tdxFixtureReportData,
		output:         output,
		timeout:        time.Second,
		tdxTCBStatuses: statuses,
	}
}

// stubVerifyLocally replaces the engine for one test.
func stubVerifyLocally(t *testing.T, stub func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, *localverify.TDXCollateral, error)) {
	t.Helper()
	prev := verifyLocally
	verifyLocally = stub
	t.Cleanup(func() { verifyLocally = prev })
}

func tdxResultWithStatus(status teetypes.TdxTcbStatus) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: teetypes.Ptr(true),
		Claims:          teetypes.Claims{LaunchDigest: strings.Repeat("ab", 48), TCB: teetypes.TcbInfo{Type: "Tdx"}},
		TCBStatus: &teetypes.DcapVerificationStatus{
			TCBStatus:   status,
			FMSPC:       "b0c06f000000",
			AdvisoryIDs: []string{"INTEL-SA-01192"},
		},
	}
}

func runVerify(t *testing.T, ctx context.Context, cfg config) (int, Outcome, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(ctx, cfg, &out, &errOut)
	var oc Outcome
	if cfg.output == "json" && out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &oc); err != nil {
			t.Fatalf("decode verdict: %v\n%s", err, out.String())
		}
	}
	return code, oc, out.String() + errOut.String()
}

func TestTDXTCBStatus(t *testing.T) {
	expires := time.Date(2026, time.December, 17, 21, 30, 1, 0, time.UTC)

	t.Run("an accepted status is reported with the collateral expiry", func(t *testing.T) {
		stubVerifyLocally(t, func(_ context.Context, _ string, _ json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, *localverify.TDXCollateral, error) {
			if !slices.Equal(p.TDXTCBStatuses, []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}) {
				t.Errorf("engine asked for statuses %v, want [UpToDate]", p.TDXTCBStatuses)
			}
			return tdxResultWithStatus(teetypes.TdxUpToDate), &localverify.TDXCollateral{NextUpdate: expires}, nil
		})
		code, oc, _ := runVerify(t, context.Background(), tdxFixtureConfig("json"))
		if code != exitVerified || !oc.Verified {
			t.Fatalf("exit %d, verdict %+v; want verified", code, oc)
		}
		if oc.TDXTCBStatus != "UpToDate" || oc.TDXCollateralExpiresAt == nil || !oc.TDXCollateralExpiresAt.Equal(expires) {
			t.Fatalf("tdx_tcb_status %q, expiry %v; want UpToDate expiring %s", oc.TDXTCBStatus, oc.TDXCollateralExpiresAt, expires)
		}
		if !slices.Equal(oc.TDXAdvisoryIDs, []string{"INTEL-SA-01192"}) || slices.Contains(oc.Warnings, tdxTCBUncheckedWarning) {
			t.Fatalf("advisories %v, warnings %v", oc.TDXAdvisoryIDs, oc.Warnings)
		}

		_, _, text := runVerify(t, context.Background(), tdxFixtureConfig("text", "UpToDate"))
		if !strings.Contains(text, "Intel TCB:    UpToDate (Intel PCS collateral, expires 2026-12-17T21:30:01Z)") {
			t.Fatalf("text verdict does not report the Intel TCB status:\n%s", text)
		}
	})

	t.Run("a status outside the accepted set fails the verdict", func(t *testing.T) {
		stubVerifyLocally(t, func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, *localverify.TDXCollateral, error) {
			return nil, nil, errors.New("tdx: platform TCB status OutOfDate is not accepted (accepted: [UpToDate])")
		})
		code, oc, _ := runVerify(t, context.Background(), tdxFixtureConfig("json", "UpToDate"))
		if code != exitFailed || oc.Verified || !strings.Contains(oc.Error, "OutOfDate is not accepted") || oc.TDXTCBStatus != "" {
			t.Fatalf("exit %d, verdict %+v; want a failed verdict naming OutOfDate", code, oc)
		}
	})

	t.Run("collateral that cannot be fetched exits 3", func(t *testing.T) {
		stubVerifyLocally(t, func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, *localverify.TDXCollateral, error) {
			return nil, nil, &localverify.CollateralError{Err: errors.New("fetch Intel PCS collateral: connection refused")}
		})
		code, _, text := runVerify(t, context.Background(), tdxFixtureConfig("json", "UpToDate"))
		if code != exitNoEvidence || !strings.Contains(text, "could not fetch verification collateral") {
			t.Fatalf("exit %d, output %q; want exit 3", code, text)
		}
	})

	t.Run("SEV-SNP evidence refuses the policy", func(t *testing.T) {
		stubVerifyLocally(t, func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, *localverify.TDXCollateral, error) {
			return &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformSNP, ReportDataMatch: teetypes.Ptr(true)}, nil, nil
		})
		code, oc, _ := runVerify(t, context.Background(), tdxFixtureConfig("json", "UpToDate"))
		if code != exitFailed || !strings.Contains(oc.Error, "--tdx-tcb-status is set but the evidence platform is \"snp\"") {
			t.Fatalf("exit %d, verdict %+v; want a policy error", code, oc)
		}
	})

	t.Run("an invalid status is a usage error", func(t *testing.T) {
		for _, status := range []string{"Revoked", "uptodate"} {
			if code, _, text := runVerify(t, context.Background(), tdxFixtureConfig("json", status)); code != exitUsage || !strings.Contains(text, "--tdx-tcb-status") {
				t.Errorf("--tdx-tcb-status %s: exit %d, output %q; want a usage error", status, code, text)
			}
		}
	})

	t.Run("offline mode cannot also require an Intel status", func(t *testing.T) {
		cfg := tdxFixtureConfig("json", "UpToDate")
		cfg.tdxOffline = true
		if code, _, text := runVerify(t, context.Background(), cfg); code != exitUsage || !strings.Contains(text, "--tdx-offline excludes") {
			t.Fatalf("exit %d, output %q; want a conflicting-flags error", code, text)
		}
	})

	t.Run("online mode requires a bounded timeout", func(t *testing.T) {
		for _, timeout := range []time.Duration{0, -time.Second} {
			cfg := tdxFixtureConfig("json")
			cfg.timeout = timeout
			if code, _, text := runVerify(t, context.Background(), cfg); code != exitUsage || !strings.Contains(text, "positive --timeout") {
				t.Fatalf("timeout %s: exit %d, output %q; want a usage error", timeout, code, text)
			}
		}
	})
}

// TestTDXTCBStatusRealEngine drives the real quote through the real engine.
// Neither case reaches the network: one verifies offline and the other's
// context is already cancelled.
func TestTDXTCBStatusRealEngine(t *testing.T) {
	t.Run("the default Intel policy leaves SNP verification unchanged", func(t *testing.T) {
		code, oc, text := runVerify(t, context.Background(), config{
			fromFile:      "testdata/azsnp-evidence-v1.json",
			expectedRDHex: hex.EncodeToString([]byte("challenge")),
			timeout:       time.Second,
			output:        "json",
		})
		if code != exitVerified || !oc.Verified || oc.Platform != "az-snp" || oc.TDXTCBStatus != "" {
			t.Fatalf("exit %d, output %s; want an SNP pass without an Intel status", code, text)
		}
	})

	t.Run("explicit offline mode verifies without Intel status and warns", func(t *testing.T) {
		cfg := tdxFixtureConfig("json")
		cfg.tdxOffline = true
		code, oc, _ := runVerify(t, context.Background(), cfg)
		if code != exitVerified || !oc.Verified || oc.Platform != "tdx" {
			t.Fatalf("exit %d, verdict %+v; want an offline TDX pass", code, oc)
		}
		if oc.TDXTCBStatus != "" || !slices.Contains(oc.Warnings, tdxTCBUncheckedWarning) {
			t.Fatalf("tdx_tcb_status %q, warnings %v; want no status and the unchecked warning", oc.TDXTCBStatus, oc.Warnings)
		}
	})

	t.Run("an unreachable PCS exits 3", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		code, _, text := runVerify(t, ctx, tdxFixtureConfig("json"))
		if code != exitNoEvidence || !strings.Contains(text, "Intel PCS collateral") {
			t.Fatalf("exit %d, output %q; want exit 3 naming Intel PCS", code, text)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("cancelled fetch took %s", elapsed)
		}
	})
}
