package cds

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// postAttestFrom submits evidence from one platform.
func postAttestFrom(t *testing.T, h AttestHandler, platform teetypes.PlatformType, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence: teetypes.AttestationEvidence{
			Platform: platform,
			Evidence: json.RawMessage(`{"test":true}`),
		},
		CSR: csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

// On Azure SEV-SNP the launch measurement covers Azure's firmware layer, so a
// pin match there names no guest image. A measured-guest deployment refuses it;
// --admit-azure-snp, for test clusters on provider CVMs, takes it.
func TestAttestPlatformAdmissionDecidesAzureSEVSNP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		platforms platformAdmission
		status    int
	}{
		{"guest measured only", guestMeasuredOnly{}, http.StatusForbidden},
		{"azure snp admitted", alsoAzureSNP{}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, testLaunchDigest)
			h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
			h.Platforms = tc.platforms
			csrPEM, _ := generateCSR(t)
			w := postAttestFrom(t, h, teetypes.PlatformAzSNP, issueChallenge(t, h), csrPEM)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

// Bare-metal SEV-SNP and TDX measure the guest, so a measured-guest deployment
// admits them.
func TestAttestAdmitsMeasuredGuests(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
	csrPEM, _ := generateCSR(t)
	if w := postAttestFrom(t, h, teetypes.PlatformSNP, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// Platform admission and the pin set are both configuration, so /attest is
// never served without them: the router refuses to be built rather than
// deciding this per request.
func TestNewRouterRequiresACompleteIssuancePolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler AttestHandler
	}{
		{"no platforms", AttestHandler{Pins: pinsForDigests(t, testLaunchDigest)}},
		{"no pins", AttestHandler{Platforms: guestMeasuredOnly{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("router served /attest without a complete issuance policy")
				}
			}()
			newRouter(dependencies{
				AttestHandler:    tc.handler,
				RateLimiter:      newTestRateLimiter(t),
				ChallengeLimiter: newTestRateLimiter(t),
				MaxRequestSize:   65536,
			})
		})
	}
}

// Claims are selected by the verified platform, so admission judges what the
// verifier attested rather than the tag the requester submitted.
func TestAdmitGuestJudgesTheVerifiedPlatform(t *testing.T) {
	h := newPinnedAttestHandler(t, "http://attestation.test", pinsForDigests(t, testLaunchDigest))
	resp := remote.VerifyResponse{Result: teetypes.VerificationResult{
		Platform: teetypes.PlatformAzSNP,
		Claims:   teetypes.Claims{LaunchDigest: testLaunchDigest},
	}}
	claimed := teetypes.AttestationEvidence{Platform: teetypes.PlatformSNP}
	if err := h.admitGuest(resp, claimed); err == nil {
		t.Fatal("admitted a guest the verifier attested as Azure SEV-SNP")
	}
}

// The acceptance policy is asked for per call, so the verdict CDS reads has
// already answered the debug question. A verifier that ignored an absent
// allow_debug would otherwise decide it.
func TestAttestRequestsStrictEvidenceAcceptance(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newPinnedAttestHandler(t, stub.URL(), pinsForDigests(t, testLaunchDigest))
	csrPEM, _ := generateCSR(t)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	requests := stub.VerifyRequests()
	if len(requests) != 1 {
		t.Fatalf("verify requests = %d, want 1", len(requests))
	}
	params := requests[0].Params
	if params == nil {
		t.Fatal("verification was requested with no params at all")
	}
	if params.AllowDebug == nil || *params.AllowDebug {
		t.Errorf("allow_debug = %v, want an explicit false", params.AllowDebug)
	}
	if len(params.ExpectedReportData) == 0 {
		t.Error("expected_report_data is empty, so the key binding was not asked for")
	}
	if params.MinTcb != nil {
		t.Errorf("min_tcb = %v, want the policy's own (unset) value", params.MinTcb)
	}
}
