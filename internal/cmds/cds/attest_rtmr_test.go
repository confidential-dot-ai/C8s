package cds

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testMRTD  = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	testRTMR1 = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	testRTMR2 = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
)

// tdxVerdict is a passing verdict whose claims carry the TDX register set the
// attestation-api reports in platform_data.
func tdxVerdict(t *testing.T, mrtd, rtmr1, rtmr2 string) mockapi.Verdict {
	t.Helper()
	v := mockapi.PassingVerdict(mrtd)
	v.Claims.PlatformData = map[string]any{
		"rtmr_0": strings.Repeat("00", 48),
		"rtmr_1": rtmr1,
		"rtmr_2": rtmr2,
		"rtmr_3": strings.Repeat("33", 48),
	}
	return v
}

func postAttestTDX(t *testing.T, h AttestHandler, challenge, csrPEM string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: challenge,
		Evidence:  teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"abc"}`)},
		CSR:       csrPEM,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

func rtmrPin(t *testing.T, idx int, hexVal string) map[int][]byte {
	t.Helper()
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		t.Fatal(err)
	}
	return map[int][]byte{idx: b}
}

func mustDecode(t *testing.T, hexVal string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The TDX lane's positive case: MRTD allowlisted and both pinned registers
// matching the report.
func TestAttestTDXWithMatchingRTMRsIssues(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, testRTMR1, testRTMR2))

	pins := pinsForDigests(t, testMRTD)
	pins.Registers = map[int][]byte{1: mustDecode(t, testRTMR1), 2: mustDecode(t, testRTMR2)}
	h := newPinnedAttestHandler(t, stub.URL(), pins)

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// The exact TDX-MRTD-ONLY attack shape: same TDVF (matching MRTD), different
// guest kernel (RTMR[1] differs). Must be refused, not issued.
func TestAttestTDXMatchingMRTDButWrongRTMRIsRefused(t *testing.T) {
	otherKernel := strings.Repeat("ab", 48)
	stub := mockapi.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, otherKernel, testRTMR2))

	pins := pinsForDigests(t, testMRTD)
	pins.Registers = rtmrPin(t, 1, testRTMR1)
	h := newPinnedAttestHandler(t, stub.URL(), pins)

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var envelope types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if envelope.Error != types.ErrorCodeMeasurementDenied {
		t.Fatalf("error code = %q, want %q", envelope.Error, types.ErrorCodeMeasurementDenied)
	}
}

// A pinned register the verdict does not report is a refusal, not a pass — a
// verifier that stopped reporting registers must not silently unpin them.
func TestAttestTDXPinnedRTMRNotReportedIsRefused(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(testMRTD)) // no platform_data at all

	pins := pinsForDigests(t, testMRTD)
	pins.Registers = rtmrPin(t, 1, testRTMR1)
	h := newPinnedAttestHandler(t, stub.URL(), pins)

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// SNP evidence carries no registers, so a register pin asks for a check it
// cannot answer. Issuing on the launch digest alone would report a pin as
// enforced that nothing enforced, so the request is refused.
func TestAttestSNPWithRTMRPinsIsRefused(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)

	pins := pinsForDigests(t, testLaunchDigest)
	pins.Registers = rtmrPin(t, 1, testRTMR1)
	h := newPinnedAttestHandler(t, stub.URL(), pins)

	csrPEM, _ := generateCSR(t)
	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
