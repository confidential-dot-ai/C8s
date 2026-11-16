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
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testMRTD  = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	testRTMR1 = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	testRTMR2 = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
	nextRTMR1 = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
	nextRTMR2 = "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
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

// tdxImagePin is one node image's TDX tuple: the firmware measurement with the
// kernel and command-line registers measured from the same build.
func tdxImagePin(t *testing.T, name, mrtd, rtmr1, rtmr2 string) remote.ImagePin {
	t.Helper()
	return remote.ImagePin{
		Name:   name,
		Digest: mustDecode(t, mrtd),
		Registers: map[int][]byte{
			1: mustDecode(t, rtmr1),
			2: mustDecode(t, rtmr2),
		},
	}
}

func mustDecode(t *testing.T, hexVal string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The TDX lane's positive case: the node image's firmware measurement and both
// of its registers matching the report.
func TestAttestTDXWithMatchingRegistersIssues(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, testRTMR1, testRTMR2))

	h := newTestAttestHandler(t, stub.URL(), []remote.ImagePin{tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2)})

	csrPEM, _ := generateCSR(t)
	w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// The exact TDX-MRTD-ONLY attack shape: same TDVF (matching MRTD), different
// guest kernel (RTMR[1] differs). Must be refused, not issued.
func TestAttestTDXMatchingMRTDButWrongRegisterIsRefused(t *testing.T) {
	otherKernel := strings.Repeat("ab", 48)
	stub := mockapi.New(t)
	stub.SetVerdict(tdxVerdict(t, testMRTD, otherKernel, testRTMR2))

	h := newTestAttestHandler(t, stub.URL(), []remote.ImagePin{tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2)})

	csrPEM, _ := generateCSR(t)
	wantRefusal(t, postAttestTDX(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// A pinned register the verdict does not report is a refusal, not a pass — a
// verifier that stopped reporting registers must not silently unpin them.
func TestAttestTDXPinnedRegisterNotReportedIsRefused(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(testMRTD)) // no platform_data at all

	h := newTestAttestHandler(t, stub.URL(), []remote.ImagePin{tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2)})

	csrPEM, _ := generateCSR(t)
	wantRefusal(t, postAttestTDX(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// A node-image upgrade pins the old and the new image at once. They share the
// TDVF firmware, so each is admitted on its own registers and no caller is
// admitted on one image's kernel paired with the other's command line.
func TestAttestTDXMatchesEachNodeImageWithItsOwnRegisters(t *testing.T) {
	stub := mockapi.New(t)
	h := newTestAttestHandler(t, stub.URL(), []remote.ImagePin{
		tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2),
		tdxImagePin(t, "node-next", testMRTD, nextRTMR1, nextRTMR2),
	})

	for _, tc := range []struct {
		name       string
		rtmr1      string
		rtmr2      string
		wantIssued bool
	}{
		{"both registers of the image being replaced", testRTMR1, testRTMR2, true},
		{"both registers of the image being rolled out", nextRTMR1, nextRTMR2, true},
		{"one image's kernel with the other's command line", testRTMR1, nextRTMR2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub.SetVerdict(tdxVerdict(t, testMRTD, tc.rtmr1, tc.rtmr2))
			csrPEM, _ := generateCSR(t)
			w := postAttestTDX(t, h, issueChallenge(t, h), csrPEM)
			if issued := w.Code == http.StatusOK; issued != tc.wantIssued {
				t.Fatalf("issued = %v, want %v; status %d, body=%s", issued, tc.wantIssued, w.Code, w.Body.String())
			}
		})
	}
}

// Registers are a TDX claim, so a caller submitting SNP evidence against a TDX
// node image is refused rather than admitted on its launch digest alone.
func TestAttestSNPEvidenceAgainstTDXImageIsRefused(t *testing.T) {
	stub := newStubAttestationApi(t, testMRTD)

	h := newTestAttestHandler(t, stub.URL(), []remote.ImagePin{tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2)})

	csrPEM, _ := generateCSR(t)
	wantRefusal(t, postAttest(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}
