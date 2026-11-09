package cds

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func podTestClaims(t *testing.T, digests ...string) workloadclaims.PodClaims {
	t.Helper()
	p := workloadclaims.PodClaims{Version: 1, BootID: strings.Repeat("b", 64), AssignedPodUID: "assigned", RuntimePodUID: "runtime", SandboxID: "sandbox", Revision: 1, RuntimeExtensions: digests}
	for _, d := range digests {
		p.Containers = append(p.Containers, workloadclaims.PodContainer{Digest: d})
	}
	return p
}

func podTestHandler(t *testing.T, p workloadclaims.PodClaims) (AttestHandler, *mockapi.Stub) {
	t.Helper()
	anchor := []byte("test-only-launch-anchor")
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), p.RuntimeExtensions)
	v := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
	v.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
	stub := mockapi.New(t)
	stub.SetVerdict(v)
	h := newTestAttestHandler(t, stub.URL(), nil)
	h.PodImages = []remote.ImagePin{{Digest: mustDecode(t, testMRTD), Registers: map[int][]byte{1: mustDecode(t, testRTMR1), 2: mustDecode(t, testRTMR2)}, Anchor: anchor}}
	h.AllowlistStore = completeAPIStore(t)
	return h, stub
}

func postPodRequest(t *testing.T, h AttestHandler, req types.AttestRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.HandleAttest(w, httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(raw)))
	return w
}

func podRequest(t *testing.T, h AttestHandler, p workloadclaims.PodClaims) types.AttestRequestBody {
	t.Helper()
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := generateCSRWith(t, pkix.Name{}, nil, nil)
	return types.AttestRequestBody{Challenge: issueChallenge(t, h), CSR: csr, PodClaims: raw, Evidence: teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"fake"}`)}}
}

// The verifier binds key, challenge and claims; the leaf carries the instance
// identity and no matched-workload stamp, since the claims carry image digests
// only; no node inventory is recorded and the spent challenge refuses a replay.
func TestPodAttestIssuesBoundMembershipLeafWithoutNodeAuthority(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, stub := podTestHandler(t, p)
	binder := &recordingBinder{}
	h.SandboxBindings = binder
	req := podRequest(t, h, p)
	w := postPodRequest(t, h, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	instance, err := armtls.SandboxIDFromCert(leaf)
	if err != nil || instance != p.InstanceID() {
		t.Fatalf("wrong instance %q %v", instance, err)
	}
	stamp, err := armtls.MatchedWorkloadFromCert(leaf)
	if err != nil || stamp != nil {
		t.Fatalf("pod CVM acquired a named identity: %v %v", stamp, err)
	}
	if len(binder.calls) != 0 {
		t.Fatal("Pod profile gained node callback ledger authority")
	}
	csr, err := attestation.ParseAndVerifyCSR(req.CSR)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(req.Challenge)
	want, err := workloadclaims.PodReportData(csr.PublicKey, nonce, req.PodClaims)
	if err != nil {
		t.Fatal(err)
	}
	requests := stub.VerifyRequests()
	if len(requests) != 1 || !bytes.Equal(requests[0].Params.ExpectedReportData, want) {
		t.Fatal("verifier did not bind complete snapshot")
	}
	wantRefusal(t, postPodRequest(t, h, req), http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
}

// One row per refused condition of the Pod profile.
func TestPodAttestRejectsAuthorityAndMeasurementConfusion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*AttestHandler, *types.AttestRequestBody)
	}{
		{"node pins are not Pod pins", func(h *AttestHandler, r *types.AttestRequestBody) {
			h.NodeImages = certifying(h.PodImages...)
			h.PodImages = nil
		}},
		{"mixed token", func(h *AttestHandler, r *types.AttestRequestBody) { r.SandboxToken = json.RawMessage(`{}`) }},
		{"null claims", func(h *AttestHandler, r *types.AttestRequestBody) { r.PodClaims = json.RawMessage(`null`) }},
		{"SNP", func(h *AttestHandler, r *types.AttestRequestBody) { r.Evidence.Platform = "snp" }},
		{"node subject", func(h *AttestHandler, r *types.AttestRequestBody) { r.CSR, _ = generateCSR(t) }},
		{"SAN profile", func(h *AttestHandler, r *types.AttestRequestBody) {
			r.CSR, _ = generateCSRWith(t, pkix.Name{}, []string{"node.example"}, nil)
		}},
		{"wrong launch key", func(h *AttestHandler, r *types.AttestRequestBody) { h.PodImages[0].Anchor = []byte("wrong") }},
		{"wrong kernel", func(h *AttestHandler, r *types.AttestRequestBody) {
			h.PodImages[0].Registers[1] = bytes.Repeat([]byte{7}, 48)
		}},
		{"no allowlist", func(h *AttestHandler, r *types.AttestRequestBody) { h.AllowlistStore = nil }},
		{"foreign image", func(h *AttestHandler, r *types.AttestRequestBody) { h.AllowlistStore = anyArgvStore(wlDigestB) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := podTestClaims(t, wlDigestA)
			h, _ := podTestHandler(t, p)
			req := podRequest(t, h, p)
			tc.change(&h, &req)
			if w := postPodRequest(t, h, req); w.Code == http.StatusOK {
				t.Fatal("unauthorized profile issued")
			}
		})
	}
}

// An inconsistent complete replay is measurement_denied.
func TestPodAttestRequiresExactJournalNotPrefix(t *testing.T) {
	// Snapshot claims A+B while the quote proves only A. Generic node pinning
	// intentionally accepts such a journal prefix; the Pod profile must not.
	measured := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, measured)
	claimed := podTestClaims(t, wlDigestA, wlDigestC)
	wantRefusal(t, postPodRequest(t, h, podRequest(t, h, claimed)), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// A Pod profile combined with a node runtime log, even a null one, is refused.
func TestPodAttestRejectsExplicitNullNodeLog(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, p)
	req := podRequest(t, h, p)
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"runtime_extensions":null}`)...)
	w := httptest.NewRecorder()
	h.HandleAttest(w, httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(raw)))
	wantRefusal(t, w, http.StatusForbidden, types.ErrorCodeCSRDenied)
}
