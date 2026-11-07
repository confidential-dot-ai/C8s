package cds

import (
	"bytes"
	"crypto/sha256"
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
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func podTestClaims(t *testing.T, digests ...string) workloadclaims.PodClaims {
	t.Helper()
	env, err := allowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := workloadclaims.PodClaims{Version: 1, BootID: strings.Repeat("b", 64), AssignedPodUID: "assigned", RuntimePodUID: "runtime", SandboxID: "sandbox", Revision: 1, RuntimeExtensions: digests}
	for _, d := range digests {
		p.Containers = append(p.Containers, workloadclaims.SandboxContainer{Digest: d, Argv: []string{"/app"}, Env: env, Mounts: []allowlist.ObservedMount{}})
	}
	return p
}

const podTestAnchor = "test-only-launch-anchor"

// podTestVerdict is a passing verdict whose RTMR[3] replays p's journal.
func podTestVerdict(t *testing.T, p workloadclaims.PodClaims) mockapi.Verdict {
	t.Helper()
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed([]byte(podTestAnchor)), p.RuntimeExtensions)
	v := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
	v.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
	return v
}

func podTestHandler(t *testing.T, p workloadclaims.PodClaims) (AttestHandler, *mockapi.Stub) {
	t.Helper()
	anchor := []byte(podTestAnchor)
	stub := mockapi.New(t)
	stub.SetVerdict(podTestVerdict(t, p))
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
// identity and the unique workload match; no node inventory is recorded and
// the spent challenge refuses a replay.
func TestPodAttestIssuesBoundNamedLeafWithoutNodeAuthority(t *testing.T) {
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
	if err != nil || stamp == nil || stamp.Name != "api" {
		t.Fatalf("missing whole-workload stamp: %v %v", stamp, err)
	}
	if len(binder.calls) != 0 {
		t.Fatal("Pod profile gained node callback ledger authority")
	}
	csr, err := certutil.ParseCSRPEM([]byte(req.CSR))
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
			h.Images = h.PodImages
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

// Every condition that makes a request carrying pod claims something other
// than a Pod attestation: refused as a denied CSR, with the cause in the log.
func TestPodAttestProfileRefusesEachConfusion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*AttestHandler, *types.AttestRequestBody)
		reason string
	}{
		{
			name:   "claims that do not decode",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) { r.PodClaims = json.RawMessage(`{"version":1}`) },
			reason: "pod claims:",
		},
		{
			name:   "sandbox token beside the claims",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) { r.SandboxToken = json.RawMessage(`{}`) },
			reason: "a sandbox token accompanies the pod claims",
		},
		{
			name:   "node runtime log beside the claims",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) { r.RuntimeExtensions = []string{wlDigestA} },
			reason: "runtime_extensions accompany the pod claims",
		},
		{
			name:   "evidence from another platform",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) { r.Evidence.Platform = "snp" },
			reason: "evidence is not from TDX",
		},
		{
			name:   "no pod image policy",
			change: func(h *AttestHandler, _ *types.AttestRequestBody) { h.PodImages = nil },
			reason: "no pod image policy is configured",
		},
		{
			name: "CSR carrying extensions",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) {
				r.CSR, _ = generateCSRWith(t, pkix.Name{}, []string{"pod.mesh.svc"}, nil)
			},
			reason: "the CSR carries extensions",
		},
		{
			name:   "CSR carrying a subject",
			change: func(_ *AttestHandler, r *types.AttestRequestBody) { r.CSR, _ = generateCSR(t) },
			reason: "the CSR carries a subject",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := podTestClaims(t, wlDigestA)
			h, _ := podTestHandler(t, p)
			req := podRequest(t, h, p)
			tc.change(&h, &req)

			logs := captureSlog(t)
			wantRefusal(t, postPodRequest(t, h, req), http.StatusForbidden, types.ErrorCodeCSRDenied)
			record := logRecord(t, logs, "Pod attestation profile refused")
			if got, _ := record["reason"].(string); !strings.Contains(got, tc.reason) {
				t.Fatalf("refusal reason = %#v, want one naming %q", record["reason"], tc.reason)
			}
		})
	}
}

// Claims no quote binds get no leaf. The challenge store mints only 32-byte
// challenges, so a challenge the claims binding cannot use (the binding needs
// 32 bytes) is refused as unissued before anything is verified; under an
// issued challenge, a quote bound to other claims fails the report-data check.
func TestPodAttestRefusesClaimsThatDoNotBind(t *testing.T) {
	t.Run("a challenge the binding cannot use", func(t *testing.T) {
		p := podTestClaims(t, wlDigestA)
		h, stub := podTestHandler(t, p)
		req := podRequest(t, h, p)
		req.Challenge = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))

		w := postPodRequest(t, h, req)
		wantRefusal(t, w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
		if got := len(stub.VerifyRequests()); got != 0 {
			t.Fatalf("/verify called %d times, want 0", got)
		}
	})
	t.Run("a quote bound to other claims", func(t *testing.T) {
		p := podTestClaims(t, wlDigestA)
		h, stub := podTestHandler(t, p)
		quoted := podRequest(t, h, p)
		sent := p
		other := sha256.Sum256([]byte("claims the quote does not bind"))
		sent.ClientDocumentDigest = hex.EncodeToString(other[:])
		req := quoted
		req.PodClaims, _ = sent.Canonical()
		csr, err := certutil.ParseCSRPEM([]byte(req.CSR))
		if err != nil {
			t.Fatal(err)
		}
		nonce, _ := base64.StdEncoding.DecodeString(req.Challenge)
		if len(nonce) != 32 {
			t.Fatalf("issued challenge is %d bytes, want 32", len(nonce))
		}
		expected, err := workloadclaims.PodReportData(csr.PublicKey, nonce, req.PodClaims)
		if err != nil {
			t.Fatal(err)
		}
		inQuote, err := workloadclaims.PodReportData(csr.PublicKey, nonce, quoted.PodClaims)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(expected, inQuote) {
			t.Fatal("the claims are not bound into the report data")
		}
		v := podTestVerdict(t, p)
		v.ReportDataMatch = teetypes.Ptr(false)
		stub.SetVerdict(v)

		w := postPodRequest(t, h, req)
		wantRefusal(t, w, http.StatusUnauthorized, types.ErrorCodeVerificationFailed)
		requests := stub.VerifyRequests()
		if len(requests) != 1 || requests[0].Params == nil || !bytes.Equal(requests[0].Params.ExpectedReportData, expected) {
			t.Fatal("the verifier was not held to the report data of the claims sent")
		}
	})
}

// A pod whose launch measurement is outside PodImages is refused on its
// measurement, whatever its claims say.
func TestPodAttestRefusesUnpinnedPodImage(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, stub := podTestHandler(t, p)
	unpinned := podTestVerdict(t, p)
	unpinned.Claims.LaunchDigest = strings.Repeat("cd", 48)
	stub.SetVerdict(unpinned)

	wantRefusal(t, postPodRequest(t, h, podRequest(t, h, p)), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// The leaf's client document is audit-relevant, so the issuance record names
// the digest the quote bound.
func TestPodAttestRecordsTheClientDocumentDigest(t *testing.T) {
	document := sha256.Sum256([]byte("client document"))
	p := podTestClaims(t, wlDigestA)
	p.ClientDocumentDigest = hex.EncodeToString(document[:])
	h, _ := podTestHandler(t, p)

	logs := captureSlog(t)
	if w := postPodRequest(t, h, podRequest(t, h, p)); w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	record := logRecord(t, logs, issuanceRecordMsg)
	if got := record["client_document_digest"]; got != p.ClientDocumentDigest {
		t.Fatalf("issuance record client_document_digest = %#v, want %q", got, p.ClientDocumentDigest)
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

// The leaf names the client document the claims carry, and only that one: a
// requester that swaps the digest after the guest quoted its claims fails the
// report-data binding, so CDS issues nothing.
func TestPodAttestStampsOnlyTheQuotedClientDocument(t *testing.T) {
	document := sha256.Sum256([]byte("client document"))
	p := podTestClaims(t, wlDigestA)
	p.ClientDocumentDigest = hex.EncodeToString(document[:])
	h, stub := podTestHandler(t, p)
	req := podRequest(t, h, p)
	w := postPodRequest(t, h, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if got, ok := armtls.ClientDocumentDigest(leafFromAttestResponse(t, w)); !ok || !bytes.Equal(got, document[:]) {
		t.Fatalf("leaf client document digest = %x %v", got, ok)
	}

	// The guest quoted the claims with the true digest; the request carries
	// another. The verifier answers as the hardware does: the report data
	// CDS expects is not the one in the quote.
	quoted := podRequest(t, h, p)
	tampered := p
	other := sha256.Sum256([]byte("another client document"))
	tampered.ClientDocumentDigest = hex.EncodeToString(other[:])
	forged := quoted
	forged.PodClaims, _ = tampered.Canonical()
	csr, err := certutil.ParseCSRPEM([]byte(quoted.CSR))
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(quoted.Challenge)
	inQuote, err := workloadclaims.PodReportData(csr.PublicKey, nonce, quoted.PodClaims)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := workloadclaims.PodReportData(csr.PublicKey, nonce, forged.PodClaims)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(inQuote, expected) {
		t.Fatal("the client document digest is not bound into the report data")
	}
	v := podTestVerdict(t, p)
	v.ReportDataMatch = teetypes.Ptr(false)
	stub.SetVerdict(v)
	if w := postPodRequest(t, h, forged); w.Code == http.StatusOK {
		t.Fatal("CDS issued for a client document digest the quote does not bind")
	}
}

// A Pod without a client document gets no client document digest.
func TestPodAttestStampsNoClientDocumentWithoutOne(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, p)
	w := postPodRequest(t, h, podRequest(t, h, p))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if _, ok := armtls.ClientDocumentDigest(leafFromAttestResponse(t, w)); ok {
		t.Fatal("leaf names a client document the Pod never had")
	}
}

// The leaf names a workload only when the pod's whole observation set matches
// exactly one entry; every other admitted pod gets the unnamed membership leaf.
func TestPodAttestNamesOnlyAUniqueWholeWorkloadMatch(t *testing.T) {
	strict := func(argv string) allowlist.Workload {
		return allowlist.Workload{Containers: []allowlist.Container{{Digest: wlDigest(t, wlDigestA),
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{argv}}, Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}}}}
	}
	for _, tc := range []struct {
		name    string
		digests []string
		store   fakeStore
		want    string
	}{
		{"exact single match", []string{wlDigestA}, fakeStore{workloads: map[string]allowlist.Workload{"api": strict("/app")}}, "api"},
		{"no entry admits the argv", []string{wlDigestA}, fakeStore{workloads: map[string]allowlist.Workload{"api": strict("/other")}}, ""},
		{"two entries match", []string{wlDigestA}, fakeStore{workloads: map[string]allowlist.Workload{"api": strict("/app"), "api-copy": strict("/app")}}, ""},
		{"an extra image the entry does not list", []string{wlDigestA, wlDigestC}, completeAPIStore(t), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := podTestClaims(t, tc.digests...)
			h, _ := podTestHandler(t, p)
			h.AllowlistStore = tc.store
			w := postPodRequest(t, h, podRequest(t, h, p))
			if w.Code != http.StatusOK {
				t.Fatalf("admitted pod refused: %d %s", w.Code, w.Body.String())
			}
			stamp, err := armtls.MatchedWorkloadFromCert(leafFromAttestResponse(t, w))
			if err != nil {
				t.Fatal(err)
			}
			name := ""
			if stamp != nil {
				name = stamp.Name
			}
			if name != tc.want {
				t.Fatalf("leaf names %q, want %q", name, tc.want)
			}
		})
	}
}

// The measured mesh endpoint is the platform's: a pod running only it gets
// membership without a workload name.
func TestPodAttestMeshOnlyIsMembershipOnly(t *testing.T) {
	p := podTestClaims(t, wlDigestC)
	p.Containers[0].Role = workloadclaims.MeshRole
	h, _ := podTestHandler(t, p)
	w := postPodRequest(t, h, podRequest(t, h, p))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if stamp, err := armtls.MatchedWorkloadFromCert(leafFromAttestResponse(t, w)); err != nil || stamp != nil {
		t.Fatalf("mesh-only pod acquired a named identity: %v %v", stamp, err)
	}
}
