package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/nodetoken"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testNodeTokenAudience = "cl-1.k8s.example.test"

func newTestNodeTokenHandler(t *testing.T, stubURL string) NodeTokenHandler {
	t.Helper()
	tokens, err := nodetoken.New(nodetoken.Config{
		URL:       "https://cds.cl-1.example.test",
		Audiences: []string{testNodeTokenAudience},
		Cluster:   "cl-1",
		TTL:       nodetoken.MaxTTL,
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return NodeTokenHandler{Attest: newTestAttestHandler(t, stubURL, nil), Issuer: tokens}
}

func nodeKeyB64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func postNodeToken(t *testing.T, h NodeTokenHandler, req types.NodeTokenRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	if req.Evidence.Platform == "" {
		req.Evidence = teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)}
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.HandleNodeToken(w, httptest.NewRequest(http.MethodPost, "/node-token", bytes.NewReader(body)))
	return w
}

func TestNodeToken_MintsForAttestedNodeKey(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h := newTestNodeTokenHandler(t, stub.URL())
	challenge := issueChallenge(t, h.Attest)
	_, key := generateCSR(t)

	w := postNodeToken(t, h, types.NodeTokenRequestBody{
		Challenge: challenge, NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var resp types.NodeTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(resp.ExpiresAt); d <= 0 || d > nodetoken.MaxTTL {
		t.Fatalf("expires in %s", d)
	}

	// The evidence was checked against this node key and challenge, so the
	// token's subject is a name only this key's holder could have attested.
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify called %d times, want 1", len(reqs))
	}
	raw, _ := base64.StdEncoding.DecodeString(challenge)
	want, err := armtls.ReportDataForKey(&key.PublicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reqs[0].Params.ExpectedReportData, want[:sha512.Size384]) {
		t.Fatal("expected_report_data is not SHA-384(node key || challenge)")
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(resp.Token, claims); err != nil {
		t.Fatal(err)
	}
	sub, _ := nodetoken.Subject(&key.PublicKey)
	if claims["sub"] != sub || claims["aud"] != testNodeTokenAudience || claims["launch_digest"] != "deadbeef" || claims["tee"] != "sev-snp" {
		t.Fatalf("claims %v", claims)
	}
}

func TestNodeToken_OtherAudienceRefusedWithoutSpendingChallenge(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h := newTestNodeTokenHandler(t, stub.URL())
	challenge := issueChallenge(t, h.Attest)
	_, key := generateCSR(t)

	wantRefusal(t, postNodeToken(t, h, types.NodeTokenRequestBody{
		Challenge: challenge, NodeKey: nodeKeyB64(t, key), Audience: "other.k8s.example.test",
	}), http.StatusForbidden, types.ErrorCodeInvalidRequest)
	if n := len(stub.VerifyRequests()); n != 0 {
		t.Fatalf("/verify called %d times for a refused audience", n)
	}
	if w := postNodeToken(t, h, types.NodeTokenRequestBody{
		Challenge: challenge, NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience,
	}); w.Code != http.StatusOK {
		t.Fatalf("challenge spent by the refused request: %d %s", w.Code, w.Body.String())
	}
}

func TestNodeToken_ChallengeIsSingleUse(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h := newTestNodeTokenHandler(t, stub.URL())
	challenge := issueChallenge(t, h.Attest)
	_, key := generateCSR(t)
	req := types.NodeTokenRequestBody{Challenge: challenge, NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience}

	if w := postNodeToken(t, h, req); w.Code != http.StatusOK {
		t.Fatalf("first: %d %s", w.Code, w.Body.String())
	}
	wantRefusal(t, postNodeToken(t, h, req), http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
}

func TestNodeToken_RefusesWhatAttestRefuses(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	verdict := mockapi.PassingVerdict("deadbeef")
	match := false
	verdict.ReportDataMatch = &match
	stub.SetVerdict(verdict)
	h := newTestNodeTokenHandler(t, stub.URL())
	_, key := generateCSR(t)

	wantRefusal(t, postNodeToken(t, h, types.NodeTokenRequestBody{
		Challenge: issueChallenge(t, h.Attest), NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience,
	}), http.StatusUnauthorized, types.ErrorCodeVerificationFailed)

	// A launch digest off the node pins is refused as /attest refuses it.
	pinned := newTestNodeTokenHandler(t, stub.URL())
	pinned.Attest.Measurements = map[string]bool{"approved-digest": true}
	stub.SetVerdict(mockapi.PassingVerdict("deadbeef"))
	if w := postNodeToken(t, pinned, types.NodeTokenRequestBody{
		Challenge: issueChallenge(t, pinned.Attest), NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience,
	}); w.Code == http.StatusOK {
		t.Fatal("minted for a launch digest outside the node pins")
	}
}

func TestNodeToken_RefusesBadRequests(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h := newTestNodeTokenHandler(t, stub.URL())
	_, key := generateCSR(t)

	cases := map[string]struct {
		body   string
		status int
	}{
		"unknown field":  {`{"challenge":"","node_key":"","audience":"","csr":"x"}`, http.StatusUnprocessableEntity},
		"key not base64": {`{"challenge":"","node_key":"!!","audience":"` + testNodeTokenAudience + `","evidence":{"platform":"snp","evidence":{}}}`, http.StatusBadRequest},
		"key not PKIX":   {`{"challenge":"","node_key":"` + base64.StdEncoding.EncodeToString([]byte("nope")) + `","audience":"` + testNodeTokenAudience + `","evidence":{"platform":"snp","evidence":{}}}`, http.StatusBadRequest},
		"bad challenge":  {`{"challenge":"AAAA","node_key":"` + nodeKeyB64(t, key) + `","audience":"` + testNodeTokenAudience + `","evidence":{"platform":"snp","evidence":{}}}`, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.HandleNodeToken(w, httptest.NewRequest(http.MethodPost, "/node-token", strings.NewReader(tc.body)))
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
	if n := len(stub.VerifyRequests()); n != 0 {
		t.Fatalf("/verify called %d times for malformed requests", n)
	}
}

func TestNewNodeTokenIssuer(t *testing.T) {
	if tokens, serving, err := newNodeTokenIssuer(config{}, false); tokens != nil || serving != nil || err != nil {
		t.Fatalf("off by default: got %v %v %v", tokens, serving, err)
	}
	cfg := config{
		nodeTokenIssuer:    "https://cds.cl-1.example.test",
		nodeTokenAudiences: []string{testNodeTokenAudience},
		nodeTokenCluster:   "cl-1",
		nodeTokenTTL:       nodetoken.MaxTTL,
	}
	if _, _, err := newNodeTokenIssuer(cfg, true); err == nil {
		t.Fatal("issuer started without armTLS in front of /node-token")
	}
	cfg.armtlsPlatform = "snp"
	if _, _, err := newNodeTokenIssuer(cfg, false); err == nil {
		t.Fatal("issuer started without node pins, so any attested TEE would get a node token")
	}
	tokens, serving, err := newNodeTokenIssuer(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !tokens.MintsFor(testNodeTokenAudience) || len(serving.CAPEM()) == 0 {
		t.Fatal("issuer not built from the flags")
	}
}

func TestNodeToken_TDXNeedsRTMRPinsWithoutImagePolicy(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h := newTestNodeTokenHandler(t, stub.URL())
	h.Attest.Measurements = map[string]bool{"deadbeef": true}
	_, key := generateCSR(t)
	challenge := issueChallenge(t, h.Attest)
	tdx := teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{"test":true}`)}

	// A TDX launch measurement pins only the firmware, so the request is
	// refused before the challenge is spent or the verifier called.
	wantRefusal(t, postNodeToken(t, h, types.NodeTokenRequestBody{
		Challenge: challenge, NodeKey: nodeKeyB64(t, key), Audience: testNodeTokenAudience, Evidence: tdx,
	}), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
	if n := len(stub.VerifyRequests()); n != 0 {
		t.Fatalf("/verify called %d times for a TDX node with no RTMR pins", n)
	}
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil || !h.Attest.Challenges.Consume(raw) {
		t.Fatal("challenge spent on a refused TDX request")
	}

	// SEV-SNP's launch measurement covers the whole image.
	if !h.pinsWholeImage("snp") {
		t.Fatal("SNP node refused with launch measurement pins")
	}
	h.Attest.RTMRs = map[int][]byte{1: make([]byte, 48)}
	if !h.pinsWholeImage("tdx") {
		t.Fatal("TDX node refused with RTMR pins")
	}
}

func TestValidateNodeTokenFlags(t *testing.T) {
	for _, name := range nodeTokenIssuerFlags {
		t.Run(name, func(t *testing.T) {
			cmd := NewCmd()
			value := "x"
			if name == "node-token-ttl" {
				value = "1m"
			}
			if err := cmd.Flags().Set(name, value); err != nil {
				t.Fatal(err)
			}
			if err := validateNodeTokenFlags(cmd.Flags(), config{}); err == nil {
				t.Fatalf("--%s accepted without --node-token-issuer", name)
			}
			if err := validateNodeTokenFlags(cmd.Flags(), config{nodeTokenIssuer: "https://cds.cl-1.example.test"}); err != nil {
				t.Fatalf("--%s refused with --node-token-issuer: %v", name, err)
			}
		})
	}
	if err := validateNodeTokenFlags(NewCmd().Flags(), config{}); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}
