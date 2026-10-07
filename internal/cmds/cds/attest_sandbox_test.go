package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

// testInventoryHost is the callback host the signer stamps into tokens. The
// tests answer it with fakeDigests rather than dialing.
const testInventoryHost = "10.0.0.7"

// fakeDigests answers the inventory callback from a sandbox -> digests map. A
// missing sandbox is workloadclaims.ErrSandboxUnknown, like a 404 on the wire.
// containers, when set for a sandbox, is the per-container (digest, argv) view;
// when unset, the response carries only the digests view — the shape of an
// inventory that predates argv reporting.
type fakeDigests struct {
	digests    map[string][]string
	containers map[string][]workloadclaims.SandboxContainer
	key        *ecdsa.PublicKey
}

func (f fakeDigests) InventoryKey(_ context.Context, host string) (*ecdsa.PublicKey, error) {
	if host != testInventoryHost {
		return nil, fmt.Errorf("unexpected inventory host %q", host)
	}
	if f.key == nil {
		return nil, fmt.Errorf("no inventory at %s", host)
	}
	return f.key, nil
}

func (f fakeDigests) FetchSandbox(_ context.Context, host, sandboxID string) (workloadclaims.SandboxDigestsResponse, error) {
	if host != testInventoryHost {
		return workloadclaims.SandboxDigestsResponse{}, fmt.Errorf("unexpected inventory host %q", host)
	}
	d, ok := f.digests[sandboxID]
	if !ok {
		return workloadclaims.SandboxDigestsResponse{}, workloadclaims.ErrSandboxUnknown
	}
	return workloadclaims.SandboxDigestsResponse{
		Digests:    d,
		Containers: f.containers[sandboxID],
	}, nil
}

// newSandboxTestEnv wires an AttestHandler that resolves an inventory key the
// way production does — from the inventory's own endpoint — and returns the
// signer holding that key.
func newSandboxTestEnv(t *testing.T, stubURL string) (AttestHandler, *workloadclaims.SandboxTokenSigner) {
	t.Helper()
	h := newTestAttestHandler(t, stubURL, nil)

	signer, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	// A token triggers the digests callback, so every sandbox test needs an
	// inventory to answer, an allowlist admitting what it reports, and node
	// CIDRs the callback host falls inside.
	h.AllowlistStore = anyArgvStore(wlDigestA)
	h.SandboxDigests = fakeDigests{
		digests: map[string][]string{testSandboxID: {wlDigestA}},
		key:     signer.PublicKey(),
	}
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.InventoryHosts = hosts
	return h, signer
}

// signedSandboxToken issues an inventory token for sandboxID and the CSR key
// behind csrPEM, bound to the same base64 challenge the request will carry
// (CDS re-checks the token nonce against the challenge it consumes).
func signedSandboxToken(t *testing.T, signer *workloadclaims.SandboxTokenSigner, csrPEM, challenge, sandboxID string) json.RawMessage {
	t.Helper()
	csr, err := attestation.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := workloadclaims.RequesterKeyDigest(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(sandboxID, keyDigest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postAttestSandbox(t *testing.T, h AttestHandler, challenge, csrPEM string, token json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge:    challenge,
		Evidence:     teetypes.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:          csrPEM,
		SandboxToken: token,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

// A valid inventory token gets its sandbox ID stamped into the signed leaf.
func TestAttest_SandboxToken_StampedOnLeaf(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	got, err := armtls.SandboxIDFromCert(leafFromAttestResponse(t, w))
	if err != nil {
		t.Fatalf("SandboxIDFromCert: %v", err)
	}
	if got != testSandboxID {
		t.Fatalf("leaf sandbox = %q, want %q", got, testSandboxID)
	}
}

// No token ⇒ no extension (the pre-sandbox flow is unchanged).
func TestAttest_SandboxToken_AbsentWhenNotRequested(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	if got, err := armtls.SandboxIDFromCert(leafFromAttestResponse(t, w)); err != nil || got != "" {
		t.Fatalf("leaf sandbox = %q, %v; want empty", got, err)
	}
}

// A token bound to a different key than the CSR's must be rejected: only the
// get-cert holding the bound key may redeem the token.
func TestAttest_SandboxToken_RejectsWrongRequesterKey(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	victimCSR, _ := generateCSR(t)
	attackerCSR, _ := generateCSR(t)

	// Token issued for the victim's key, replayed with the attacker's CSR.
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, attackerCSR, signedSandboxToken(t, signer, victimCSR, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A token signed by a key other than the inventory key CDS resolves must be
// rejected: the token must come from the attested inventory.
func TestAttest_SandboxToken_RejectsForeignInventoryEAR(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, stub.URL())
	// A second environment with a signing key the handler does not trust.
	_, foreignSigner := newSandboxTestEnv(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, foreignSigner, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// The core of the design: a token signed by a key the inventory does not hold
// is rejected. This is what stops a compromised workload — which shares the
// node's launch measurement and can reach CDS — from minting a token naming
// another pod's sandbox. CDS resolves the key from the inventory's own
// privileged-port endpoint, so the impostor's own key never matches.
func TestAttest_SandboxToken_RejectsKeyTheInventoryDoesNotHold(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, stub.URL())

	// An attacker signs its own token for someone else's sandbox.
	impostor, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, impostor, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A token naming a host outside the operator's node CIDRs is refused before
// anything is dialed — that boundary is what stops a workload pointing the
// callback at its own pod IP and answering as its node's inventory.
func TestAttest_SandboxToken_RejectsHostOutsideNodeCIDRs(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"192.168.99.0/24"}) // not testInventoryHost
	if err != nil {
		t.Fatal(err)
	}
	h.InventoryHosts = hosts

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// With no CIDRs configured CDS has no boundary to apply, so it refuses tokens
// outright rather than dialing wherever it is pointed.
func TestAttest_SandboxToken_RejectsWithoutConfiguredCIDRs(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.InventoryHosts = nil

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// The freshness guarantee: a validly-signed token whose nonce is some other
// challenge — not the one this request consumes — is rejected, so a captured or
// pre-signed token cannot be replayed against a fresh challenge.
func TestAttest_SandboxToken_RejectsStaleNonce(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	csrPEM, _ := generateCSR(t)

	// Token is bound to a different challenge than the request carries.
	staleChallenge := base64.StdEncoding.EncodeToString([]byte("a-different-challenge"))
	w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, signedSandboxToken(t, signer, csrPEM, staleChallenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A CDS without an inventory resolver cannot verify sandbox tokens and must
// reject a request that carries one rather than stamp it unverified.
func TestAttest_SandboxToken_RejectsWhenUnverifiable(t *testing.T) {
	stub := newStubAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, stub.URL())
	h.SandboxDigests = nil
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A malformed token envelope, and one whose signed bytes are not a token, are
// both refused before any callback is attempted.
func TestAttest_SandboxToken_RejectsMalformedEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token json.RawMessage
	}{
		{"wrong JSON shape", json.RawMessage(`[]`)},
		{"unknown field", json.RawMessage(`{"token":"AA==","signature":"AA==","ear":"x"}`)},
		{"token bytes are not DER", json.RawMessage(`{"token":"bm90LWRlcg==","signature":"AA=="}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, "deadbeef")
			h, _ := newSandboxTestEnv(t, stub.URL())
			csrPEM, _ := generateCSR(t)
			w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, tc.token)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

// A token carrying an ID ValidateSandboxID rejects is refused at token
// verification — before the evidence round-trip and before any ledger write —
// so a garbage ID can never be bound to an inventory or stamped on a leaf.
// (A non-IA5 ID like "sandbox-🙂" is unrepresentable: the token's IA5String
// marshal refuses it. ValidateSandboxID's own test pins that case.)
func TestAttest_SandboxToken_RejectsMalformedSandboxID(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"path traversal", "../../etc"},
		{"embedded slash", "a/b"},
		{"embedded space", "sandbox id"},
		{"over 128 chars", strings.Repeat("a", 129)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, "deadbeef")
			h, signer := newSandboxTestEnv(t, stub.URL())
			// The inventory answers for the malformed ID, so the ID check is
			// the only thing between this token and issuance.
			h.SandboxDigests = fakeDigests{
				digests: map[string][]string{tc.id: {wlDigestA}},
				key:     signer.PublicKey(),
			}
			binder := &recordingBinder{}
			h.SandboxBindings = binder
			csrPEM, _ := generateCSR(t)

			challenge := issueChallenge(t, h)
			w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, tc.id))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
			}
			if len(binder.calls) != 0 {
				t.Fatalf("Record called %d times for a rejected sandbox ID, want 0", len(binder.calls))
			}
			if got := len(stub.VerifyRequests()); got != 0 {
				t.Fatalf("/verify called %d times for a rejected sandbox ID, want 0", got)
			}
		})
	}
}
