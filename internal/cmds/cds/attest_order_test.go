package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// rsaCSRPEM is a well-formed CSR whose key is not ECDSA.
func rsaCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "rsa-node"}}, key)
	if err != nil {
		t.Fatalf("create rsa csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// A request refused on its CSR has spent its challenge: a corrected retry under
// the same challenge is refused on the challenge.
func TestAttest_RefusedCSRConsumesChallenge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		csrPEM string
	}{
		{"not a CSR", "not a pem"},
		{"non-ECDSA key", rsaCSRPEM(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, testLaunchDigest)
			h := newTestAttestHandler(t, stub.URL(), nil)
			challenge := issueChallenge(t, h)

			wantRefusal(t, postAttest(t, h, challenge, tc.csrPEM), http.StatusBadRequest, types.ErrorCodeInvalidCSR)

			csrPEM, _ := generateCSR(t)
			wantRefusal(t, postAttest(t, h, challenge, csrPEM), http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
		})
	}
}

// A request whose sandbox token is refused has spent its challenge.
func TestAttest_SandboxToken_RefusalConsumesChallenge(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h, signer := newSandboxTestEnv(t, stub.URL())
	csrPEM := sandboxCSR(t)
	challenge := issueChallenge(t, h)

	boundToAnotherKey := signedSandboxToken(t, signer, sandboxCSR(t), challenge, testSandboxID)
	wantRefusal(t, postAttestSandbox(t, h, challenge, csrPEM, boundToAnotherKey), http.StatusForbidden, types.ErrorCodeCSRDenied)

	valid := signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID)
	wantRefusal(t, postAttestSandbox(t, h, challenge, csrPEM, valid), http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
}

// A request refused as a Pod attestation has spent its challenge.
func TestPodAttestProfileRefusalConsumesChallenge(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, p)
	valid := podRequest(t, h, p)
	refused := valid
	refused.Evidence.Platform = "snp"

	wantRefusal(t, postPodRequest(t, h, refused), http.StatusForbidden, types.ErrorCodeCSRDenied)
	wantRefusal(t, postPodRequest(t, h, valid), http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
}

// countingDigests counts inventory key fetches, each of which dials the inventory.
type countingDigests struct {
	fakeDigests
	keyFetches *int
}

func (c countingDigests) InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error) {
	*c.keyFetches++
	return c.fakeDigests.InventoryKey(ctx, host)
}

// A request under a challenge CDS did not issue is refused before its sandbox
// token or its evidence is checked.
func TestAttest_UnissuedChallengeRefusedBeforeTokenAndEvidence(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h, signer := newSandboxTestEnv(t, stub.URL())
	keyFetches := 0
	h.SandboxDigests = countingDigests{
		fakeDigests: fakeDigests{key: signer.PublicKey()},
		keyFetches:  &keyFetches,
	}
	csrPEM := sandboxCSR(t)
	unissued := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	w := postAttestSandbox(t, h, unissued, csrPEM, signedSandboxToken(t, signer, csrPEM, unissued, testSandboxID))
	wantRefusal(t, w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge)
	if keyFetches != 0 {
		t.Fatalf("inventory key fetched %d times under an unissued challenge, want 0", keyFetches)
	}
	if got := len(stub.VerifyRequests()); got != 0 {
		t.Fatalf("/verify called %d times under an unissued challenge, want 0", got)
	}
}

// Every refused sandbox token is refused before CDS sends the evidence to the
// attestation-api.
func TestAttest_SandboxToken_RefusedBeforeEvidenceVerification(t *testing.T) {
	impostor, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *AttestHandler, *types.AttestRequestBody)
	}{
		{"no inventory to verify against", func(_ *testing.T, h *AttestHandler, _ *types.AttestRequestBody) {
			h.SandboxDigests = nil
		}},
		{"no node CIDRs", func(_ *testing.T, h *AttestHandler, _ *types.AttestRequestBody) {
			h.InventoryHosts = nil
		}},
		{"malformed token envelope", func(_ *testing.T, _ *AttestHandler, r *types.AttestRequestBody) {
			r.SandboxToken = json.RawMessage(`[]`)
		}},
		{"inventory outside the node CIDRs", func(t *testing.T, h *AttestHandler, _ *types.AttestRequestBody) {
			hosts, err := workloadclaims.ParseInventoryHosts([]string{"192.168.99.0/24"})
			if err != nil {
				t.Fatal(err)
			}
			h.InventoryHosts = hosts
		}},
		{"inventory key unreachable", func(_ *testing.T, h *AttestHandler, _ *types.AttestRequestBody) {
			h.SandboxDigests = fakeDigests{}
		}},
		{"signed by a key the inventory does not hold", func(t *testing.T, _ *AttestHandler, r *types.AttestRequestBody) {
			r.SandboxToken = signedSandboxToken(t, impostor, r.CSR, r.Challenge, testSandboxID)
		}},
		{"bound to another CSR key", func(t *testing.T, _ *AttestHandler, r *types.AttestRequestBody) {
			r.CSR = sandboxCSR(t)
		}},
		{"bound to another challenge", func(t *testing.T, h *AttestHandler, r *types.AttestRequestBody) {
			r.Challenge = issueChallenge(t, *h)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubAttestationApi(t, testLaunchDigest)
			h, signer := newSandboxTestEnv(t, stub.URL())
			csrPEM := sandboxCSR(t)
			challenge := issueChallenge(t, h)
			req := types.AttestRequestBody{
				Challenge:    challenge,
				CSR:          csrPEM,
				SandboxToken: signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID),
			}
			tc.change(t, &h, &req)

			w := postAttestSandbox(t, h, req.Challenge, req.CSR, req.SandboxToken)
			wantRefusal(t, w, http.StatusForbidden, types.ErrorCodeCSRDenied)
			if got := len(stub.VerifyRequests()); got != 0 {
				t.Fatalf("/verify called %d times for a refused sandbox token, want 0", got)
			}
		})
	}
}

// A token naming an inventory outside the node address ranges is refused
// before CDS dials that inventory for its key.
func TestAttest_SandboxToken_InventoryOutsideNodeRangesIsNotDialed(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h, signer := newSandboxTestEnv(t, stub.URL())
	keyFetches := 0
	h.SandboxDigests = countingDigests{
		fakeDigests: fakeDigests{key: signer.PublicKey()},
		keyFetches:  &keyFetches,
	}
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"192.168.99.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.InventoryHosts = hosts
	csrPEM := sandboxCSR(t)
	challenge := issueChallenge(t, h)

	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge, testSandboxID))
	wantRefusal(t, w, http.StatusForbidden, types.ErrorCodeCSRDenied)
	if keyFetches != 0 {
		t.Fatalf("inventory key fetched %d times for an inventory outside the node ranges, want 0", keyFetches)
	}
}

// A Pod request is held to the Pod pins alone: evidence a node pin admits does
// not admit a Pod whose launch key the Pod pins refuse.
func TestPodAttestIsNotAdmittedByANodePin(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, p)
	h.Images = fixedImages([]remote.ImagePin{tdxImagePin(t, "node", testMRTD, testRTMR1, testRTMR2)})
	h.PodImages[0].Anchor = []byte("another launch key")

	wantRefusal(t, postPodRequest(t, h, podRequest(t, h, p)), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// A node request is held to the node pins alone: evidence the Pod pins admit
// does not admit a node no node pin names.
func TestAttest_NodeIsNotAdmittedByAPodPin(t *testing.T) {
	p := podTestClaims(t)
	h, _ := podTestHandler(t, p)
	csrPEM, _ := generateCSR(t)

	wantRefusal(t, postAttestTDX(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// A Pod's membership gate and its workload stamp come from one policy
// snapshot, even when the allowlist changes during the request.
func TestPodAttestStampsTheSnapshotItsGateUsed(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, _ := podTestHandler(t, p)
	loads := 0
	h.AllowlistStore = racedStore{
		first: completeAPIStore(t),
		later: fakeStore{workloads: map[string]pkgallowlist.Workload{"renamed": namedEntry(t, wlDigestA)}},
		calls: &loads,
	}

	w := postPodRequest(t, h, podRequest(t, h, p))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if loads != 1 {
		t.Fatalf("allowlist loaded %d times during issuance, want 1", loads)
	}
	stamp, err := armtls.MatchedWorkloadFromCert(leafFromAttestResponse(t, w))
	if err != nil || stamp == nil || stamp.Name != "api" || stamp.AllowlistVersion != "1" {
		t.Fatalf("stamp = %+v, %v; want the first snapshot's api at version 1", stamp, err)
	}
}

// The CA returned with a leaf is the CA that signed it.
func TestAttest_ReturnsTheCAThatSignedTheLeaf(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	h := newTestAttestHandler(t, stub.URL(), nil)
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	chain, err := certutil.ParsePEMCertificates(w.Body.Bytes())
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length: got %d, want leaf + CA", len(chain))
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Fatalf("leaf returned with a CA that did not sign it: %v", err)
	}
}
