package cds

import (
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// A node decree that also names the Pod launch authority is
// refused as a whole, and the measured Pod policy stays in force regardless.
func TestConflictingNodeDecreeRefusesIssuanceWithoutDisablingPodProfile(t *testing.T) {
	p := podTestClaims(t, wlDigestA)
	h, stub := podTestHandler(t, p)
	podKey := operatorKeysPEM(t)
	h.PodImages[0].Anchor = podKey
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(podKey), p.RuntimeExtensions)
	verdict := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
	verdict.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
	// An otherwise valid node image cannot rescue a decree that also
	// assigns the Pod launch authority to a node.
	node := imagePin(t, "node", testLaunchDigest)
	moving := certifiedByCommand(node)
	h.NodeImages = separatePodAuthorities(moving, h.PodImages)
	csr, _ := generateCSR(t)
	stub.SetVerdict(mockapi.PassingVerdict(testLaunchDigest))
	if w := postAttest(t, h, issueChallenge(t, h), csr); w.Code != http.StatusOK {
		t.Fatalf("disjoint node policy refused issuance: %d %s", w.Code, w.Body)
	}
	moving.certify(node, h.PodImages[0])
	wantRefusal(t, postAttest(t, h, issueChallenge(t, h), csr), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
	stub.SetVerdict(verdict)
	if w := postPodRequest(t, h, podRequest(t, h, p)); w.Code != http.StatusOK {
		t.Fatalf("independent measured Pod policy was disabled: %d %s", w.Code, w.Body)
	}
}
