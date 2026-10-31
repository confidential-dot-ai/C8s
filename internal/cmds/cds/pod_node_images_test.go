package cds

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestNodeDecreesRetainTheMeasuredPodAuthorityBoundary(t *testing.T) {
	podKey := operatorKeysPEM(t)
	pods := []remote.ImagePin{{Anchor: podKey}}
	old := imagePin(t, "old", otherLaunchDigest)
	next := imagePin(t, "next", testLaunchDigest)
	next.Anchor = operatorKeysPEM(t)
	moving := certifiedByCommand(old)
	guarded := separatePodAuthorities(moving, pods)
	verifier := mockapi.New(t)
	tlsConfig, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy: armtls.Pins(guarded.Current().Policy()).VerifyPolicy(verifier.URL()),
	})
	if err != nil {
		t.Fatal(err)
	}
	armtls.FollowServerPins(tlsConfig, guarded, verifier.URL())
	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := armtls.CreateAttestedCert(key, &armtls.Attestation{
		Family: armtls.TEETypeSEVSNP,
		Report: []byte(`{"platform":"snp","evidence":{"report":"AA=="}}`),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, images := range [][]remote.ImagePin{{old, next}, {next}} {
		moving.certify(images...)
		if got := guarded.Current(); !reflect.DeepEqual(got, moving.Current()) {
			t.Fatal("disjoint node rotation was filtered or unioned with retired pins")
		}
		if guarded.Generation() != moving.Generation() {
			t.Fatal("guard lost the decree generation")
		}
	}
	for _, anchor := range [][]byte{podKey, append([]byte(" \n"), append(bytes.Clone(podKey), '\n', '\t')...), []byte("malformed")} {
		conflict := imagePin(t, "conflicting", testLaunchDigest)
		conflict.Anchor = anchor
		moving.certify(next, conflict)
		if got := guarded.Current(); got.Family != moving.Current().Family || len(got.Images) != 0 {
			t.Fatalf("conflicting decree retained node authority: %+v", got)
		}
		// The published set and callback TLS policy must refuse the same
		// whole set, including its otherwise valid entry.
		w := httptest.NewRecorder()
		handleMeasurements(guarded)(w, httptest.NewRequest(http.MethodGet, "/measurements", nil))
		published, err := refvalues.ParseRendered(w.Body.Bytes())
		if w.Code != http.StatusOK || err != nil || len(published.Images) != 0 {
			t.Fatalf("refused node set was not published empty: %d %s (%v)", w.Code, w.Body, err)
		}
		if err := tlsConfig.VerifyPeerCertificate([][]byte{certificate}, nil); !errors.Is(err, armtls.ErrUnpinned) {
			t.Fatalf("existing callback TLS config accepted refused node pins: %v", err)
		}
		if len(verifier.VerifyRequests()) != 0 {
			t.Fatal("a refused node set reached the attestation verifier")
		}
	}
	moving.certify(next)
	if !reflect.DeepEqual(guarded.Current(), moving.Current()) {
		t.Fatal("a later disjoint decree did not restore its own exact node set")
	}
}

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

type refreshableNodePins struct {
	armtls.PinSource
	err       error
	refreshes int
}

func (s *refreshableNodePins) Refresh() error {
	s.refreshes++
	return s.err
}

func TestPodAuthorityGuardPreservesSourceRefreshAndDisabledPolicy(t *testing.T) {
	moving := certifiedByCommand(imagePin(t, "node", testLaunchDigest))
	wantErr := errors.New("decree unavailable")
	source := &refreshableNodePins{PinSource: moving, err: wantErr}
	guarded := separatePodAuthorities(source, []remote.ImagePin{{Anchor: operatorKeysPEM(t)}})
	if err := guarded.Refresh(); !errors.Is(err, wantErr) || source.refreshes != 1 {
		t.Fatalf("refresh result=%v, calls=%d", err, source.refreshes)
	}
	moving.certify(imagePin(t, "next", otherLaunchDigest))
	if guarded.Generation() != moving.Generation() {
		t.Fatal("the wrapper froze a generation")
	}
	if separatePodAuthorities(source, nil) != source {
		t.Fatal("disabled Pod policy changed the upstream node source")
	}
	// A malformed Pod authority cannot silently disable the guard.
	if got := separatePodAuthorities(source, []remote.ImagePin{{Anchor: []byte("malformed")}}).Current(); len(got.Images) != 0 {
		t.Fatal("malformed Pod authority left nodes trusted")
	}
}
