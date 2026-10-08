package verify

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestNodePolicyPinsActualEvidence(t *testing.T) {
	serverOnly, serverAndAgents := loadNodeIdentities(t)
	plan, err := buildPolicy(config{
		measurementsConfig: writeImagePolicy(t, "server.json", serverOnly),
		servedPolicyFile:   writeImagePolicy(t, "peers.json", serverAndAgents),
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := serverOnly.Images[0]
	bound := func(key []byte) *teetypes.VerificationResult {
		r := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX}
		r.Claims.LaunchDigest = hex.EncodeToString(entry.Digest)
		r.Claims.PlatformData = map[string]any{}
		for idx, pin := range entry.Registers {
			r.Claims.PlatformData["rtmr_"+string(rune('0'+idx))] = hex.EncodeToString(pin)
		}
		seed := runtimemeasure.Seed(key)
		r.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(seed[:])
		return r
	}
	agent := bound(serverAndAgents.Images[1].Anchor)
	if err := remote.EnforceImages(remote.VerifyResponse{Result: *agent}, plan.served.want.Images, agent.Platform); err != nil {
		t.Fatalf("agent evidence must be admitted by the served policy: %v", err)
	}
	if err := remote.EnforceImages(remote.VerifyResponse{Result: *agent}, plan.policy.Policy.Images, agent.Platform); err == nil {
		t.Fatal("the target verification policy admitted an agent")
	}
	for _, tc := range []struct {
		name   string
		change func(*teetypes.VerificationResult)
		want   bool
	}{
		{"matching server", func(*teetypes.VerificationResult) {}, true},
		{"wrong image", func(r *teetypes.VerificationResult) { r.Claims.LaunchDigest = strings.Repeat("ff", 48) }, false},
		{"wrong kernel", func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_1"] = strings.Repeat("ff", 48) }, false},
		{"wrong rootfs", func(r *teetypes.VerificationResult) { r.Claims.PlatformData["rtmr_2"] = strings.Repeat("ff", 48) }, false},
		{"agent on same image", func(r *teetypes.VerificationResult) { *r = *agent }, false},
		{"unknown launch key", func(r *teetypes.VerificationResult) { *r = *bound([]byte("another role key")) }, false},
		{"wrong platform", func(r *teetypes.VerificationResult) { r.Platform = teetypes.PlatformSNP }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bound(entry.Anchor)
			tc.change(r)
			got := newOutcome(config{}, &evidence{platform: "tdx"}, r, nil, plan)
			if got.Verified != tc.want || !got.Pinned {
				t.Fatalf("verdict = %+v", got)
			}
		})
	}
	// Hardware rejection dominates even if all untrusted claim fields match.
	if got := newOutcome(config{}, &evidence{}, bound(entry.Anchor), errors.New("invalid hardware signature"), plan); got.Verified {
		t.Fatal("failed hardware evidence became verified")
	}
	// A matching weak alternative may not borrow a different image's complete
	// RTMR tuple to pass the existing TDX deployment-image requirement.
	complete := entry
	complete.Digest = []byte(strings.Repeat("x", 48))
	weak := entry
	weak.Registers = nil
	plan.refValues.Images = []remote.ImagePin{weak, complete}
	if got := newOutcome(config{}, &evidence{}, bound(entry.Anchor), nil, plan); got.Verified || !strings.Contains(got.Error, "MRTD only") {
		t.Fatalf("weak matching image borrowed unrelated pins: %+v", got)
	}
}

func TestServedNodePolicyDetectsDroppedOperatorKey(t *testing.T) {
	want, err := refvalues.Load(filepath.Join("..", "..", "..", "internal", "testdata", "node-identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	served := want
	served.Images = append([]remote.ImagePin(nil), want.Images...)
	served.Images[0].Anchor = nil
	fail, messages := collectFailures()
	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: served, fetched: true}, fail)
	if len(*messages) != 2 {
		t.Fatalf("dropped role key did not change the admitted identities: %v", *messages)
	}
}

// A --served-policy-file alone is a cross-check input, never an identity pin:
// the verdict must report itself unpinned.
func TestServedPolicyFileAloneDoesNotPin(t *testing.T) {
	plan := &verifyPlan{
		policy: &armtls.VerifyPolicy{},
		served: &servedSet{flag: "--served-policy-file", want: refvalues.ReferenceValues{Family: teetypes.FamilyTDX}},
	}
	r := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX}
	r.Claims.LaunchDigest = strings.Repeat("11", 48)
	got := newOutcome(config{}, &evidence{platform: "tdx"}, r, nil, plan)
	if got.Pinned {
		t.Fatalf("a served-set cross-check became an identity pin: %+v", got)
	}
}

func TestCDSMultipleLaunchAnchorsWarning(t *testing.T) {
	serverOnly, serverAndAgent := loadNodeIdentities(t)
	otherImage := serverOnly.Images[0]
	otherImage.Digest = bytes.Repeat([]byte{0xff}, 48)
	unanchored := serverOnly.Images[0]
	unanchored.Anchor = nil
	for _, tc := range []struct {
		name     string
		kind     string
		images   []remote.ImagePin
		verified bool
		partial  bool
		wantWarn bool
	}{
		{"server and agent", "cds", serverAndAgent.Images, true, false, true},
		{"server only", "cds", serverOnly.Images, true, false, false},
		{"image rotation with same anchor", "cds", []remote.ImagePin{serverOnly.Images[0], otherImage}, true, false, false},
		{"unanchored images", "cds", []remote.ImagePin{unanchored, unanchored}, true, false, false},
		{"one anchor and unanchored", "cds", []remote.ImagePin{unanchored, serverOnly.Images[0]}, true, false, false},
		{"no target policy", "cds", nil, true, false, false},
		{"load balancer", "lb", serverAndAgent.Images, true, false, false},
		{"workload", "workload", serverAndAgent.Images, true, false, false},
		{"auto", "auto", serverAndAgent.Images, true, false, false},
		{"failed verdict", "cds", serverAndAgent.Images, false, false, false},
		{"partial verdict", "cds", serverAndAgent.Images, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := &verifyPlan{refValues: refvalues.ReferenceValues{Family: serverOnly.Family, Images: tc.images}}
			oc := Outcome{Verified: tc.verified, Partial: tc.partial}
			applyVerdictPolicies(&oc, config{kind: tc.kind}, &evidence{}, nil, operatorKeysReport{}, plan, measurementsReport{})
			if oc.Verified != tc.verified || oc.Partial != tc.partial {
				t.Fatalf("warning changed verdict: %+v", oc)
			}
			if gotWarn := len(oc.Warnings) > 0; gotWarn != tc.wantWarn {
				t.Fatalf("warnings = %v, want warning = %v", oc.Warnings, tc.wantWarn)
			}
			for _, format := range []string{"text", "json"} {
				var out bytes.Buffer
				render(config{output: format}, oc, &out)
				if strings.Contains(out.String(), "multiple launch-key anchors") != tc.wantWarn {
					t.Errorf("%s warning missing or unexpected: %s", format, &out)
				}
			}
		})
	}
}
