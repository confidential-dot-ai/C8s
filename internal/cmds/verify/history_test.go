package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

var (
	testPolicyP = "sha256:" + strings.Repeat("1", 64)
	testPolicyQ = "sha256:" + strings.Repeat("2", 64)
	testPolicyR = "sha256:" + strings.Repeat("3", 64)
)

func historyPlan(t *testing.T, cfg config) (*verifyPlan, [runtimemeasure.Size]byte) {
	t.Helper()
	pubPath, _, pubPEM := operatorKeypair(t)
	cfg.imageManifest = writeTestManifest(t)
	cfg.operatorPubkey = pubPath
	return mustPlan(t, cfg), runtimemeasure.Seed(pubPEM)
}

func rtmr3Claims(reg [runtimemeasure.Size]byte) map[string]any {
	return map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": hex.EncodeToString(reg[:])}
}

func TestReplayMeasuredPolicies(t *testing.T) {
	plan, seed := historyPlan(t, config{})
	measured := []string{testPolicyP, testPolicyQ, testPolicyR}
	for _, tc := range []struct {
		name     string
		measured []string
		rtmr3    [runtimemeasure.Size]byte
		want     []string
		ok       bool
	}{
		{"bare seed", measured, seed, nil, true},
		{"whole list", measured, runtimemeasure.FromDigestsSeeded(seed, measured), measured, true},
		{"prefix read after the quote", measured, runtimemeasure.FromDigestsSeeded(seed, measured[:2]), measured[:2], true},
		{"extend outside the list", measured, runtimemeasure.FromDigestsSeeded(seed, []string{testPolicyQ}), nil, false},
		{"no list", nil, runtimemeasure.FromDigestsSeeded(seed, measured[:1]), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{platform: "tdx", measured: tc.measured}
			oc := newOutcome(config{}, ev, tdxResult(testMRTD, rtmr3Claims(tc.rtmr3)), nil, plan)
			if oc.Verified != tc.ok {
				t.Fatalf("newOutcome verified = %v (%s), want %v", oc.Verified, oc.Error, tc.ok)
			}
			if !slices.Equal(oc.MeasuredPolicies, tc.want) {
				t.Errorf("MeasuredPolicies = %v, want %v", oc.MeasuredPolicies, tc.want)
			}
		})
	}
}

func TestMeasuredPoliciesWithoutOperatorPkeyWarn(t *testing.T) {
	plan := mustPlan(t, config{imageManifest: writeTestManifest(t)})
	ev := &evidence{platform: "tdx", measured: []string{testPolicyP}}
	oc := newOutcome(config{}, ev, tdxResult(testMRTD, matchingRTMRs()), nil, plan)
	if !oc.Verified || len(oc.MeasuredPolicies) != 0 {
		t.Fatalf("newOutcome = verified %v, history %v; want verified, no history", oc.Verified, oc.MeasuredPolicies)
	}
	if !slices.ContainsFunc(oc.Warnings, func(w string) bool { return strings.Contains(w, "--operator-pkey") }) {
		t.Errorf("Warnings = %v, want one naming --operator-pkey", oc.Warnings)
	}
}

func TestMeasuredPoliciesOutput(t *testing.T) {
	oc := Outcome{Verified: true, MeasuredPolicies: []string{testPolicyP, testPolicyQ}}
	var js bytes.Buffer
	render(config{output: "json"}, oc, &js)
	var decoded struct {
		MeasuredPolicies []string `json:"measured_policies"`
	}
	if err := json.Unmarshal(js.Bytes(), &decoded); err != nil || !slices.Equal(decoded.MeasuredPolicies, oc.MeasuredPolicies) {
		t.Errorf("JSON measured_policies = %v, %v; want %v", decoded.MeasuredPolicies, err, oc.MeasuredPolicies)
	}
	var text bytes.Buffer
	render(config{}, oc, &text)
	if want := "history:      " + testPolicyP + ", " + testPolicyQ; !strings.Contains(text.String(), want) {
		t.Errorf("text output lacks %q:\n%s", want, text.String())
	}
}
