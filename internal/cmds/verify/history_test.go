package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

var (
	testPolicyP = "sha256:" + strings.Repeat("1", 64)
	testPolicyQ = "sha256:" + strings.Repeat("2", 64)
	testPolicyR = "sha256:" + strings.Repeat("3", 64)
)

// historyPlan is a plan pinning the test image and the operator-key seed.
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

// A list that nothing replays must not read as a checked history.
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

func TestHistoryFlags(t *testing.T) {
	pubPath, _, pubPEM := operatorKeypair(t)
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{"pin", config{operatorPubkey: pubPath, pinPolicies: []string{testPolicyP}}, ""},
		{"trust", config{operatorPubkey: pubPath, trustOperator: true, trustOperatorKeys: keysPath}, ""},
		{"fetch", config{operatorPubkey: pubPath, fetchAllowlists: t.TempDir()}, ""},
		{"malformed pin", config{operatorPubkey: pubPath, pinPolicies: []string{"sha256:ABC"}}, "not sha256:<64 lowercase hex>"},
		{"exclusive", config{operatorPubkey: pubPath, pinPolicies: []string{testPolicyP}, trustOperator: true, trustOperatorKeys: keysPath}, "exclusive"},
		{"pin without seed", config{pinPolicies: []string{testPolicyP}}, "--pin-policy requires --operator-pkey"},
		{"trust without seed", config{trustOperator: true, trustOperatorKeys: keysPath}, "--trust-operator requires --operator-pkey"},
		{"fetch without seed", config{fetchAllowlists: t.TempDir()}, "--fetch-allowlists requires --operator-pkey"},
		{"trust without keys", config{operatorPubkey: pubPath, trustOperator: true}, "requires --trust-operator-keys"},
		{"keys without trust", config{operatorPubkey: pubPath, trustOperatorKeys: keysPath}, "requires --trust-operator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.imageManifest = writeTestManifest(t)
			_, err := buildPolicy(tc.cfg)
			if (tc.wantErr == "" && err != nil) || (tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Errorf("buildPolicy = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestPinPolicy(t *testing.T) {
	stampP, _ := hex.DecodeString(strings.TrimPrefix(testPolicyP, "sha256:"))
	stampR, _ := hex.DecodeString(strings.TrimPrefix(testPolicyR, "sha256:"))
	pins := []string{testPolicyP, testPolicyQ}
	for _, tc := range []struct {
		name    string
		history []string
		stamp   []byte
		wantErr string
	}{
		{"history pinned", []string{testPolicyP, testPolicyQ}, nil, ""},
		{"stamp pinned", []string{testPolicyP}, stampP, ""},
		{"history not pinned", []string{testPolicyP, testPolicyR}, nil, "policy_history_not_pinned: the node enforced policy " + testPolicyR},
		{"stamp not pinned", []string{testPolicyP}, stampR, "policy_history_not_pinned: the leaf was issued under policy " + testPolicyR},
		{"no history", nil, nil, "policy_history_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{}
			if tc.stamp != nil {
				ev.workload = &armtls.MatchedWorkload{Name: "app", AllowlistDigest: tc.stamp}
			}
			oc := Outcome{Verified: true, MeasuredPolicies: tc.history}
			applyPinPolicy(&oc, config{pinPolicies: pins}, ev)
			if oc.Verified != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("applyPinPolicy = verified %v, error %q; want error containing %q", oc.Verified, oc.Error, tc.wantErr)
			}
		})
	}
}

// signatureVector is pkg/operatorauth's shared test vector: an operator key
// and its stored write token over a canonical allowlist.
type signatureVector struct {
	KeysPEM string `json:"operator_keys_pem"`
	Policy  []byte `json:"policy_b64"`
	Token   string `json:"token"`
}

func loadSignatureVector(t *testing.T) signatureVector {
	t.Helper()
	raw, err := os.ReadFile("../../../pkg/operatorauth/testdata/operator_signature_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v signatureVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// objectServer serves CDS's history object routes: body under digest, and
// token as its signature when non-empty.
func objectServer(digest string, body []byte, token string) http.Handler {
	object := "/allowlist/objects/sha256/" + strings.TrimPrefix(digest, "sha256:")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+object, func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
	if token != "" {
		mux.HandleFunc("GET "+object+"/signature", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(token + "\n")) })
	}
	return mux
}

func TestTrustOperator(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := operatorKeypair(t)

	for _, tc := range []struct {
		name    string
		handler http.Handler
		keys    string
		history []string
		wantErr string
	}{
		{"signed", objectServer(digest, v.Policy, v.Token), keysPath, []string{digest}, ""},
		{"unsigned", objectServer(digest, v.Policy, ""), keysPath, []string{digest}, "policy_history_unsigned: policy " + digest + " carries no operator signature"},
		{"other key", objectServer(digest, v.Policy, v.Token), otherPub, []string{digest}, "policy_history_unsigned: policy " + digest + ":"},
		{"unknown object", objectServer(testPolicyP, v.Policy, v.Token), keysPath, []string{digest}, "policy_history_unsigned: fetch " + digest},
		{"tampered object", objectServer(digest, append(slices.Clone(v.Policy), ' '), v.Token), keysPath, []string{digest}, "allowlist_digest_mismatch"},
		{"no history", objectServer(digest, v.Policy, v.Token), keysPath, nil, "policy_history_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: tc.keys, timeout: 5 * time.Second}
			plan, _ := historyPlan(t, cfg)
			oc := Outcome{Partial: true, MeasuredPolicies: tc.history}
			checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
			if oc.Partial != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("checkPolicyHistory = partial %v, error %q; want error containing %q", oc.Partial, oc.Error, tc.wantErr)
			}
		})
	}
}

func TestFetchAllowlists(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	hexDigest := hex.EncodeToString(sum[:])
	srv := httptest.NewTLSServer(objectServer("sha256:"+hexDigest, v.Policy, ""))
	defer srv.Close()
	leaf := sha256.Sum256(srv.Certificate().Raw)

	for _, tc := range []struct {
		name    string
		leaf    []byte
		wantErr string
	}{
		{"bound to the attested leaf", leaf[:], ""},
		{"serving leaf changed", make([]byte, sha256.Size), "allowlist_fetch_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "policies")
			cfg := config{url: srv.URL, fetchAllowlists: dir, timeout: 5 * time.Second}
			ev := &evidence{fresh: true, servingLeafSHA256: base64.RawURLEncoding.EncodeToString(tc.leaf)}
			oc := Outcome{Verified: true, MeasuredPolicies: []string{"sha256:" + hexDigest}}
			checkPolicyHistory(context.Background(), &oc, cfg, ev, nil)
			if oc.Verified != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Fatalf("checkPolicyHistory = verified %v, error %q; want error containing %q", oc.Verified, oc.Error, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got, err := os.ReadFile(filepath.Join(dir, hexDigest+".json"))
			if err != nil || !bytes.Equal(got, v.Policy) {
				t.Errorf("saved policy = %q, %v; want the served bytes", got, err)
			}
		})
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
