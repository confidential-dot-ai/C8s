package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
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
			if named := strings.Contains(oc.Error, "no prefix of the"); named != (!tc.ok && len(tc.measured) > 0) {
				t.Errorf("Error = %q; want the rejected history named only when a listed one fails to replay", oc.Error)
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
	snp := snpVerifiedOutcome(t, config{}, &evidence{platform: "snp", measured: []string{testPolicyP}})
	if slices.ContainsFunc(snp.Warnings, func(w string) bool { return strings.Contains(w, "--operator-pkey") }) {
		t.Errorf("SNP Warnings = %v, want none naming --operator-pkey, a TDX-only flag", snp.Warnings)
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
		name        string
		history     []string
		stamp       []byte
		leaf        bool
		workloadErr error
		wantErr     string
	}{
		{"history pinned", []string{testPolicyP, testPolicyQ}, nil, false, nil, ""},
		{"stamp pinned", []string{testPolicyP}, stampP, true, nil, ""},
		{"history not pinned", []string{testPolicyP, testPolicyR}, nil, false, nil, "policy_history_not_pinned: the node enforced policy " + testPolicyR},
		{"stamp not pinned", []string{testPolicyP}, stampR, true, nil, "policy_history_not_pinned: the leaf was issued under policy " + testPolicyR},
		{"leaf without stamp", []string{testPolicyP}, nil, true, nil, "policy_history_not_pinned: the leaf carries no issuing policy"},
		{"unreadable stamp", []string{testPolicyP}, nil, true, errors.New("bad extension"), "policy_history_not_pinned: the leaf's issuing policy cannot be read: bad extension"},
		{"no history", nil, nil, false, nil, "policy_history_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{workloadErr: tc.workloadErr}
			if tc.leaf {
				ev.leaf = &x509.Certificate{}
			}
			if tc.stamp != nil {
				ev.workload = &armtls.MatchedWorkload{Name: "app", AllowlistDigest: tc.stamp}
			}
			for _, partial := range []bool{false, true} {
				oc := Outcome{Verified: !partial, Partial: partial, MeasuredPolicies: tc.history}
				applyPinPolicy(&oc, config{pinPolicies: pins}, ev)
				if passed := oc.Verified || oc.Partial; passed != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
					t.Errorf("applyPinPolicy(partial %v) = passed %v, error %q; want error containing %q", partial, passed, oc.Error, tc.wantErr)
				}
			}
		})
	}
}

// Without --mesh-ca every attest-pq and attest-lb verdict is demoted to
// partial; --pin-policy must still fail it, wherever it runs in the sequence.
func TestPinPolicyThroughVerdictPolicies(t *testing.T) {
	measured := []string{testPolicyP, testPolicyQ}
	for _, tc := range []struct {
		name    string
		pins    []string
		wantErr string
	}{
		{"pinned", measured, ""},
		{"not pinned", []string{testPolicyP}, "policy_history_not_pinned: the node enforced policy " + testPolicyQ},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{pinPolicies: tc.pins}
			plan, seed := historyPlan(t, cfg)
			ev := &evidence{platform: "tdx", measured: measured, leafChainDerived: true}
			oc := newOutcome(cfg, ev, tdxResult(testMRTD, rtmr3Claims(runtimemeasure.FromDigestsSeeded(seed, measured))), nil, plan)
			applyVerdictPolicies(&oc, cfg, ev, nil, operatorKeysReport{}, plan, measurementsReport{})
			checkPolicyHistory(context.Background(), &oc, cfg, ev, plan.trustKeys)
			if oc.Verified || oc.Partial != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("verdict = verified %v, partial %v, error %q; want partial only without error containing %q", oc.Verified, oc.Partial, oc.Error, tc.wantErr)
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
		{"signature unavailable", signatureFails(objectServer(digest, v.Policy, v.Token)), keysPath, []string{digest}, "policy_history_unsigned: fetch the signature of " + digest + ": status 502"},
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

// signatureFails answers every signature request with 502, as a router does
// while CDS is unavailable.
func signatureFails(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/signature") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func TestFetchAllowlists(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	hexDigest := hex.EncodeToString(sum[:])
	srv := httptest.NewTLSServer(objectServer("sha256:"+hexDigest, v.Policy, ""))
	defer srv.Close()
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		url     string
		trust   bool
		saved   bool
		wantErr string
	}{
		{"fetch", srv.URL, false, true, ""},
		{"saved before the signature check", srv.URL, true, true, "policy_history_unsigned: policy sha256:" + hexDigest + " carries no operator signature"},
		{"no target URL", "", false, false, "allowlist_fetch_failed: fetching the policy history needs a target URL"},
		{"no target URL to trust", "", true, false, "policy_history_unsigned: fetching the policy history needs a target URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "policies")
			cfg := config{url: tc.url, fetchAllowlists: dir, timeout: 5 * time.Second}
			if tc.trust {
				cfg.trustOperator, cfg.trustOperatorKeys = true, keysPath
			}
			plan, _ := historyPlan(t, cfg)
			oc := Outcome{Verified: true, MeasuredPolicies: []string{"sha256:" + hexDigest}}
			checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
			if oc.Verified != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("checkPolicyHistory = verified %v, error %q; want error containing %q", oc.Verified, oc.Error, tc.wantErr)
			}
			got, err := os.ReadFile(filepath.Join(dir, hexDigest+".json"))
			if saved := err == nil && bytes.Equal(got, v.Policy); saved != tc.saved {
				t.Errorf("policy saved = %v (%v), want %v", saved, err, tc.saved)
			}
		})
	}
}

func TestFetchAllowlistsEmptyHistoryWarns(t *testing.T) {
	cfg := config{url: "https://unused.example", fetchAllowlists: t.TempDir()}
	oc := Outcome{Verified: true}
	checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, nil)
	if !oc.Verified || !slices.ContainsFunc(oc.Warnings, func(w string) bool { return strings.Contains(w, "--fetch-allowlists saved nothing") }) {
		t.Errorf("checkPolicyHistory = verified %v, warnings %v; want verified with a warning naming --fetch-allowlists", oc.Verified, oc.Warnings)
	}
}

// A history of a signed then an unsigned policy: both are saved for review,
// and the failure names the second.
func TestTrustOperatorTwoEntries(t *testing.T) {
	v := loadSignatureVector(t)
	signed := sha256.Sum256(v.Policy)
	unsignedBody := []byte(`{"version":"2"}`)
	unsigned := sha256.Sum256(unsignedBody)
	history := []string{"sha256:" + hex.EncodeToString(signed[:]), "sha256:" + hex.EncodeToString(unsigned[:])}
	signedObjects := objectServer(history[0], v.Policy, v.Token)
	unsignedObjects := objectServer(history[1], unsignedBody, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, hex.EncodeToString(signed[:])) {
			signedObjects.ServeHTTP(w, r)
			return
		}
		unsignedObjects.ServeHTTP(w, r)
	}))
	defer srv.Close()
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: keysPath, fetchAllowlists: dir, timeout: 5 * time.Second}
	plan, _ := historyPlan(t, cfg)
	oc := Outcome{Partial: true, MeasuredPolicies: history}
	checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
	if want := "policy_history_unsigned: policy " + history[1] + " carries no operator signature"; oc.Partial || !strings.Contains(oc.Error, want) {
		t.Errorf("checkPolicyHistory = partial %v, error %q; want error containing %q", oc.Partial, oc.Error, want)
	}
	for i, body := range [][]byte{v.Policy, unsignedBody} {
		got, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(history[i], "sha256:")+".json"))
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("saved %s = %q, %v; want the served bytes", history[i], got, err)
		}
	}
}

func TestFetchPolicyLimits(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /big", func(w http.ResponseWriter, _ *http.Request) { w.Write(make([]byte, maxPolicyBytes+1)) })
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/big", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, tc := range []struct{ path, wantErr string }{
		{"/big", "exceeds"},
		{"/redirect", "status 302"},
		{"/missing", errNotFound.Error()},
	} {
		if _, err := fetchPolicy(context.Background(), srv.URL+tc.path, "", 5*time.Second); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("fetchPolicy(%s) = %v, want error containing %q", tc.path, err, tc.wantErr)
		}
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

// --trust-operator also requires the policy the leaf was issued under to be
// signed, as --pin-policy requires it pinned.
func TestTrustOperatorLeafPolicy(t *testing.T) {
	v := loadSignatureVector(t)
	signedSum := sha256.Sum256(v.Policy)
	unsignedBody := []byte(`{"version":"2"}`)
	unsignedSum := sha256.Sum256(unsignedBody)
	signed, unsigned := "sha256:"+hex.EncodeToString(signedSum[:]), "sha256:"+hex.EncodeToString(unsignedSum[:])
	signedObjects := objectServer(signed, v.Policy, v.Token)
	unsignedObjects := objectServer(unsigned, unsignedBody, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, hex.EncodeToString(signedSum[:])) {
			signedObjects.ServeHTTP(w, r)
			return
		}
		unsignedObjects.ServeHTTP(w, r)
	}))
	defer srv.Close()
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{}
	for _, tc := range []struct {
		name    string
		ev      *evidence
		wantErr string
	}{
		{"signed stamp", &evidence{leaf: leaf, workload: &armtls.MatchedWorkload{AllowlistDigest: signedSum[:]}}, ""},
		{"unsigned stamp", &evidence{leaf: leaf, workload: &armtls.MatchedWorkload{AllowlistDigest: unsignedSum[:]}}, "policy_history_unsigned: policy " + unsigned + " carries no operator signature"},
		{"no stamp", &evidence{leaf: leaf}, "policy_history_unsigned: the leaf carries no issuing policy"},
		{"unreadable stamp", &evidence{leaf: leaf, workloadErr: errors.New("bad stamp")}, "policy_history_unsigned: the leaf's issuing policy cannot be read: bad stamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: keysPath, timeout: 5 * time.Second}
			plan, _ := historyPlan(t, cfg)
			oc := Outcome{Partial: true, MeasuredPolicies: []string{signed}}
			checkPolicyHistory(context.Background(), &oc, cfg, tc.ev, plan.trustKeys)
			if oc.Partial != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("checkPolicyHistory = partial %v, error %q; want error containing %q", oc.Partial, oc.Error, tc.wantErr)
			}
		})
	}
}
