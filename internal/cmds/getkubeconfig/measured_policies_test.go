package getkubeconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// A node that measured allowlist policies after its workloads binds the
// operator key once a prefix of its reported list replays the quote's
// register; a node that measured none keeps today's check.
func TestCheckIdentityReplaysMeasuredPolicies(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	exp.workloadDigests = []string{"sha256:" + strings.Repeat("a", 64)}
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	quote := func(policies ...string) *policyList {
		return &policyList{list: policies}
	}
	overCap := []string{p}
	for len(overCap) <= armtls.MaxRuntimeExtensions {
		overCap = append(overCap, q)
	}
	for _, tc := range []struct {
		name     string
		measured []string // extended after the workloads in the quote
		policies *policyList
		wantErr  bool
	}{
		{name: "no policies measured, no list", wantErr: false},
		{name: "no policies measured, list ahead", policies: quote(p)},
		{name: "list matches", measured: []string{p, q}, policies: quote(p, q)},
		{name: "list ahead of the quote", measured: []string{p}, policies: quote(p, q)},
		{name: "list does not replay", measured: []string{p}, policies: quote(q), wantErr: true},
		{name: "measured without a list", measured: []string{p}, wantErr: true},
		{name: "measured, empty list", measured: []string{p}, policies: quote(), wantErr: true},
		{name: "replaying list over the cap", measured: []string{p}, policies: quote(overCap...), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := verifiedResultFor(exp)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), append(slices.Clone(exp.workloadDigests), tc.measured...))
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			e := exp
			e.policies = tc.policies
			err := e.checkIdentity(res)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkIdentity = %v, want error %v", err, tc.wantErr)
			}
			// A miss with a list says the list may be stale.
			if err != nil && tc.policies != nil && !strings.Contains(err.Error(), "may predate") {
				t.Errorf("checkIdentity = %v, want it to say the list may predate the latest policy", err)
			}
		})
	}
}

// Run takes the node's list from the verified cred-release leaf and releases
// only when a prefix of it replays the quote's RTMR[3].
func TestRunReplaysMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name    string
		leaf    []string
		wantErr bool
	}{
		{name: "leaf list replays", leaf: []string{p, q}},
		{name: "leaf list does not replay", leaf: []string{q}, wantErr: true},
		{name: "leaf carries no list", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
			res := verifiedResultFor(env.exp)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.exp.operatorPubPEM), []string{p})
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			stubVerify(t, res, nil)

			var releaseHits atomic.Int32
			release := newAttestedTLSServerWithExtensions(t, teetypes.PlatformTDX, tc.leaf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				releaseHits.Add(1)
				releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
			}))
			cfg := env.config()
			cfg.ReleaseBaseURL = release.URL

			err := Run(context.Background(), cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && releaseHits.Load() != 0 {
				t.Fatalf("cred-release hits = %d, want 0", releaseHits.Load())
			}
		})
	}
}

// The fresh gate replays the list the /attest response carries, read after
// the quote, so a node that measured a policy after its leaf was minted still
// passes; without that list it falls back to the leaf's lagging one.
func TestAttestResponseListSupersedesLeaf(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name     string
		response []string
		wantErr  bool
	}{
		{name: "response lists the new policy", response: []string{p, q}},
		{name: "response carries no list", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, "", http.StatusOK, goodRelease)
			res := verifiedResultFor(env.exp)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.exp.operatorPubPEM), []string{p, q})
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			stubVerify(t, res, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(credrelease.AttestResponse{
					AttestationEvidence: teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)},
					RuntimeExtensions:   tc.response,
				})
			}))
			defer srv.Close()
			keyPEM, err := os.ReadFile(env.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			exp := env.exp
			exp.policies = &policyList{list: []string{p}} // the leaf predates q

			err = attestCredentialRelease(context.Background(), srv.Client(), srv.URL, keyPEM, exp)
			if (err != nil) != tc.wantErr {
				t.Fatalf("attestCredentialRelease = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
