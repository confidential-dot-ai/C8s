package getkubeconfig

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := verifiedResultFor(exp)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), append(slices.Clone(exp.workloadDigests), tc.measured...))
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			e := exp
			e.policies = tc.policies
			if err := e.checkIdentity(res); (err != nil) != tc.wantErr {
				t.Fatalf("checkIdentity = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// A node whose list no leaf has recorded yet, or that measured a policy since
// the last verified leaf, passes once a refresh records a list that replays;
// a list that still replays is not refreshed.
func TestPolicyListRefreshesOnMiss(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	leaves := [][]string{{p}, {p, q}}
	refreshes := 0
	exp.policies = &policyList{}
	exp.policies.refresh = func() {
		exp.policies.record(leaves[min(refreshes, len(leaves)-1)])
		refreshes++
	}
	for _, step := range []struct {
		measured      []string
		wantRefreshes int
	}{
		{measured: []string{p}, wantRefreshes: 1},
		{measured: []string{p, q}, wantRefreshes: 2},
		{measured: []string{p}, wantRefreshes: 2},
	} {
		res := verifiedResultFor(exp)
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), append(slices.Clone(exp.workloadDigests), step.measured...))
		res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
		if err := exp.checkIdentity(res); err != nil {
			t.Fatalf("checkIdentity(seed+%v) = %v, want nil", step.measured, err)
		}
		if refreshes != step.wantRefreshes {
			t.Fatalf("after seed+%v: list refreshed %d times, want %d", step.measured, refreshes, step.wantRefreshes)
		}
	}
}

// Run takes the node's list from the verified cred-release leaf and releases
// only when a prefix of it replays the quote's RTMR[3]. A list the host serves
// over HTTP is never consulted.
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

			var releaseHits, listHits atomic.Int32
			release := newAttestedTLSServerWithExtensions(t, teetypes.PlatformTDX, tc.leaf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/measured-policies" {
					listHits.Add(1)
					io.WriteString(w, `["`+p+`"]`) // would replay
					return
				}
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
			if n := listHits.Load(); n != 0 {
				t.Fatalf("host-served list fetched %d times, want 0", n)
			}
		})
	}
}
