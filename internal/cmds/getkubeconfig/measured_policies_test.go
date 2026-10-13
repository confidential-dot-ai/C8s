package getkubeconfig

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
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
		return &policyList{fetch: func() []string { return policies }}
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

// A node that measures a policy between two gates passes the later gate: the
// stale cached list is refetched once it replays nothing, and a list that
// still replays is not fetched again.
func TestPolicyListRefetchesOnMiss(t *testing.T) {
	exp := testPolicy(t, operatorPub(t))
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	served := [][]string{{p}, {p, q}}
	fetches := 0
	exp.policies = &policyList{fetch: func() []string {
		list := served[min(fetches, len(served)-1)]
		fetches++
		return list
	}}
	for _, step := range []struct {
		measured    []string
		wantFetches int
	}{
		{measured: []string{p}, wantFetches: 1},
		{measured: []string{p, q}, wantFetches: 2},
		{measured: []string{p}, wantFetches: 2},
	} {
		res := verifiedResultFor(exp)
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), append(slices.Clone(exp.workloadDigests), step.measured...))
		res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
		if err := exp.checkIdentity(res); err != nil {
			t.Fatalf("checkIdentity(seed+%v) = %v, want nil", step.measured, err)
		}
		if fetches != step.wantFetches {
			t.Fatalf("after seed+%v: list fetched %d times, want %d", step.measured, fetches, step.wantFetches)
		}
	}
}

func TestFetchMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   []string
	}{
		{name: "list", status: http.StatusOK, body: `["` + p + `"]`, want: []string{p}},
		{name: "older node", status: http.StatusNotFound, body: "404 page not found"},
		{name: "malformed", status: http.StatusOK, body: `{"not":"a list"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != credrelease.MeasuredPoliciesPath || r.Method != http.MethodGet {
					t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, credrelease.MeasuredPoliciesPath)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			if got := fetchMeasuredPolicies(context.Background(), srv.URL, 5*time.Second); !slices.Equal(got, tc.want) {
				t.Fatalf("fetchMeasuredPolicies = %v, want %v", got, tc.want)
			}
		})
	}
}

// Run fetches the node's list from cred-release and releases only when a
// prefix of it replays the quote's RTMR[3].
func TestRunReplaysMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name    string
		served  string
		wantErr bool
	}{
		{name: "list replays", served: `["` + p + `","` + q + `"]`},
		{name: "list does not replay", served: `["` + q + `"]`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
			res := verifiedResultFor(env.exp)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.exp.operatorPubPEM), []string{p})
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			stubVerify(t, res, nil)

			var releaseHits, listHits atomic.Int32
			release := newAttestedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == credrelease.MeasuredPoliciesPath {
					listHits.Add(1)
					io.WriteString(w, tc.served)
					return
				}
				releaseHits.Add(1)
				releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
			}))
			t.Cleanup(release.Close)
			cfg := env.config()
			cfg.ReleaseBaseURL = release.URL

			err := Run(context.Background(), cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && releaseHits.Load() != 0 {
				t.Fatalf("cred-release hits = %d, want 0", releaseHits.Load())
			}
			if n := listHits.Load(); !tc.wantErr && n != 1 {
				t.Fatalf("%s fetched %d times, want once while it replays", credrelease.MeasuredPoliciesPath, n)
			}
		})
	}
}
