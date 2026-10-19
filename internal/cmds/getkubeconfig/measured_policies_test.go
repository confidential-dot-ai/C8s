package getkubeconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
		name        string
		noWorkloads bool     // the quote lacks the workload chain
		measured    []string // extended after the workloads in the quote
		policies    *policyList
		wantErr     bool
	}{
		{name: "no policies measured, no list", wantErr: false},
		{name: "no policies measured, list ahead", policies: quote(p)},
		{name: "list matches", measured: []string{p, q}, policies: quote(p, q)},
		{name: "list ahead of the quote", measured: []string{p}, policies: quote(p, q)},
		{name: "list does not replay", measured: []string{p}, policies: quote(q), wantErr: true},
		{name: "measured without a list", measured: []string{p}, wantErr: true},
		{name: "measured, empty list", measured: []string{p}, policies: quote(), wantErr: true},
		{name: "replaying list over the cap", measured: []string{p}, policies: quote(overCap...), wantErr: true},
		{name: "non-canonical entry", measured: []string{p}, policies: quote(strings.ToUpper(p)), wantErr: true},
		{name: "invalid entry past the replaying prefix", measured: []string{p}, policies: quote(p, "not-a-digest"), wantErr: true},
		{name: "workload chain missing", noWorkloads: true, measured: []string{p}, policies: quote(p), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := verifiedResultFor(exp)
			extended := tc.measured
			if !tc.noWorkloads {
				extended = append(slices.Clone(exp.workloadDigests), tc.measured...)
			}
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), extended)
			res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			e := exp
			e.policies = tc.policies
			err := e.checkIdentity(res)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkIdentity = %v, want error %v", err, tc.wantErr)
			}
			// Only Run knows where the list came from, so the error gives no advice.
			if err != nil && strings.Contains(err.Error(), "--attest-url") {
				t.Errorf("checkIdentity = %v, want no advice about --attest-url", err)
			}
		})
	}
}

// Run takes the node's list from the verified cred-release leaf and releases
// only when a prefix of it replays the quote's RTMR[3]. A failure names its
// cause: a dial that recorded no list, or a list older than the fresh quote.
func TestRunReplaysMeasuredPolicies(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct {
		name     string
		leaf     []string
		fresh    []string // measured in the /attest quote; the leaf's quote holds p
		noServer bool     // cred-release refuses the dial
		wantErr  string
	}{
		{name: "leaf list replays", leaf: []string{p, q}, fresh: []string{p}},
		{name: "leaf list does not replay its own quote", leaf: []string{q}, fresh: []string{p}, wantErr: "dial to cred-release failed"},
		{name: "leaf carries no list", fresh: []string{p}, wantErr: "dial to cred-release failed"},
		{name: "cred-release unreachable", noServer: true, fresh: []string{p}, wantErr: "dial to cred-release failed"},
		{name: "leaf list predates the fresh quote", leaf: []string{p}, fresh: []string{p, q}, wantErr: "may predate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
			quote := func(measured []string) *teetypes.VerificationResult {
				res := verifiedResultFor(env.exp)
				reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.exp.operatorPubPEM), measured)
				res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
				return res
			}
			leafQuote, freshQuote := quote([]string{p}), quote(tc.fresh)
			orig := verifyEnvelope
			t.Cleanup(func() { verifyEnvelope = orig })
			var calls atomic.Int32
			verifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
				// Run verifies the pre-dial leaf, then the fresh quote.
				if calls.Add(1) == 2 {
					return freshQuote, nil
				}
				return leafQuote, nil
			}

			var releaseHits atomic.Int32
			release := newAttestedTLSServerWithExtensions(t, teetypes.PlatformTDX, tc.leaf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				releaseHits.Add(1)
				releaseHandler(t, http.StatusOK, goodRelease, nil).ServeHTTP(w, r)
			}))
			cfg := env.config()
			cfg.ReleaseBaseURL = release.URL
			if tc.noServer {
				release.Close()
			}

			err := Run(context.Background(), cfg)
			if (err != nil) != (tc.wantErr != "") || err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Run = %v, want error containing %q", err, tc.wantErr)
			}
			if err != nil && releaseHits.Load() != 0 {
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

// A refused pre-dial is retried within --release-wait, so a cred-release that
// starts late still supplies its list.
func TestDialReleaseRetriesRefusal(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	env := newTestEnv(t, "", http.StatusOK, goodRelease)
	res := verifiedResultFor(env.exp)
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.exp.operatorPubPEM), []string{p})
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
	stubVerify(t, res, nil)

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	reserved.Close()
	release := unstartedAttestedTLSServer(t, teetypes.PlatformTDX, []string{p}, http.NotFoundHandler())
	const delay = 300 * time.Millisecond
	started := make(chan error, 1)
	go func() {
		time.Sleep(delay) // the first dial, at once, is refused
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			release.Listener = ln
			release.StartTLS()
		}
		started <- err
	}()
	t.Cleanup(func() { <-started })

	exp := env.exp
	exp.policies = &policyList{}
	begin := time.Now()
	err = dialRelease(context.Background(), Config{Timeout: 5 * time.Second, ReleaseWait: 10 * time.Second}, &url.URL{Scheme: "https", Host: addr}, exp)
	if err != nil {
		t.Fatalf("dialRelease = %v, want nil", err)
	}
	if elapsed := time.Since(begin); elapsed < delay {
		t.Errorf("dialRelease returned after %v, before cred-release started at %v", elapsed, delay)
	}
	if got := exp.policies.current(); !slices.Equal(got, []string{p}) {
		t.Errorf("recorded list = %v, want %v", got, []string{p})
	}
}

// With --attest-url the pre-dial and the release step share one
// --release-wait, so a node that measured nothing and a cred-release that
// never answers cost one wait, not two.
func TestRunAttestURLSharesReleaseWait(t *testing.T) {
	env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
	stubVerify(t, verifiedResultFor(env.exp), nil)
	closed := newAttestedTLSServer(t, http.NotFoundHandler())
	closed.Close()
	cfg := env.config()
	cfg.ReleaseBaseURL = closed.URL
	cfg.ReleaseWait = 6 * time.Second // past one 5s retry interval

	begin := time.Now()
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "credential release") {
		t.Fatalf("Run = %v, want the credential release to fail", err)
	}
	if elapsed := time.Since(begin); elapsed > cfg.ReleaseWait+2*time.Second {
		t.Errorf("Run took %v, want about one --release-wait of %v", elapsed, cfg.ReleaseWait)
	}
}
