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
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
)

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
				res := verifiedResultFor(env.operatorPubPEM)
				reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.operatorPubPEM), measured)
				res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
				return res
			}
			leafQuote, freshQuote := quote([]string{p}), quote(tc.fresh)
			orig := guestverify.VerifyEnvelope
			t.Cleanup(func() { guestverify.VerifyEnvelope = orig })
			var calls atomic.Int32
			guestverify.VerifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
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
			res := verifiedResultFor(env.operatorPubPEM)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.operatorPubPEM), []string{p, q})
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
			exp = exp.WithMeasuredPolicies([]string{p}) // the leaf predates q

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
	res := verifiedResultFor(env.operatorPubPEM)
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(env.operatorPubPEM), []string{p})
	res.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
	stubVerify(t, res, nil)

	release := newAttestedTLSServerWithExtensions(t, teetypes.PlatformTDX, []string{p}, http.NotFoundHandler())
	releaseURL, err := url.Parse(release.URL)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	next := retryRefused
	t.Cleanup(func() { retryRefused = next })
	retryRefused = func(ctx context.Context, timeout, wait time.Duration, operation func(context.Context) error) error {
		return next(ctx, timeout, wait, func(stepCtx context.Context) error {
			attempts++
			if attempts == 1 { // cred-release is not listening yet
				return refusedDial(releaseURL)
			}
			return operation(stepCtx)
		})
	}

	exp := env.exp
	exp = exp.WithMeasuredPolicies(nil)
	if err := dialRelease(context.Background(), Config{Timeout: 5 * time.Second, ReleaseWait: 10 * time.Second}, releaseURL, exp); err != nil {
		t.Fatalf("dialRelease = %v, want nil", err)
	}
	if attempts != 2 {
		t.Errorf("dialRelease made %d attempts, want 2", attempts)
	}
	if got := exp.MeasuredPolicies(); !slices.Equal(got, []string{p}) {
		t.Errorf("recorded list = %v, want %v", got, []string{p})
	}
}

// With --attest-url the pre-dial and the release step share one
// --release-wait, so a node that measured nothing and a cred-release that
// never answers cost one wait, not two.
func TestRunAttestURLSharesReleaseWait(t *testing.T) {
	env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)
	stubVerify(t, verifiedResultFor(env.operatorPubPEM), nil)
	cfg := env.config()
	cfg.ReleaseWait = 100 * time.Millisecond
	releaseURL, err := url.Parse(cfg.ReleaseBaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	next := retryRefused
	t.Cleanup(func() { retryRefused = next })
	retryRefused = func(ctx context.Context, timeout, wait time.Duration, _ func(context.Context) error) error {
		waits = append(waits, wait)
		return next(ctx, timeout, wait, func(context.Context) error { return refusedDial(releaseURL) })
	}

	err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "credential release") {
		t.Fatalf("Run = %v, want the credential release to fail", err)
	}
	// The pre-dial spends the whole wait, so the release step gets none.
	if want := []time.Duration{cfg.ReleaseWait, 0}; !slices.Equal(waits, want) {
		t.Errorf("cred-release retry budgets = %v, want %v", waits, want)
	}
}

// refusedDial is the error a dial to a cred-release that is not listening
// returns.
func refusedDial(u *url.URL) error {
	return &url.Error{Op: "Dial", URL: u.String(), Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
}
