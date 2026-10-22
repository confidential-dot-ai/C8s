package verify

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// seedTarget serves a signed history policy, an unsigned seed, and names
// named in the seed header of GET /allowlist, over TLS.
func seedTarget(t *testing.T, signed string, signedBody []byte, token, seed string, seedBody []byte, named string) (*httptest.Server, string) {
	t.Helper()
	signedObjects := objectServer(signed, signedBody, token)
	seedObjects := objectServer(seed, seedBody, "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/allowlist":
			if named != "" {
				w.Header().Set(pkgallowlist.SeedHeader, named)
			}
			w.Write(signedBody)
		case strings.Contains(r.URL.Path, strings.TrimPrefix(signed, "sha256:")):
			signedObjects.ServeHTTP(w, r)
		default:
			seedObjects.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv, hex.EncodeToString(sum[:])
}

// --trust-operator accepts a leaf stamped with the seed the target names over
// the attested channel, and nothing else unsigned: not a seed the target does
// not name, not one named without an attested channel, and never a policy in
// the replayed history.
func TestTrustOperatorSeedStamp(t *testing.T) {
	v := loadSignatureVector(t)
	signedSum := sha256.Sum256(v.Policy)
	signed := "sha256:" + hex.EncodeToString(signedSum[:])
	seedBody := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"seed":{}}}`)
	seedSum := sha256.Sum256(seedBody)
	seed := "sha256:" + hex.EncodeToString(seedSum[:])
	other := "sha256:" + strings.Repeat("ab", 32)
	keysPath := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		named    string
		attested bool
		history  []string
		wantErr  string
	}{
		{name: "named seed", named: seed, attested: true, history: []string{signed}},
		{name: "other seed named", named: other, attested: true, history: []string{signed}, wantErr: "the target names seed " + other},
		{name: "no seed named", attested: true, history: []string{signed}, wantErr: "the target names no seed"},
		{name: "no attested channel", named: seed, history: []string{signed}, wantErr: "could not be authenticated"},
		{name: "seed in the history", named: seed, attested: true, history: []string{signed, seed}, wantErr: "policy " + seed + " carries no operator signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, certSHA := seedTarget(t, signed, v.Policy, v.Token, seed, seedBody, tc.named)
			ev := &evidence{fresh: true, leaf: &x509.Certificate{}, workload: &armtls.MatchedWorkload{AllowlistDigest: seedSum[:]}}
			if tc.attested {
				ev.certSHA256 = certSHA
			}
			cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: keysPath, timeout: 5 * time.Second}
			plan, _ := historyPlan(t, cfg)
			cfg.meshCA = "mesh-ca.pem"
			oc := Outcome{Verified: true, MeasuredPolicies: tc.history}
			checkPolicyHistory(context.Background(), &oc, cfg, ev, plan.trustKeys)
			if tc.wantErr == "" {
				if !oc.Verified || oc.LeafPolicySeed != seed {
					t.Fatalf("verdict = verified %v, error %q, leaf seed %q; want verified with leaf seed %s", oc.Verified, oc.Error, oc.LeafPolicySeed, seed)
				}
				return
			}
			if oc.Verified || oc.Partial || !strings.Contains(oc.Error, tc.wantErr) || oc.LeafPolicySeed != "" {
				t.Errorf("verdict = verified %v, partial %v, error %q, leaf seed %q; want error containing %q", oc.Verified, oc.Partial, oc.Error, oc.LeafPolicySeed, tc.wantErr)
			}
		})
	}
}

// --pin-policy does not accept the seed, but names it so it can be pinned.
func TestPinPolicyNamesSeed(t *testing.T) {
	seedSum := sha256.Sum256([]byte("seed"))
	seed := "sha256:" + hex.EncodeToString(seedSum[:])
	srv, certSHA := seedTarget(t, testPolicyP, nil, "", seed, nil, seed)
	ev := &evidence{fresh: true, leaf: &x509.Certificate{}, workload: &armtls.MatchedWorkload{AllowlistDigest: seedSum[:]}, certSHA256: certSHA}
	cfg := config{url: srv.URL, pinPolicies: []string{testPolicyP}, meshCA: "mesh-ca.pem", timeout: 5 * time.Second}
	oc := Outcome{Verified: true, MeasuredPolicies: []string{testPolicyP}}
	applyPinPolicy(context.Background(), &oc, cfg, ev)
	if oc.Verified || !strings.Contains(oc.Error, "policy_history_not_pinned") || !strings.Contains(oc.Error, "allowlist seed: pin it") {
		t.Errorf("verdict = verified %v, error %q; want policy_history_not_pinned naming the seed", oc.Verified, oc.Error)
	}
}
