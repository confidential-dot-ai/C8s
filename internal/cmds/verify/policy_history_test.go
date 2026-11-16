package verify

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// historyKeysFile writes the keys --trust-operator-keys reads.
func historyKeysFile(t *testing.T, keysPEM string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, []byte(keysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// countingObjects serves h and counts the requests it answered per path.
func countingObjects(h http.Handler) (*httptest.Server, func() map[string]int) {
	var mu sync.Mutex
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(counts)
	}
}

// A token that verifies over another policy's bytes signs neither policy.
func TestTrustOperatorCrossSignedHistory(t *testing.T) {
	v := loadSignatureVector(t)
	signedSum := sha256.Sum256(v.Policy)
	crossBody := []byte(`{"version":"2"}`)
	crossSum := sha256.Sum256(crossBody)
	signed, cross := "sha256:"+hex.EncodeToString(signedSum[:]), "sha256:"+hex.EncodeToString(crossSum[:])
	signedObjects := objectServer(signed, v.Policy, v.Token)
	crossObjects := objectServer(cross, crossBody, v.Token)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, hex.EncodeToString(signedSum[:])) {
			signedObjects.ServeHTTP(w, r)
			return
		}
		crossObjects.ServeHTTP(w, r)
	}))
	defer srv.Close()
	keysPath := historyKeysFile(t, v.KeysPEM)
	for _, tc := range []struct {
		name    string
		history []string
	}{
		{"cross-signed first", []string{cross, signed}},
		{"cross-signed second", []string{signed, cross}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: keysPath, timeout: 5 * time.Second}
			plan, _ := historyPlan(t, cfg)
			oc := Outcome{Partial: true, MeasuredPolicies: tc.history}
			unreachable := checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
			want := "policy_history_unsigned: policy " + cross + ":"
			if oc.Verified || oc.Partial || unreachable || !strings.Contains(oc.Error, want) {
				t.Errorf("checkPolicyHistory = partial %v, unreachable %v, error %q; want error containing %q", oc.Partial, unreachable, oc.Error, want)
			}
		})
	}
}

// A signature the target never answers is an unreachable target, not an unsigned policy.
func TestTrustOperatorSignatureUnreachable(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	objects := objectServer(digest, v.Policy, v.Token)
	keysPath := historyKeysFile(t, v.KeysPEM)
	for _, tc := range []struct {
		name      string
		signature http.HandlerFunc
	}{
		{"hangs past the timeout", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }},
		{"connection dropped", dropConnection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/signature") {
					tc.signature(w, r)
					return
				}
				objects.ServeHTTP(w, r)
			}))
			defer srv.Close()
			cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: keysPath, timeout: 100 * time.Millisecond}
			plan, _ := historyPlan(t, cfg)
			oc := Outcome{Verified: true, MeasuredPolicies: []string{digest}}
			unreachable := checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
			want := "policy_history_unsigned: fetch the signature of " + digest
			if !unreachable || oc.Verified || oc.Partial || !strings.Contains(oc.Error, want) {
				t.Errorf("checkPolicyHistory = unreachable %v, verified %v, error %q; want an unreachable failure containing %q", unreachable, oc.Verified, oc.Error, want)
			}
		})
	}
}

// dropConnection answers nothing and hangs up, as a target that went away.
func dropConnection(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	conn.Close()
}

// A --fetch-allowlists directory that cannot be created fails as a fetch.
func TestTrustOperatorAllowlistDirUnusable(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	srv, counts := countingObjects(objectServer(digest, v.Policy, v.Token))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "policies")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: historyKeysFile(t, v.KeysPEM)}
	cfg.fetchAllowlists, cfg.timeout = filepath.Join(file, "under"), 5*time.Second
	plan, _ := historyPlan(t, cfg)
	oc := Outcome{Verified: true, MeasuredPolicies: []string{digest}}
	unreachable := checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
	if oc.Verified || oc.Partial || unreachable || !strings.HasPrefix(oc.Error, "allowlist_fetch_failed") {
		t.Errorf("checkPolicyHistory = verified %v, unreachable %v, error %q; want a failure starting allowlist_fetch_failed", oc.Verified, unreachable, oc.Error)
	}
	if got := counts(); len(got) != 0 {
		t.Errorf("requests = %v, want none", got)
	}
}

// A verdict that already failed keeps its error and reaches no target.
func TestPolicyHistorySkipsFailedVerdict(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	srv, counts := countingObjects(objectServer(digest, v.Policy, v.Token))
	defer srv.Close()
	cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: historyKeysFile(t, v.KeysPEM)}
	cfg.fetchAllowlists, cfg.timeout = filepath.Join(t.TempDir(), "policies"), 5*time.Second
	plan, _ := historyPlan(t, cfg)
	const earlier = "measurement_mismatch: the node served another image"
	oc := Outcome{Error: earlier, MeasuredPolicies: []string{digest}}
	unreachable := checkPolicyHistory(context.Background(), &oc, cfg, &evidence{}, plan.trustKeys)
	if unreachable || oc.Verified || oc.Partial || oc.Error != earlier {
		t.Errorf("checkPolicyHistory = unreachable %v, verified %v, error %q; want %q kept", unreachable, oc.Verified, oc.Error, earlier)
	}
	if got := counts(); len(got) != 0 {
		t.Errorf("requests = %v, want none", got)
	}
}

// The leaf's policy is already in the history, so it is not fetched twice.
func TestTrustOperatorFetchesEachPolicyOnce(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	object := "/allowlist/objects/sha256/" + hex.EncodeToString(sum[:])
	srv, counts := countingObjects(objectServer(digest, v.Policy, v.Token))
	defer srv.Close()
	cfg := config{url: srv.URL, trustOperator: true, trustOperatorKeys: historyKeysFile(t, v.KeysPEM), timeout: 5 * time.Second}
	plan, _ := historyPlan(t, cfg)
	cfg.meshCA = "mesh-ca.pem"
	ev := &evidence{fresh: true, leaf: &x509.Certificate{}, workload: &armtls.MatchedWorkload{AllowlistDigest: sum[:]}}
	oc := Outcome{Verified: true, MeasuredPolicies: []string{digest}}
	checkPolicyHistory(context.Background(), &oc, cfg, ev, plan.trustKeys)
	if !oc.Verified || oc.Error != "" {
		t.Fatalf("checkPolicyHistory = verified %v, error %q; want a verified verdict", oc.Verified, oc.Error)
	}
	want := map[string]int{object: 1, object + "/signature": 1}
	if got := counts(); !maps.Equal(got, want) {
		t.Errorf("requests = %v, want %v", got, want)
	}
}
