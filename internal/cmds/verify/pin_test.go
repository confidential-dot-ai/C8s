package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func signRolloutState(t *testing.T, key *ecdsa.PrivateKey, st types.RolloutState) *types.SignedRolloutState {
	t.Helper()
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(body)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return &types.SignedRolloutState{State: body, Signature: sig}
}

func TestVerifyRolloutState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{PublicKey: &key.PublicKey}
	nonce := []byte{1, 2, 3}

	for _, tc := range []struct {
		name   string
		signer *ecdsa.PrivateKey
		nonce  string
		want   string
	}{
		{"valid", key, hex.EncodeToString(nonce), ""},
		{"foreign signer", other, hex.EncodeToString(nonce), "signature"},
		{"other nonce", key, "ff", "nonce"},
	} {
		signed := signRolloutState(t, tc.signer, types.RolloutState{Bound: []string{"sha256:p"}, Nonce: tc.nonce})
		_, err := verifyRolloutState(signed, ca, nonce)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: verifyRolloutState = %v, want error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestApplyPinPolicy(t *testing.T) {
	state := &types.RolloutState{Bound: []string{"sha256:p", "sha256:q"}, Lease: 30}
	pins := []string{"sha256:p", "sha256:q"}
	for _, tc := range []struct {
		name string
		pins []string
		ev   evidence
		want string
	}{
		{"bound inside pins", pins, evidence{fresh: true, rollout: state}, ""},
		{"unpinned policy", pins[:1], evidence{fresh: true, rollout: state}, "policy_not_pinned: policy sha256:q"},
		{"no state", pins, evidence{fresh: true}, "pinned_state_absent"},
		{"invalid state", pins, evidence{fresh: true, rolloutErr: errSandboxTest}, "pinned_state_invalid"},
		{"offline bundle", pins, evidence{rollout: state}, "pinned_state_stale"},
		{"no lease", pins, evidence{fresh: true, rollout: &types.RolloutState{Bound: pins}}, "pinned_state_unleased"},
		{"no pins", nil, evidence{}, ""},
	} {
		oc := Outcome{Verified: true}
		applyPinPolicy(&oc, config{pinPolicies: tc.pins}, &tc.ev)
		if (tc.want == "") != oc.Verified || !strings.Contains(oc.Error, tc.want) {
			t.Errorf("%s: verified=%v error=%q, want error containing %q", tc.name, oc.Verified, oc.Error, tc.want)
		}
	}
}

func TestBuildPolicyPinPolicyFormat(t *testing.T) {
	if _, err := buildPolicy(config{pinPolicies: []string{"sha256:p"}}); err == nil || !strings.Contains(err.Error(), "is not sha256:") {
		t.Fatalf("buildPolicy(malformed --pin-policy) = %v, want the format error", err)
	}
	if _, err := buildPolicy(config{pinPolicies: []string{"sha256:" + strings.Repeat("ab", 32)}}); err != nil {
		t.Fatalf("buildPolicy(--pin-policy without --mesh-ca) = %v, want it accepted", err)
	}
}

func TestApplyPinPolicyHidesStaleBound(t *testing.T) {
	oc := Outcome{Verified: true}
	applyPinPolicy(&oc, config{}, &evidence{rollout: &types.RolloutState{Bound: []string{"sha256:p"}}})
	if oc.AllowlistBound != nil {
		t.Fatalf("offline bundle reported bound %v, want none", oc.AllowlistBound)
	}
}

func TestFetchAllowlists(t *testing.T) {
	policy := []byte(`{"schema":"x","workloads":{}}`)
	sum := sha256.Sum256(policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/c8s/objects/sha256/"+hex.EncodeToString(sum[:]) {
			w.Write(policy)
			return
		}
		w.Write([]byte("tampered"))
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name  string
		bound []string
		want  string
	}{
		{"attested bytes", []string{digest}, ""},
		{"bytes that do not match the digest", []string{"sha256:" + strings.Repeat("00", 32)}, "allowlist_digest_mismatch"},
		{"no attested state", nil, "allowlist_fetch_failed"},
	} {
		dir := t.TempDir()
		oc := Outcome{Verified: true, AllowlistBound: tc.bound}
		fetchAllowlists(context.Background(), config{url: srv.URL, fetchAllowlists: dir, timeout: 5 * time.Second}, &oc)
		if (tc.want == "") != oc.Verified || !strings.Contains(oc.Error, tc.want) {
			t.Errorf("%s: verified=%v error=%q, want %q", tc.name, oc.Verified, oc.Error, tc.want)
		}
		if tc.want == "" {
			got, err := os.ReadFile(filepath.Join(dir, hex.EncodeToString(sum[:])+".json"))
			if err != nil || string(got) != string(policy) {
				t.Errorf("%s: wrote %q (%v), want the policy bytes", tc.name, got, err)
			}
		}
	}
}
