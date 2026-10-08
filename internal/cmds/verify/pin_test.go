package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func signRolloutState(t *testing.T, key *ecdsa.PrivateKey, st types.RolloutState) *types.SignedRolloutState {
	t.Helper()
	if st.IssuedAt == 0 && st.ExpiresAt == 0 {
		rolloutstate.Stamp(&st, time.Now())
	}
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rolloutstate.Sign(key, rolloutstate.ContextChallenge, body)
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

	expired := time.Now().Add(-rolloutstate.Validity - rolloutstate.MaxClockSkew - time.Minute)
	for _, tc := range []struct {
		name   string
		signer *ecdsa.PrivateKey
		nonce  string
		issued time.Time
		live   bool
		want   string
	}{
		{"valid", key, hex.EncodeToString(nonce), time.Time{}, true, ""},
		{"foreign signer", other, hex.EncodeToString(nonce), time.Time{}, true, "signature"},
		{"other nonce", key, "ff", time.Time{}, true, "nonce"},
		{"expired live state", key, hex.EncodeToString(nonce), expired, true, "expired"},
		{"expired saved bundle", key, hex.EncodeToString(nonce), expired, false, ""},
	} {
		st := types.RolloutState{Bound: []string{"sha256:p"}, Nonce: tc.nonce}
		if !tc.issued.IsZero() {
			rolloutstate.Stamp(&st, tc.issued)
		}
		signed := signRolloutState(t, tc.signer, st)
		_, err := verifyRolloutState(signed, ca, nonce, tc.live)
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
	if _, err := buildPolicy(config{pinPolicies: []string{"sha256:" + strings.Repeat("ab", 32)}}); err == nil || !strings.Contains(err.Error(), "--pin-policy requires --mesh-ca") {
		t.Fatalf("buildPolicy(--pin-policy without --mesh-ca) = %v, want the --mesh-ca error", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mesh CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPolicy(config{pinPolicies: []string{"sha256:" + strings.Repeat("ab", 32)}, meshCA: caFile}); err != nil {
		t.Fatalf("buildPolicy(--pin-policy with --mesh-ca) = %v, want it accepted", err)
	}
	pubPath, _, _ := operatorKeypair(t)
	baked := config{pinPolicies: []string{"sha256:" + strings.Repeat("ab", 32)}, imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
	if _, err := buildPolicy(baked); err != nil {
		t.Fatalf("buildPolicy(--pin-policy with a pinned baked node) = %v, want it accepted", err)
	}
	baked.operatorPubkey = ""
	if _, err := buildPolicy(baked); err == nil || !strings.Contains(err.Error(), "--pin-policy requires --mesh-ca") {
		t.Fatalf("buildPolicy(--pin-policy with an image pin but no RTMR[3]) = %v, want the --mesh-ca error", err)
	}
}

func TestApplyPinPolicyReportsVerifiedState(t *testing.T) {
	oc := Outcome{Verified: true}
	applyPinPolicy(&oc, config{}, &evidence{fresh: true, rollout: &types.RolloutState{Head: "sha256:h", Bound: []string{"sha256:p"}}})
	if oc.VerifiedState != "sha256:h" {
		t.Fatalf("verified state = %q, want the journal head sha256:h", oc.VerifiedState)
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
		{"malformed digest", []string{"sha256:../../etc"}, "malformed digest"},
	} {
		dir := t.TempDir()
		oc := Outcome{Partial: true, AllowlistBound: tc.bound}
		fetchAllowlists(context.Background(), config{url: srv.URL, fetchAllowlists: dir, timeout: 5 * time.Second}, &oc)
		if (tc.want == "") != (oc.Error == "") || !strings.Contains(oc.Error, tc.want) {
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
