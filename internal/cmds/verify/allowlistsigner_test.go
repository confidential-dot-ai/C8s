package verify

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestCheckAllowlistSigner(t *testing.T) {
	v := loadSignatureVector(t)
	sum := sha256.Sum256(v.Policy)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keysPath, []byte(v.KeysPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM([]byte(v.KeysPEM))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keyFingerprint(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	otherP384, _, _ := operatorKeypair(t)
	otherP256 := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherP256, approverKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	other := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"x":{}}}`)
	otherSum := sha256.Sum256(other)

	leaf := &x509.Certificate{}
	stamped := func(d [32]byte) *evidence {
		return &evidence{leaf: leaf, workload: &armtls.MatchedWorkload{AllowlistDigest: d[:]}}
	}
	signed := objectServer(digest, v.Policy, v.Token)
	for _, tc := range []struct {
		name        string
		handler     http.Handler
		ev          *evidence
		pins        []string
		meshCA      string
		wantErr     string
		wantPartial bool
	}{
		{"pem", signed, stamped(sum), []string{keysPath}, "mesh-ca.pem", "", false},
		{"pem, unvouched stamp", signed, stamped(sum), []string{keysPath}, "", "", true},
		{"one of several", signed, stamped(sum), []string{otherP256, keysPath}, "mesh-ca.pem", "", false},
		{"other P-256 key", signed, stamped(sum), []string{otherP256}, "mesh-ca.pem", "allowlist_signer_not_pinned: the leaf's allowlist " + digest, false},
		{"other P-384 key", signed, stamped(sum), []string{otherP384}, "mesh-ca.pem", "allowlist_signer_not_pinned", false},
		{"token for another document", objectServer("sha256:"+hex.EncodeToString(otherSum[:]), other, v.Token), stamped(otherSum), []string{keysPath}, "mesh-ca.pem", "allowlist_signature_invalid", false},
		{"malformed token", objectServer(digest, v.Policy, "not-a-token"), stamped(sum), []string{keysPath}, "mesh-ca.pem", "allowlist_signature_invalid", false},
		{"unsigned", objectServer(digest, v.Policy, ""), stamped(sum), []string{keysPath}, "mesh-ca.pem", "allowlist_unsigned: the leaf's allowlist " + digest, false},
		{"signature unavailable", signatureFails(signed), stamped(sum), []string{keysPath}, "mesh-ca.pem", "allowlist_fetch_failed: fetch the signature of " + digest + ": status 502", false},
		{"unknown object", objectServer(testPolicyP, v.Policy, v.Token), stamped(sum), []string{keysPath}, "mesh-ca.pem", "allowlist_fetch_failed: fetch " + digest, false},
		{"tampered object", objectServer(digest, append([]byte(" "), v.Policy...), v.Token), stamped(sum), []string{keysPath}, "mesh-ca.pem", "allowlist_digest_mismatch", false},
		{"unstamped leaf", signed, &evidence{leaf: leaf}, []string{keysPath}, "mesh-ca.pem", "", true},
		{"unreadable stamp", signed, &evidence{leaf: leaf, workloadErr: errors.New("bad stamp")}, []string{keysPath}, "mesh-ca.pem", "allowlist_unstamped: the leaf's issuing policy cannot be read: bad stamp", false},
		{"no leaf", signed, &evidence{}, []string{keysPath}, "mesh-ca.pem", "allowlist_unstamped", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			cfg := config{url: srv.URL, allowlistSigner: tc.pins, timeout: 5 * time.Second}
			pinned, err := parseSignerPins(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cfg.meshCA = tc.meshCA
			oc := Outcome{Verified: true}
			if checkAllowlistSigner(context.Background(), &oc, cfg, tc.ev, pinned) {
				t.Fatal("reported the target unreachable")
			}
			if passed := oc.Verified || oc.Partial; passed != (tc.wantErr == "") || !strings.Contains(oc.Error, tc.wantErr) {
				t.Fatalf("passed %v, error %q; want error containing %q", passed, oc.Error, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if oc.Partial != tc.wantPartial {
				t.Errorf("partial %v (not proven %v), want %v", oc.Partial, oc.NotProven, tc.wantPartial)
			}
			if wantSigner := tc.ev.workload != nil; (oc.AllowlistSigner == signer) != wantSigner {
				t.Errorf("AllowlistSigner = %q, want %q: %v", oc.AllowlistSigner, signer, wantSigner)
			}
		})
	}
}

func TestCheckAllowlistSignerUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	keyPath, _, _ := operatorKeypair(t)
	cfg := config{url: url, allowlistSigner: []string{keyPath}, timeout: time.Second}
	keys, err := parseSignerPins(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	oc := Outcome{Verified: true}
	ev := &evidence{leaf: &x509.Certificate{}, workload: &armtls.MatchedWorkload{AllowlistDigest: sum[:]}}
	if !checkAllowlistSigner(context.Background(), &oc, cfg, ev, keys) || !strings.HasPrefix(oc.Error, "allowlist_fetch_failed") {
		t.Errorf("unreachable target: error %q, want allowlist_fetch_failed reported unreachable", oc.Error)
	}
}

func TestParseSignerPins(t *testing.T) {
	keyPath, keyPaths, _ := operatorKeypair(t)
	for _, tc := range []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{"unset", config{}, ""},
		{"two files", config{url: "https://x", allowlistSigner: []string{keyPath, keyPath}}, ""},
		{"no target", config{fromFile: "ev.json", allowlistSigner: []string{keyPath}}, "--allowlist-signer needs a live target"},
		{"missing file", config{url: "https://x", allowlistSigner: []string{"nope.pem"}}, "read --allowlist-signer"},
		{"private key", config{url: "https://x", allowlistSigner: []string{keyPaths[0]}}, "no PEM PUBLIC KEY block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSignerPins(tc.cfg)
			if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("parseSignerPins = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
