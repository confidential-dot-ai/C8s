package cds

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/shamir"
)

func TestRecoveryKeySplitAndCombine(t *testing.T) {
	key, _ := testKeyPEM(t)
	keyFile := writeKey(t, key)
	out := filepath.Join(t.TempDir(), "shares")
	cmd := newHARecoveryKeyCmd()
	cmd.SetArgs([]string{"split", "--recovery-key", keyFile, "--out", out, "--shares", "5", "--threshold", "3"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	share := func(x int) string { return filepath.Join(out, "share-"+string(rune('0'+x))+".json") }
	got, err := loadRecoveryKey("", []string{share(5), share(2), share(4)})
	if err != nil || !got.Equal(key) {
		t.Fatalf("three shares: %v", err)
	}
	if _, err := loadRecoveryKey("", []string{share(1), share(2)}); err == nil || !strings.Contains(err.Error(), "the key needs 3") {
		t.Fatalf("two of three: %v", err)
	}
	if k, err := loadRecoveryKey(keyFile, nil); err != nil || !k.Equal(key) {
		t.Fatalf("key file: %v", err)
	}
	// Shares of another key, or a damaged share, are caught.
	other, _ := testKeyPEM(t)
	o, _ := SplitRecoveryKey(other, 3, 2)
	mine, _ := loadRecoveryShares([]string{share(1), share(2), share(3)})
	if _, err := CombineRecoveryKey([]RecoveryKeyShare{mine[0], o[1], mine[2]}); err == nil || !strings.Contains(err.Error(), "different recovery keys") {
		t.Fatalf("mixed keys: %v", err)
	}
	mine[1].Y[3] ^= 1
	if _, err := CombineRecoveryKey(mine); err == nil {
		t.Fatal("a damaged share rebuilt a key")
	}
	mine[0].Kind = "x"
	if _, err := CombineRecoveryKey(mine); err == nil {
		t.Fatal("not a share accepted")
	}
	if _, err := CombineRecoveryKey(nil); err == nil {
		t.Fatal("no shares accepted")
	}
	// Splitting again into the same directory does not overwrite shares.
	cmd = newHARecoveryKeyCmd()
	cmd.SetArgs([]string{"split", "--recovery-key", keyFile, "--out", out})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("overwrote existing shares")
	}
}

// Shares that rebuild a non-EC key, a key other than the one they name, or
// that repeat an x, do not combine.
func TestCombineRecoveryKeyRefusesBadShares(t *testing.T) {
	key, _ := testKeyPEM(t)
	fp, _ := publicKeySHA256(&key.PublicKey)
	shares := func(der []byte) []RecoveryKeyShare {
		parts, err := shamir.Split(der, 3, 2)
		if err != nil {
			t.Fatal(err)
		}
		var out []RecoveryKeyShare
		for _, p := range parts {
			out = append(out, RecoveryKeyShare{Kind: recoveryShareKind, Version: 1, X: p.X, Y: p.Y, Threshold: 2, Shares: 3, PublicKeySHA256: fp})
		}
		return out
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if _, err := CombineRecoveryKey(shares(edDER)); err == nil || !strings.Contains(err.Error(), "EC key") {
		t.Fatalf("shares of an Ed25519 key: %v", err)
	}
	other, _ := testKeyPEM(t)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if _, err := CombineRecoveryKey(shares(otherDER)); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("shares naming another key: %v", err)
	}
	s := shares(otherDER)
	s[0].X = s[1].X
	if _, err := CombineRecoveryKey(s); err == nil {
		t.Fatal("two shares at the same x combined")
	}
}
