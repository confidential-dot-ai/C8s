package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryKeySplitAndCombine(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "recovery.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "shares")
	cmd := newHARecoveryKeyCmd()
	cmd.SetArgs([]string{"split", "--recovery-key", keyFile, "--out", out, "--shares", "5", "--threshold", "3"})
	cmd.SetOut(new(nopWriter))
	cmd.SetErr(new(nopWriter))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	share := func(x int) string { return filepath.Join(out, "share-"+string(rune('0'+x))+".json") }
	got, err := loadRecoveryKey("", []string{share(5), share(2), share(4)})
	if err != nil || !got.Equal(key) {
		t.Fatalf("three shares: %v", err)
	}
	if _, err := loadRecoveryKey("", []string{share(1), share(2)}); err == nil {
		t.Fatal("two of three restored the key")
	}
	if _, err := loadRecoveryKey(keyFile, []string{share(1)}); err == nil {
		t.Fatal("key and shares together accepted")
	}
	if _, err := loadRecoveryKey("", nil); err == nil {
		t.Fatal("neither accepted")
	}
	if k, err := loadRecoveryKey(keyFile, nil); err != nil || !k.Equal(key) {
		t.Fatalf("key file: %v", err)
	}
	// Shares of another key, or a damaged share, are caught.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o, _ := SplitRecoveryKey(other, 3, 2)
	mine, _ := loadRecoveryShares([]string{share(1), share(2), share(3)})
	if _, err := CombineRecoveryKey([]RecoveryKeyShare{mine[0], o[1], mine[2]}); err == nil {
		t.Fatal("mixed keys accepted")
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
	cmd.SetOut(new(nopWriter))
	cmd.SetErr(new(nopWriter))
	if err := cmd.Execute(); err == nil {
		t.Fatal("overwrote existing shares")
	}
}

type nopWriter struct{}

func (*nopWriter) Write(p []byte) (int, error) { return len(p), nil }
