package cds

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/shamir"
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
			last := len(p) - 1
			out = append(out, RecoveryKeyShare{Kind: recoveryShareKind, Version: 1, X: p[last], Y: p[:last], Threshold: 2, Shares: 3, PublicKeySHA256: fp})
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

// oldBuildShares are shares 1, 3 and 4 of a 3-of-5 split of a throwaway
// P-256 key, written by "recovery-key split" before it used the OpenBao
// library. Custodians may hold such files, so they must keep combining.
var oldBuildShares = []string{
	`{"kind":"c8s-recovery-key-share","version":1,"x":1,"threshold":3,"shares":5,"public_key_sha256":"b93a6ed10803e724db3a39357d7b6ecafdab916b089ede494622a00d9f1b69df","y":"isJF1WVQVAYhqbAAecr9418P6y+OJUc1ixIKLwnrTddJqu+I4/jAbb26Z0YiVwvxKNMS5ST/ASrBOAd3guubbo/f3S+NcB8d5APz63kJZirxlpp+kEd+nsKqCTQMrupk3zsvlYEp651Rwctji7TImmQkD4MSha/yYTrtGroCVC/Ibc3JiJoN1cDL"}`,
	`{"kind":"c8s-recovery-key-share","version":1,"x":3,"threshold":3,"shares":5,"public_key_sha256":"b93a6ed10803e724db3a39357d7b6ecafdab916b089ede494622a00d9f1b69df","y":"0xARExyxPh6H9RJqZXqm0a68315qBhh0GP5VqvJ2ogv3+IOqbr70/Xn41Og0nEcyzbk5CUlURz/cEiybwPPQiUOWBIWeqWb/zXCkSPkcSlLrReZ/YQ635kNBxe3vX96tUerSb7HwhuA3B2eX+w6T83R9sJnYMksOf0V4V596LgdXYZDmc5aXiZrK"}`,
	`{"kind":"c8s-recovery-key-share","version":1,"x":4,"threshold":3,"shares":5,"public_key_sha256":"b93a6ed10803e724db3a39357d7b6ecafdab916b089ede494622a00d9f1b69df","y":"WnUuQgHGWuvc03e9k2Om59fJ6T+oxzPgaMe2dEzRFA7e2W7bkjKWrackzhYVQ5KNzYC98Q03dmaqmsdnMbmTbjY/5vewH+72lw2k9FuAFXF8WyTc3Zcdfo8+S9yYQ7bLrH3GsVTKIX08CxFKB52kCfpa9lJmJj1YchCJlPNiHPJc1N86gxEK9vGG"}`,
}

func TestRecoveryKeyOldBuildShares(t *testing.T) {
	var shares []RecoveryKeyShare
	for _, raw := range oldBuildShares {
		var s RecoveryKeyShare
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		shares = append(shares, s)
	}
	key, err := CombineRecoveryKey(shares)
	if err != nil {
		t.Fatalf("old shares: %v", err)
	}
	if fp, _ := publicKeySHA256(&key.PublicKey); fp != "b93a6ed10803e724db3a39357d7b6ecafdab916b089ede494622a00d9f1b69df" {
		t.Fatalf("old shares rebuilt key %s", fp)
	}
	if _, err := CombineRecoveryKey(shares[:2]); err == nil {
		t.Fatal("two old shares of three accepted")
	}
	// The rebuilt key splits again, and the new shares rebuild it.
	again, err := SplitRecoveryKey(key, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := CombineRecoveryKey([]RecoveryKeyShare{again[4], again[0], again[2]}); err != nil || !got.Equal(key) {
		t.Fatalf("new shares: %v", err)
	}
	// The field itself: a 3-of-5 split of a plain string by the old build.
	y := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	got, err := shamir.Combine([][]byte{
		append(y("202f53ffb7a5b4df71c2955f4d7a2b9e"), 1),
		append(y("aa9d4ab968391d27cd58b3b1208afea6"), 3),
		append(y("1f161ed2319a8d0eecfc38267de4a577"), 5),
	})
	if err != nil || string(got) != "c8s recovery key" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// Every k-subset of a split rebuilds the key; k-1 shares do not rebuild the
// secret even when the count check is bypassed; no share is the secret.
func TestRecoveryKeyThreshold(t *testing.T) {
	key, _ := testKeyPEM(t)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	shares, err := SplitRecoveryKey(key, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			for c := b + 1; c < 5; c++ {
				got, err := CombineRecoveryKey([]RecoveryKeyShare{shares[c], shares[a], shares[b]})
				if err != nil || !got.Equal(key) {
					t.Fatalf("shares %d,%d,%d: %v", a, b, c, err)
				}
			}
		}
	}
	if got, err := CombineRecoveryKey(shares); err != nil || !got.Equal(key) {
		t.Fatalf("all five: %v", err)
	}
	two := [][]byte{append(bytes.Clone(shares[0].Y), shares[0].X), append(bytes.Clone(shares[1].Y), shares[1].X)}
	if got, _ := shamir.Combine(two); bytes.Equal(got, der) {
		t.Fatal("two shares of three rebuilt the key")
	}
	for _, s := range shares {
		if s.X == 0 || bytes.Equal(s.Y, der) {
			t.Fatalf("share x=%d leaks the key", s.X)
		}
	}
}

func TestRecoveryKeyRefusals(t *testing.T) {
	key, _ := testKeyPEM(t)
	for _, c := range []struct{ n, k int }{{3, 1}, {2, 3}, {256, 3}} {
		if _, err := SplitRecoveryKey(key, c.n, c.k); err == nil {
			t.Fatalf("n=%d k=%d accepted", c.n, c.k)
		}
	}
	shares, err := SplitRecoveryKey(key, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	zero := shares[0]
	zero.X = 0
	short := shares[1]
	short.Y = short.Y[:len(short.Y)-1]
	for name, in := range map[string][]RecoveryKeyShare{
		"one":       shares[:1],
		"duplicate": {shares[0], shares[0]},
		"zero x":    {zero, shares[1]},
		"lengths":   {shares[0], short},
	} {
		if _, err := CombineRecoveryKey(in); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
