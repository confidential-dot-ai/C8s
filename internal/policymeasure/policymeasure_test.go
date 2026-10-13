package policymeasure

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, JournalName)
	if got, err := Read(path); err != nil || got != nil {
		t.Fatalf("Read(missing) = %v, %v; want none", got, err)
	}
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	if err := os.WriteFile(path, []byte(p+"\n"+q+"\n"+p+"\npartial-line"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(path); err != nil || !slices.Equal(got, []string{p, q}) {
		t.Fatalf("Read = %v, %v; want [%s %s]", got, err, p, q)
	}
}

func TestPrefix(t *testing.T) {
	anchor := []byte("operator key")
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	report := func(digests ...string) *teetypes.VerificationResult {
		reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), digests)
		return &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: teetypes.Claims{
			PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])},
		}}
	}
	for _, tc := range []struct {
		name    string
		report  *teetypes.VerificationResult
		digests []string
		want    []string
		wantErr bool
	}{
		{name: "bare seed", report: report(), digests: []string{p, q}},
		{name: "prefix", report: report(p), digests: []string{p, q}, want: []string{p}},
		{name: "whole list", report: report(p, q), digests: []string{p, q}, want: []string{p, q}},
		{name: "extend outside the list", report: report(q), digests: []string{p}, wantErr: true},
		{name: "no list", report: report(p), wantErr: true},
	} {
		got, err := Prefix(tc.report, anchor, tc.digests)
		if (err != nil) != tc.wantErr || !slices.Equal(got, tc.want) {
			t.Errorf("%s: Prefix = %v, %v; want %v, error %v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
}

// A peer controls the list's length, so replaying it must stay linear.
func TestPrefixLongList(t *testing.T) {
	digests := make([]string, 200_000)
	for i := range digests {
		digests[i] = "x"
	}
	reg := runtimemeasure.Seed([]byte("k"))
	r := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: teetypes.Claims{
		PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])},
	}}
	start := time.Now()
	if got, err := Prefix(r, []byte("k"), digests); err != nil || got != nil {
		t.Fatalf("Prefix = %v, %v; want the bare seed", len(got), err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Prefix over %d digests took %s", len(digests), d)
	}
}
