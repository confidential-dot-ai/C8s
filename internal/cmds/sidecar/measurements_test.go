package sidecar

import (
	"encoding/hex"
	"strings"
	"testing"
)

func measurementHex() string { return strings.Repeat(hex.EncodeToString([]byte{0xab}), 48) }

func TestParsePinsRefusesAnUnpinnedCDS(t *testing.T) {
	cfg := Config{}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("error = %v, want a refusal naming the flag that pins CDS", err)
	}
}

func TestParsePinsAcceptsAPinnedCDS(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}}
	got, err := cfg.ParsePins()
	if err != nil {
		t.Fatalf("ParsePins: %v", err)
	}
	if len(got.Measurements) != 1 {
		t.Fatalf("parsed %d measurements, want 1", len(got.Measurements))
	}
}

func TestParsePinsRejectsMalformedHex(t *testing.T) {
	cfg := Config{Measurements: []string{"zz"}}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}

func TestParsePinsRejectsMalformedRTMR(t *testing.T) {
	cfg := Config{Measurements: []string{measurementHex()}, RTMRs: []string{"1=zz"}}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "--rtmrs") {
		t.Fatalf("error = %v, want a parse error naming the flag", err)
	}
}
