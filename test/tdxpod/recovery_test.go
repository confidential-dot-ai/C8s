package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-recovery"
)

func recoveryTestPins(t *testing.T) pins {
	t.Helper()
	overlay := strings.Repeat("c", 40)
	t.Setenv("GITHUB_SHA", overlay)
	h := strings.Repeat("d", 64)
	return pins{"schema": float64(1), "source": fixture.Baseline, "profileSource": fixture.Baseline, "buildRun": "123",
		"image": "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + h, "artifact": "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + h,
		"manifestSHA256": h, "diskSHA256": h, "meshImage": baselineMesh, "recoveryFixture": true, "overlaySource": overlay,
		"controllerSHA256": h, "baselineDiskSHA256": baselineDisk, "runtimeComponentsSHA256": h}
}

func TestRecoveryReceiptCannotEnterProductionOrSelectAnotherBaseline(t *testing.T) {
	p := recoveryTestPins(t)
	if err := validateRecoveryPins(p); err != nil {
		t.Fatal(err)
	}
	if validatePins(p) == nil {
		t.Fatal("fixture entered production acceptance")
	}
	for _, edit := range []struct {
		key   string
		value any
	}{
		{"source", strings.Repeat("e", 40)}, {"profileSource", strings.Repeat("e", 40)}, {"overlaySource", strings.Repeat("e", 40)},
		{"recoveryFixture", false}, {"diskSHA256", baselineDisk}, {"baselineDiskSHA256", strings.Repeat("e", 64)},
		{"image", "ghcr.io/confidential-dot-ai/node-guest-base:rke2-tdx"}, {"developmentProfile", true}, {"controllerSHA256", ""},
	} {
		if validateRecoveryPins(p.with(edit.key, edit.value)) == nil {
			t.Fatalf("accepted changed %s", edit.key)
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POD_RECOVERY_RECEIPT", path)
	t.Setenv("POD_RECOVERY_RECEIPT_SHA256", sha256Hex(raw))
	if _, err := recoveryPins(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoveryPins(); err == nil {
		t.Fatal("accepted a changed explicit receipt")
	}
}

func TestRecoveryAcceptsLiveCheckerBeforeSoakCompletion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options readinessOptions
		accept  bool
	}{
		{"all three running", readinessOptions{}, true},
		{"intentional readiness dip", readinessOptions{unready: true}, false},
		{"checker already completed", readinessOptions{complete: true}, false},
		{"readiness recovered with checker running", readinessOptions{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readinessStatus(t, "True", "2026-01-01T00:10:00Z", tc.options)
			state, err := podStateOf(raw, "pod")
			if err != nil {
				t.Fatal(err)
			}
			if fixture.LiveWorkload(state) != tc.accept {
				t.Fatalf("unexpected recovery gate: %+v", state)
			}
			if len(state.Starts) != 3 {
				t.Fatal("three container starts not retained")
			}
		})
	}
}
