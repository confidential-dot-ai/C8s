//go:build !c8s_node

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	pinDigestA = "aa11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	pinDigestB = "bb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	pinReg1    = "111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	pinReg2    = "222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

// installPins reads package-level flag vars, so each case restores them.
func withInstallFlags(t *testing.T, config string, measurements, rtmrs []string) {
	t.Helper()
	origC, origM, origR := installMeasurementsConfig, installMeasurements, installRegisters
	t.Cleanup(func() {
		installMeasurementsConfig, installMeasurements, installRegisters = origC, origM, origR
	})
	installMeasurementsConfig, installMeasurements, installRegisters = config, measurements, rtmrs
}

func writePinConfig(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "measurements.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Config mode must ship the file AND fan the same pins out flat, or the
// consumers that read a plain digest list would install unpinned.
func TestInstallPinsEmitsFileAndFlatValues(t *testing.T) {
	path := writePinConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+pinDigestA+`","rtmr":[null,"`+pinReg1+`","`+pinReg2+`"]},
		{"name":"b","mrtd":"00`+pinDigestB+`","rtmr":[null,"`+pinReg1+`","`+pinReg2+`"]}]}`)
	withInstallFlags(t, path, nil, nil)

	digests, rtmrs, helmArgs, err := installPins()
	if err != nil {
		t.Fatalf("installPins: %v", err)
	}
	if len(digests) != 2 {
		t.Fatalf("got %d digests, want both images", len(digests))
	}
	if got := hex.EncodeToString(digests[0]); got != "00"+pinDigestA {
		t.Errorf("digest[0] = %s", got)
	}
	if len(rtmrs) != 2 {
		t.Errorf("rtmrs = %v, want the two shared register pins", rtmrs)
	}
	joined := strings.Join(helmArgs, " ")
	for _, want := range []string{"cds.measurementsConfig=" + path, "armtlsMesh.measurementsConfig=" + path} {
		if !strings.Contains(joined, want) {
			t.Errorf("helm args %v missing %s", helmArgs, want)
		}
	}
	if n := strings.Count(joined, "--set-file"); n != 2 {
		t.Errorf("got %d --set-file args, want 2", n)
	}
}

func TestInstallPinsRefusesToDropOperatorIdentity(t *testing.T) {
	withInstallFlags(t, "../../internal/testdata/node-identities.json", nil, nil)
	if _, _, _, err := installPins(); err == nil || !strings.Contains(err.Error(), "baked node launch flow") {
		t.Fatalf("operator-key policy was flattened for Helm: %v", err)
	}
}

// NRI receives one shared register set, so nonuniform image policies must be refused.
func TestInstallPinsRejectsDivergentRegisters(t *testing.T) {
	path := writePinConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[
		{"name":"a","mrtd":"00`+pinDigestA+`","rtmr":[null,"`+pinReg1+`"]},
		{"name":"b","mrtd":"00`+pinDigestB+`","rtmr":[null,"`+pinReg2+`"]}]}`)
	withInstallFlags(t, path, nil, nil)
	if digests, rtmrs, args, err := installPins(); err == nil || !strings.Contains(err.Error(), "identical register pins") || len(digests)+len(rtmrs)+len(args) != 0 {
		t.Fatalf("divergent register policy was weakened: digests=%v rtmrs=%v args=%v err=%v", digests, rtmrs, args, err)
	}
}

func TestInstallPinsRejectsMixedFlags(t *testing.T) {
	path := writePinConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+pinDigestA+`"}]}`)

	for _, tc := range []struct {
		name         string
		measurements []string
		rtmrs        []string
	}{
		{"with --measurements", []string{"00" + pinDigestB}, nil},
		{"with --rtmrs", nil, []string{"1=" + pinReg1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withInstallFlags(t, path, tc.measurements, tc.rtmrs)
			if _, _, _, err := installPins(); err == nil {
				t.Fatal("accepted a mixed configuration")
			}
		})
	}
}

// Independent digest and RTMR inputs are normalized for the chart.
func TestInstallPinsMeasurementInputs(t *testing.T) {
	withInstallFlags(t, "", []string{"00" + pinDigestA}, []string{"1=" + pinReg1})

	digests, rtmrs, helmArgs, err := installPins()
	if err != nil {
		t.Fatalf("installPins: %v", err)
	}
	if len(helmArgs) != 0 {
		t.Errorf("flat mode emitted config args: %v", helmArgs)
	}
	if len(digests) != 1 || hex.EncodeToString(digests[0]) != "00"+pinDigestA {
		t.Errorf("digests = %v", digests)
	}
	if len(rtmrs) != 1 {
		t.Errorf("rtmrs = %v, want the one pin", rtmrs)
	}
}

func TestInstallPinsFailsClosed(t *testing.T) {
	withInstallFlags(t, filepath.Join(t.TempDir(), "absent.json"), nil, nil)
	if _, _, _, err := installPins(); err == nil {
		t.Fatal("a missing config produced pins")
	}
}

// helm resolves --set-file itself, so the emitted path must not depend on the
// directory the install ran from.
func TestInstallPinsEmitsAnAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "measurements.json"),
		[]byte(`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+pinDigestA+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	withInstallFlags(t, "measurements.json", nil, nil)

	_, _, helmArgs, err := installPins()
	if err != nil {
		t.Fatalf("installPins with a relative path: %v", err)
	}
	for _, arg := range helmArgs {
		key, path, found := strings.Cut(arg, "=")
		if !found {
			continue
		}
		if !filepath.IsAbs(path) {
			t.Errorf("%s=%s is not absolute", key, path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("emitted path does not resolve: %v", err)
		}
	}
}
