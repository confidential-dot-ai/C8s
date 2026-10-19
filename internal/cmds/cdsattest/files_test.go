package cdsattest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg := config{frontDoorModeFile: write("front-door-mode", "acme\n")}
	if err := loadFiles(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.frontDoorMode != types.FrontDoorModeACME {
		t.Fatalf("loaded front-door mode %q, want acme", cfg.frontDoorMode)
	}

	cfg = config{frontDoorMode: types.FrontDoorModeCDS, frontDoorModeFile: write("mode", "cds")}
	if err := loadFiles(&cfg); err == nil {
		t.Fatal("--front-door-mode with --front-door-mode-file was accepted")
	}

	// The serving leaf follows the mode: nginx serves the ACME leaf in acme
	// mode and the mesh leaf otherwise.
	for mode, want := range map[string]string{"acme": "/etc/c8s-acme-tls/cert.pem", "cds": "/tls/cert.pem"} {
		cfg = config{
			frontDoorModeFile:   write("mode-"+mode, mode+"\n"),
			servingCertFile:     "/tls/cert.pem",
			acmeServingCertFile: "/etc/c8s-acme-tls/cert.pem",
		}
		if err := loadFiles(&cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.servingCertFile != want {
			t.Errorf("mode %s: serving cert = %q, want %q", mode, cfg.servingCertFile, want)
		}
	}
}
