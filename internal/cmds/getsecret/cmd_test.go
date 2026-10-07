package getsecret

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The webhook renders these flags, so a malformed --secret has to fail at parse
// rather than reaching CDS.
func TestNewCmdRejectsBadSecretSpec(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{
		"--cds-secrets-url=https://cds.example",
		"--attestation-api-url=http://127.0.0.1:8080",
		"--secret=notaspec",
	})
	cmd.SetOut(nil)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "NAME=/store/path") {
		t.Fatalf("err = %v, want a spec-parse failure", err)
	}
}

func TestNewCmdRejectsMissingSecretsURL(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{"--secret=DB=/api/db"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--cds-secrets-url") {
		t.Fatalf("err = %v, want a missing --cds-secrets-url failure", err)
	}
}

func TestNewCmdDefaults(t *testing.T) {
	cmd := NewCmd()
	for flag, want := range map[string]string{
		"cert":      "/run/c8s/certs/tls.crt",
		"key":       "/run/c8s/certs/tls.key",
		"out-dir":   "/run/c8s/secrets",
		"file-mode": "0640",
	} {
		if got := cmd.Flags().Lookup(flag).DefValue; got != want {
			t.Fatalf("--%s default = %q, want %q", flag, got, want)
		}
	}
}

// A malformed measurement is a typo in rendered config, and pinning nothing is
// not an acceptable fallback for it.
func TestRunRejectsBadMeasurements(t *testing.T) {
	cfg := validConfig(t)
	cfg.Measurements = []string{"not-hex"}
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "--measurements") {
		t.Fatalf("err = %v, want a measurement-parse failure", err)
	}
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	cfg := validConfig(t)
	cfg.SecretsURL = ""
	if err := run(cfg); err == nil {
		t.Fatal("an invalid config was accepted")
	}
}

// fetchAll builds the client before it asks for anything, so a leaf that is not
// on disk yet surfaces there.
func TestFetchAllWithoutLeaf(t *testing.T) {
	cfg := validConfig(t)
	cfg.CertPath = filepath.Join(t.TempDir(), "absent.crt")
	cfg.KeyPath = filepath.Join(t.TempDir(), "absent.key")
	if _, err := fetchAll(context.Background(), cfg, armtls.Pins{}); err == nil {
		t.Fatal("a missing leaf was accepted")
	}
}
