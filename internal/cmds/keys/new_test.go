package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/certutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

func TestNewKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "operator.key")
	pubPath := filepath.Join(dir, "operator.pub")

	cmd := NewCmd()
	cmd.SetArgs([]string{"new", "--out", keyPath, "--pub-out", pubPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read private: %v", err)
	}
	// The private half must load into the signer every write command uses.
	if _, err := operatorauth.NewSignerFromKeyPEM(keyPEM); err != nil {
		t.Fatalf("private key does not parse as an operator key: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %o, want 0600", info.Mode().Perm())
	}

	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	// The public half must parse the way Trust Authority pins it (ta.operatorKeys).
	parsed, err := operatorauth.ParsePublicKeysPEM(pubPEM)
	if err != nil {
		t.Fatalf("public key does not parse as an operator key set: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed %d public keys, want 1", len(parsed))
	}
	priv, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("re-parse private: %v", err)
	}
	if !priv.PublicKey.Equal(parsed[0]) {
		t.Error("public half does not match the private half")
	}
}

func TestNewKeyRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "operator.key")
	pubPath := filepath.Join(dir, "operator.pub")
	if err := os.WriteFile(keyPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewCmd()
	cmd.SetArgs([]string{"new", "--out", keyPath, "--pub-out", pubPath})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "operator.key") {
		t.Fatalf("want refusal naming the existing file, got %v", err)
	}
}

func TestNewKeyRequiresBothPaths(t *testing.T) {
	for _, args := range [][]string{
		{"new", "--out", filepath.Join(t.TempDir(), "k")},
		{"new", "--pub-out", filepath.Join(t.TempDir(), "p")},
		{"new"},
	} {
		cmd := NewCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Errorf("args %v: want an error, got nil", args)
		}
	}
}
