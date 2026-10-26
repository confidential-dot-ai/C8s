package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func writeOperatorKey(t *testing.T) (path string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pem, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "operator.key")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

// writeLaunch writes content to <dir>/launch.yaml and returns its path — the
// document every sign-launch test signs.
func writeLaunch(t *testing.T, dir string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, "launch.yaml")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runSign runs `c8s keys sign-launch --key <keyPath> <launchPath>` through
// the real cobra command, the shape every test below exercises.
func runSign(keyPath, launchPath string, args ...string) error {
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	argv := []string{"sign-launch"}
	if keyPath != "" {
		argv = append(argv, "--key", keyPath)
	}
	argv = append(argv, args...)
	argv = append(argv, launchPath)
	cmd.SetArgs(argv)
	return cmd.Execute()
}

func TestSignLaunchWritesVerifiableSignature(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	content := []byte("schemaVersion: c8s-launch/v2\nrole: server\n")
	launchPath := writeLaunch(t, dir, content)

	if err := runSign(keyPath, launchPath); err != nil {
		t.Fatalf("execute: %v", err)
	}

	sigPath := launchPath + ".sig"
	sigLine, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	trimmed := strings.TrimSuffix(string(sigLine), "\n")
	if strings.Contains(trimmed, "\n") {
		t.Fatalf("signature file is not a single line: %q", trimmed)
	}
	der, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	digest := sha256.Sum256(content)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatal("signature does not verify against the signing key over sha256(launch.yaml)")
	}
}

func TestSignLaunchRefusesToOverwrite(t *testing.T) {
	keyPath, _ := writeOperatorKey(t)
	dir := t.TempDir()
	launchPath := writeLaunch(t, dir, []byte("schemaVersion: c8s-launch/v2\nrole: agent\n"))
	if err := os.WriteFile(launchPath+".sig", []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runSign(keyPath, launchPath)
	if err == nil || !strings.Contains(err.Error(), "launch.yaml.sig") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want refusal naming the existing sig file and --force, got %v", err)
	}
	if err := runSign(keyPath, launchPath, "--force"); err != nil {
		t.Fatalf("--force: %v", err)
	}
	sig, err := os.ReadFile(launchPath + ".sig")
	if err != nil || string(sig) == "existing" {
		t.Fatalf("--force did not replace the signature: %q, %v", sig, err)
	}
}

func TestSignLaunchRequiresKey(t *testing.T) {
	dir := t.TempDir()
	launchPath := writeLaunch(t, dir, []byte("schemaVersion: c8s-launch/v2\nrole: agent\n"))
	if err := runSign("", launchPath); err == nil {
		t.Fatal("want an error when --key is missing")
	}
}

func TestSignLaunchDetectsTamperedContent(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	launchPath := writeLaunch(t, dir, []byte("schemaVersion: c8s-launch/v2\nrole: agent\n"))
	if err := runSign(keyPath, launchPath); err != nil {
		t.Fatalf("execute: %v", err)
	}
	sigLine, err := os.ReadFile(launchPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(string(sigLine), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	tamperedDigest := sha256.Sum256([]byte("schemaVersion: c8s-launch/v2\nrole: server\n"))
	if ecdsa.VerifyASN1(&key.PublicKey, tamperedDigest[:], der) {
		t.Fatal("signature verified against tampered content")
	}
}
