package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
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

func launchKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate launch key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal launch key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Lengths the launch schema fixes: a 48-byte launch measurement and 32-byte
// join tokens, both in lowercase hex.
var (
	launchMeasurement = strings.Repeat("11", 48)
	agentJoinToken    = strings.Repeat("a", 64)
	serverJoinToken   = strings.Repeat("b", 64)
)

// cdsMeasurements is the document `c8s cds config new` writes: the CDS image
// bound to the configuration its VM boots.
func cdsMeasurements(t *testing.T) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       "cds",
			Digest:     bytes.Repeat([]byte{0x50}, 48),
			LaunchFile: []byte("schemaVersion: c8s-cds/v1\nclusterID: cluster-one\n"),
		}},
	})
	if err != nil {
		t.Fatalf("format CDS measurements: %v", err)
	}
	return string(data)
}

// agentDocument is an agent launch document a node accepts.
func agentDocument(t *testing.T) []byte {
	t.Helper()
	doc := oneNodeDocument(t, launchconfig.Agent)
	doc.AgentOperatorPublicKeys = []string{launchKeyPEM(t)}
	return marshalDocument(t, doc)
}

// serverDocument is a server launch document a node accepts.
func serverDocument(t *testing.T) []byte {
	t.Helper()
	doc := oneNodeDocument(t, launchconfig.Server)
	doc.RKE2.ServerToken = serverJoinToken
	return marshalDocument(t, doc)
}

func oneNodeDocument(t *testing.T, role launchconfig.Role) launchconfig.Document {
	t.Helper()
	return launchconfig.Document{
		SchemaVersion: launchconfig.SchemaVersion,
		ClusterID:     "cluster-one",
		Role:          role,
		Image: launchconfig.Image{
			Platform:    "snp",
			Measurement: launchMeasurement,
		},
		Node: launchconfig.Node{
			Name: "node-one",
			IP:   "10.0.0.2",
		},
		RKE2: launchconfig.RKE2{AgentToken: agentJoinToken},
		CDS: launchconfig.CDS{
			Address:      "192.0.2.50:8443",
			Measurements: cdsMeasurements(t),
		},
		Server: launchconfig.ServerConfig{
			Address:           "10.0.0.1",
			OperatorPublicKey: launchKeyPEM(t),
		},
	}
}

func marshalDocument(t *testing.T, doc launchconfig.Document) []byte {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal launch document: %v", err)
	}
	return data
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
	content := serverDocument(t)
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
	launchPath := writeLaunch(t, dir, agentDocument(t))
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
	launchPath := writeLaunch(t, dir, agentDocument(t))
	if err := runSign("", launchPath); err == nil {
		t.Fatal("want an error when --key is missing")
	}
}

func TestSignLaunchRefusesANonLaunchDocument(t *testing.T) {
	keyPath, _ := writeOperatorKey(t)
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{
			name:    "an operator decree",
			content: []byte(`{"kind":"UpdateMeasurements","baseVersion":3}`),
		},
		{
			name:    "a launch document without a cluster",
			content: []byte("schemaVersion: c8s-launch/v1\nrole: agent\n"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launchPath := writeLaunch(t, t.TempDir(), tc.content)
			err := runSign(keyPath, launchPath)
			if err == nil || !strings.Contains(err.Error(), "not a launch configuration") {
				t.Fatalf("want a refusal, got %v", err)
			}
			if _, err := os.Stat(launchPath + ".sig"); !os.IsNotExist(err) {
				t.Fatal("signed a document that is not a launch configuration")
			}
		})
	}
}

func TestSignLaunchDetectsTamperedContent(t *testing.T) {
	keyPath, key := writeOperatorKey(t)
	dir := t.TempDir()
	launchPath := writeLaunch(t, dir, agentDocument(t))
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
	tamperedDigest := sha256.Sum256([]byte("schemaVersion: c8s-launch/v1\nrole: server\n"))
	if ecdsa.VerifyASN1(&key.PublicKey, tamperedDigest[:], der) {
		t.Fatal("signature verified against tampered content")
	}
}
