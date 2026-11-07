package podlaunch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const cdsLaunchFile = "schemaVersion: c8s-cds/v1\nclusterID: cluster-one\n"

func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// testPodDocument returns a generic pod document, its launch key and public key.
func testPodDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, pub := testKey(t)
	doc := Document{
		SchemaVersion: SchemaVersion, ClusterID: "cluster-one", Role: Pod,
		Image:                Image{Platform: platform, Measurement: strings.Repeat("11", 48)},
		Node:                 Node{Name: "node-one"},
		PodOperatorPublicKey: pub,
		CDS: cmdsutil.CDS{
			Address:      "cds.example.org:8443",
			Measurements: testCDSPin(t, teetypes.FamilySNP, 2),
		},
	}
	if platform == "tdx" {
		doc.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
	}
	return doc, key, pub
}

func testCDSPin(t *testing.T, family teetypes.Family, digests int) string {
	t.Helper()
	pins := refvalues.ReferenceValues{Family: family}
	for i := range digests {
		image := remote.ImagePin{
			Name:       fmt.Sprintf("cds-smp%d", 4*(i+1)),
			Digest:     mustDecodeHex(strings.Repeat(fmt.Sprintf("%02x", 0x50+i), 48)),
			LaunchFile: []byte(cdsLaunchFile),
		}
		if family == teetypes.FamilyTDX {
			image.Registers = map[int][]byte{
				1: mustDecodeHex(strings.Repeat("22", 48)),
				2: mustDecodeHex(strings.Repeat("33", 48)),
			}
		}
		pins.Images = append(pins.Images, image)
	}
	data, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func stagedCDSPolicy(t *testing.T, d *Document) refvalues.ReferenceValues {
	t.Helper()
	endpoint, err := d.CDS.Parse()
	if err != nil {
		t.Fatal(err)
	}
	return endpoint.Pins
}

func testMeasuredIdentity(t *testing.T, doc Document, pub string) launchbinding.MeasuredIdentity {
	t.Helper()
	image, err := runtimemeasure.IdentityFromResult(&teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.NormalizePlatform(doc.Image.Platform),
		Claims: teetypes.Claims{
			LaunchDigest: doc.Image.Measurement,
			PlatformData: map[string]any{"rtmr_1": doc.Image.RTMRs[1], "rtmr_2": doc.Image.RTMRs[2]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return launchbinding.MeasuredIdentity{OperatorKey: []byte(pub), Image: image}
}

func testLoader(t *testing.T, doc Document, pub string) {
	t.Helper()
	old := loadMeasuredIdentity
	t.Cleanup(func() { loadMeasuredIdentity = old })
	measured := testMeasuredIdentity(t, doc, pub)
	loadMeasuredIdentity = func(context.Context, string, string, string) (launchbinding.MeasuredIdentity, error) {
		return measured, nil
	}
}

func testConfig(t *testing.T, doc Document, key *ecdsa.PrivateKey) Config {
	t.Helper()
	cfg := Config{Platform: doc.Image.Platform, RootDir: t.TempDir()}
	cfg.DocumentPath = filepath.Join(t.TempDir(), "launch.yaml")
	cfg.SignaturePath = cfg.DocumentPath + ".sig"
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := operatorauth.SignDetached(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DocumentPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte(sig+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func requirePresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
}

func requireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s must not exist: %v", path, err)
	}
}

func runBundleCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

func writeManifest(t *testing.T, platform string) string {
	t.Helper()
	var body string
	switch platform {
	case "tdx":
		body = `{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"` + strings.Repeat("11", 48) +
			`","rtmr1":"` + strings.Repeat("22", 48) + `","rtmr2":"` + strings.Repeat("33", 48) + `"}}`
	case "snp":
		body = `{"snp_variants":[` +
			`{"smp":4,"measurement":{"snp_launch_digest":"` + strings.Repeat("44", 48) + `","algorithm":"sha384"}},` +
			`{"smp":8,"measurement":{"snp_launch_digest":"` + strings.Repeat("55", 48) + `","algorithm":"sha384"}}]}`
	}
	return writeFile(t, "manifest.json", body)
}

func readBundleDocument(t *testing.T, dir, node string) (*Document, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, node, documentFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("%s document does not parse: %v", node, err)
	}
	return doc, data
}

func stageBundleNode(t *testing.T, dir, node string) {
	t.Helper()
	doc, _ := readBundleDocument(t, dir, node)
	pub, err := os.ReadFile(filepath.Join(dir, node, pubkeyFile))
	if err != nil {
		t.Fatal(err)
	}
	testLoader(t, *doc, string(pub))
	cfg := Config{
		Platform:      doc.Image.Platform,
		RootDir:       t.TempDir(),
		DocumentPath:  filepath.Join(dir, node, documentFile),
		SignaturePath: filepath.Join(dir, node, signatureFile),
	}
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatalf("stage %s from the bundle: %v", node, err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Node.Name != doc.Node.Name || staged.Role != doc.Role {
		t.Fatalf("staged %s %q for bundle entry %q", staged.Role, staged.Node.Name, node)
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
