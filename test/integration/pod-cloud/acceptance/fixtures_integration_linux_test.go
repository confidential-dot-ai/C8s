//go:build linux && pod_cloud_integration

package acceptance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func fixtureCDSPolicy(t *testing.T, launch []byte) []byte {
	t.Helper()
	policy, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "independent-cds", Digest: bytes.Repeat([]byte{0x88}, 48), LaunchFile: launch}}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// fixtureConfig exercises the production mounted-file loader. No test-only
// attestation bypass or alternate launch authority is present in production.
func fixtureConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	write("launch.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	write("server.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	write("token", []byte("test-launcher-token\n"))
	write("cds.json", fixtureCDSPolicy(t, []byte("schemaVersion: c8s-cds/v1\nclusterID: test-cluster\n")))
	write("manifest.json", []byte(`{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"`+strings.Repeat("11", 48)+`","rtmr1":"`+strings.Repeat("22", 48)+`","rtmr2":"`+strings.Repeat("33", 48)+`"}}`))
	write("workloads.json", []byte(`{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:`+strings.Repeat("a", 64)+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	cfg := Config{ProviderID: "test-launcher", CloudURL: "https://cloud.example", CloudTokenFile: "token", Image: "c8s-pod@2026.10.26-1", ImageManifestFile: "manifest.json", LaunchKeyFile: "launch.key", ServerAddress: "198.51.100.2", ServerPublicKeyFile: "server.pub", CDSAddress: "cds.example.test:8443", CDSImagePolicyFile: "cds.json", WorkloadsFile: "workloads.json", ClusterID: "test-cluster", Size: "c1.2x", Location: "eu", VCPUs: 2, MemoryMiB: 8192, MeshPeers: []string{"203.0.113.2:9443"}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write("config.json", b)
	loaded, err := LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func fixturePod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "11111111-1111-1111-1111-111111111111"}, Spec: corev1.PodSpec{AutomountServiceAccountToken: new(false), ServiceAccountName: "default", Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app@sha256:" + strings.Repeat("a", 64), Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}}}}}}
}

// launchFixture binds an offline run to a loaded launcher configuration so
// prepared records pass the run's own snapshot checks.
func launchFixture(t *testing.T) (*cloudRun, *Config) {
	t.Helper()
	cfg := fixtureConfig(t)
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.CloudURL, r.cfg.Image = cfg.CloudURL, cfg.Image
	r.ledger.Run, r.ledger.CredentialHash = cfg.ProviderID, credentialHash(cfg.token)
	r.ledger.Owned = map[string]*cloudOwned{}
	return r, cfg
}

// ownedReceipt is the Cloud receipt checkOwned accepts for one owned launch.
func ownedReceipt(r *cloudRun, o *cloudOwned, id string) cloudReceipt {
	in := cloudReceipt{ID: id, Name: o.Key, CreatedAt: o.IntentAt, Tee: "tdx", Size: r.cfg.Size, Location: r.cfg.Location, Labels: o.Labels}
	in.Image.Family, in.Image.Version, _ = strings.Cut(o.Image, "@")
	in.Image.Launch = "c8s-pod/1"
	in.Image.Digest = r.cfg.DiskDigest
	in.Attestation.ReferenceManifest.Digest = r.cfg.ManifestDigest
	in.Attestation.LaunchBinding.SHA256 = cloudHash([]byte(o.LaunchKey))
	return in
}

// instanceJSON renders a receipt as the running instance the Cloud API returns.
func instanceJSON(receipt cloudReceipt, status string, boot int64) map[string]any {
	raw, _ := json.Marshal(receipt)
	var item map[string]any
	_ = json.Unmarshal(raw, &item)
	item["status"] = status
	item["boot"] = map[string]any{"count": boot}
	item["compute"] = map[string]any{"vcpus": 2, "memoryGiB": 8}
	return item
}
