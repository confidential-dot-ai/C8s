package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const (
	testPodUID       = "0b7c6f9e-3c1a-4d3e-9a51-2f0c1d2e3f40"
	testPodWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
)

func testPodManifest(spec string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + testPodUID +
		`"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]` + spec + `}}`
}

// testPodDocument returns a generic pod document, its launch key and public key.
func testPodDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, _, _ := testDocument(t, platform, Server)
	key, pub := testKey(t)
	doc.Role = Pod
	doc.RKE2 = RKE2{}
	doc.AgentOperatorPublicKeys = nil
	doc.PodOperatorPublicKey = pub
	return doc, key, pub
}

// A pod document stages its trust and no workload authority, and nothing of
// a cluster node.
func TestStagePodRole(t *testing.T) {
	doc, key, pub := testPodDocument(t, "tdx")
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	// A stale marker from another role must not survive restaging.
	if err := os.MkdirAll(cfg.path("/run/confos"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.path(agentMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	requirePresent(t, cfg.path(podMarker))
	for _, path := range []string{serverMarker, agentMarker, serverTokenPath, agentTokenPath, rke2FragmentPath, Dir + "/workloads.json", Dir + "/cds.json"} {
		requireAbsent(t, cfg.path(path))
	}
	for path, want := range map[string]string{Dir + "/operator-pubkey": pub} {
		got, err := os.ReadFile(cfg.path(path))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Role != Pod || staged.PodOperatorPublicKey != pub || staged.Server != doc.Server || staged.CDS != doc.CDS {
		t.Fatalf("staged %+v", staged)
	}
	peers, err := refvalues.Load(cfg.path(Dir + "/peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers.Images) != 2 || string(peers.Images[0].Anchor) != doc.Server.OperatorPublicKey || peers.Images[0].Name != "server" || string(peers.Images[1].Anchor) != pub || peers.Images[1].Name != "pod" {
		t.Fatalf("pod peers = %+v", peers.Images)
	}
	cds := stagedCDSPolicy(t, staged)
	if cds.Family != teetypes.FamilySNP || len(cds.Images) != 2 {
		t.Fatalf("pod CDS pins = %+v", cds)
	}
	for _, pin := range cds.Images {
		if string(pin.LaunchFile) != cdsLaunchFile || pin.Anchor != nil {
			t.Fatalf("Pod CDS pin is not independently launch-file-bound: %+v", pin)
		}
	}

	if err := clearOutputs(cfg); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, cfg.path(podMarker))
	requireAbsent(t, cfg.path(Dir+"/workloads.json"))
}

// The pod launch key is the document's single signing key, matched by
// its exact bytes; the cluster server's key authorizes no pod launch.
func TestVerifyRequiresTheExactPodLaunchKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (doc Document, signer *ecdsa.PrivateKey, loaded string)
		want  string
	}{
		{"cluster server key", func(t *testing.T) (Document, *ecdsa.PrivateKey, string) {
			doc, _, _ := testPodDocument(t, "tdx")
			server, pub := testKey(t)
			doc.Server.OperatorPublicKey = pub
			return doc, server, pub
		}, "pod launch key does not match"},
		{"differently encoded key", func(t *testing.T) (Document, *ecdsa.PrivateKey, string) {
			doc, key, pub := testPodDocument(t, "tdx")
			doc.PodOperatorPublicKey = strings.TrimSpace(pub)
			return doc, key, pub
		}, "podOperatorPublicKey bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, signer, loaded := tc.setup(t)
			testLoader(t, doc, loaded)
			cfg := testConfig(t, doc, signer)
			if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			requireAbsent(t, cfg.path(podMarker))
		})
	}
}

// Every refusal of a pod document, one row per check. A pod section or
// allowlist entries are unknown keys: a pod document is always generic.
func TestValidatePodRole(t *testing.T) {
	_, agentPub := testKey(t)
	tests := []struct {
		name   string
		change func(*Document)
		append string
		want   string
	}{
		{"no cluster server address", func(d *Document) { d.Server.Address = "" }, "", "server.address"},
		{"no CDS policy", func(d *Document) { d.CDS.Measurements = "" }, "", "cds.measurements"},
		{"no cluster server key", func(d *Document) { d.Server.OperatorPublicKey = "" }, "", "server.operatorPublicKey"},
		{"no pod key", func(d *Document) { d.PodOperatorPublicKey = "" }, "", "podOperatorPublicKey"},
		{"server is equivalent pod key", func(d *Document) { d.PodOperatorPublicKey = strings.TrimSpace(d.Server.OperatorPublicKey) }, "", "must be distinct"},
		{"agent token", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "", "rke2 tokens"},
		{"agent keys", func(d *Document) { d.AgentOperatorPublicKeys = []string{agentPub} }, "", "agentOperatorPublicKeys"},
		{"registry mirrors", func(d *Document) { d.RegistryMirrors = map[string]string{"ghcr.io": "http://10.43.0.5:5000"} }, "", "registryMirrors"},
		{"no runtime register", func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "", "runtime register"},
		{"pod section", func(*Document) {}, "pod:\n  uid: " + testPodUID + "\n  namespace: tenant\n  name: app\n", "pod"},
		{"workloads", func(*Document) {}, "workloads: '" + testPodWorkloads + "'\n", "workloads"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "tdx")
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, tc.append...)
			_, err = Parse(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	doc, _, _ := testDocument(t, "tdx", Server)
	data, _ := yaml.Marshal(doc)
	if _, err := Parse(append(data, "pod:\n  uid: x\n"...)); err == nil || !strings.Contains(err.Error(), "pod") {
		t.Fatalf("server with pod section: %v", err)
	}
}

// The only happy path of NewPodBundle: a generic document.
func TestNewPodBundleStages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	serverPubPath, serverPub := writePodServerKey(t)
	if err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "tdx"), "--name", "p-1",
		"--server-address", "10.0.0.1", "--server-public-key", serverPubPath,
		"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t)); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, podDir)
	if doc.Role != Pod || doc.Node.Name != "p-1" {
		t.Fatalf("pod document %+v", doc)
	}
	if doc.Server.Address != "10.0.0.1" || doc.Server.OperatorPublicKey != serverPub || doc.PodOperatorPublicKey == serverPub {
		t.Fatal("pod bundle did not preserve the independent cluster server identity")
	}
	if doc.CDS.Address != "cds.example.org:8443" || stagedCDSPolicy(t, doc).Family != teetypes.FamilySNP {
		t.Fatal("Pod bundle lost independent DNS-addressed SNP CDS trust")
	}
	requirePresent(t, filepath.Join(dir, podKeyFile))
	stageBundleNode(t, dir, podDir)
}

// An SNP image has no runtime register to measure the pod with, so new-pod
// refuses its manifest before writing anything.
func TestNewPodBundleRefusesSNPManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	serverPubPath, _ := writePodServerKey(t)
	err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "snp"), "--name", "p-1",
		"--server-address", "10.0.0.1", "--server-public-key", serverPubPath,
		"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t))
	if err == nil || !strings.Contains(err.Error(), "TDX-only") {
		t.Fatalf("got %v, want a TDX-only refusal", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("a refused bundle left %s behind: %v", dir, statErr)
	}
}

func writePodServerKey(t *testing.T) (string, string) {
	t.Helper()
	_, pub := testKey(t)
	path := filepath.Join(t.TempDir(), "server.pub")
	if err := os.WriteFile(path, []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func writePodCDSPin(t *testing.T) string {
	t.Helper()
	return writeFile(t, "cds.json", testCDSPin(t, teetypes.FamilySNP, 2))
}
