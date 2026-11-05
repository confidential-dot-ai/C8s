package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"slices"
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

// testPodDocument returns a pod document, its launch key and public key.
func testPodDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, _, _ := testDocument(t, platform, Server)
	key, pub := testKey(t)
	doc.Role = Pod
	doc.RKE2 = RKE2{}
	doc.AgentOperatorPublicKeys = nil
	doc.PodOperatorPublicKey = pub
	doc.Workloads = testPodWorkloads
	doc.Pod = &PodSpec{UID: testPodUID, Namespace: "tenant", Name: "app", Manifest: testPodManifest("")}
	return doc, key, pub
}

// A pod document stages its trust and pod, and nothing of a cluster node.
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
	if staged.Role != Pod || staged.Pod == nil || staged.Pod.UID != testPodUID || staged.PodOperatorPublicKey != pub || staged.Server != doc.Server || staged.CDS != doc.CDS || staged.Workloads != testPodWorkloads {
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

// Every refusal of a pod document, one row per check.
func TestValidatePodRole(t *testing.T) {
	_, agentPub := testKey(t)
	tests := []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"no cluster server address", func(d *Document) { d.Server.Address = "" }, "server.address"},
		{"no CDS policy", func(d *Document) { d.CDS.Measurements = "" }, "cds.measurements"},
		{"no cluster server key", func(d *Document) { d.Server.OperatorPublicKey = "" }, "server.operatorPublicKey"},
		{"no pod key", func(d *Document) { d.PodOperatorPublicKey = "" }, "podOperatorPublicKey"},
		{"server is equivalent pod key", func(d *Document) { d.PodOperatorPublicKey = strings.TrimSpace(d.Server.OperatorPublicKey) }, "must be distinct"},
		{"agent token", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "rke2 tokens"},
		{"agent keys", func(d *Document) { d.AgentOperatorPublicKeys = []string{agentPub} }, "agentOperatorPublicKeys"},
		{"generic workloads", func(d *Document) { d.Pod = nil }, "must not carry workloads"},
		{"no runtime register", func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "runtime register"},
		{"bad uid", func(d *Document) { d.Pod.UID = "Not A UID" }, "pod.uid"},
		{"bad namespace", func(d *Document) { d.Pod.Namespace = "Tenant" }, "pod.namespace"},
		{"uid mismatch", func(d *Document) { d.Pod.UID = "other" }, "must match"},
		{"not a pod", func(d *Document) { d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"Pod"`, `"Deployment"`, 1) }, "v1 Pod"},
		{"unknown field", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"bogus":true`) }, "pod.manifest"},
		{"host network", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"hostNetwork":true`) }, "host namespaces"},
		{"platform container", func(d *Document) {
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"name":"app","image"`, `"name":"c8s-mesh","image"`, 1)
		}, "reserved"},
		{"guest status ingress", func(d *Document) {
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"name":"app","image"`, `"name":"app","ports":[{"containerPort":8443}],"image"`, 1)
		}, "reserved"},
		{"local peer", func(d *Document) { d.Pod.MeshPeers = []string{"169.254.169.254:80"} }, "pod.meshPeers"},
		{"Pod subnet peer", func(d *Document) { d.Pod.MeshPeers = []string{"10.255.254.1:8400"} }, "pod.meshPeers"},
		{"IPv6 peer", func(d *Document) { d.Pod.MeshPeers = []string{"[2001:db8::1]:80"} }, "pod.meshPeers"},
		{"peer without port", func(d *Document) { d.Pod.MeshPeers = []string{"192.0.2.1"} }, "pod.meshPeers"},
		{"tag-only image", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"image":"busybox@sha256:`+strings.Repeat("a", 64)+`"`, `"image":"busybox:1.36"`, 1)
		}, "pin the image by digest"},
		{"tag-only init image", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"initContainers":[{"name":"init","image":"busybox"}]`)
		}, "pin the image by digest"},
		{"sha512 digest", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), "sha256:"+strings.Repeat("a", 64), "sha512:"+strings.Repeat("a", 128), 1)
		}, "not sha256"},
		{"disk emptyDir", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"d","emptyDir":{}}]`)
		}, "medium: Memory"},
		{"host path", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"h","hostPath":{"path":"/"}}]`)
		}, "only emptyDir"},
		{"host port", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","ports":[{"containerPort":80,"hostPort":80}],"image"`, 1)
		}, "hostPort"},
		{"privileged", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","securityContext":{"privileged":true},"image"`, 1)
		}, "privileged"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "tdx")
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	doc, _, _ := testDocument(t, "tdx", Server)
	doc.Pod = &PodSpec{}
	data, _ := yaml.Marshal(doc)
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "requires role pod") {
		t.Fatalf("server with pod section: %v", err)
	}
}

// The only happy path of NewPodBundle.
func TestNewPodBundleStages(t *testing.T) {
	manifest := writeFile(t, "pod.json", testPodManifest(""))
	workloads := writeFile(t, "workloads.json", testPodWorkloads)
	dir := filepath.Join(t.TempDir(), "bundle")
	serverPubPath, serverPub := writePodServerKey(t)
	if err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "tdx"), "--pod-manifest", manifest, "--workloads", workloads,
		"--server-address", "10.0.0.1", "--server-public-key", serverPubPath,
		"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t),
		"--mesh-peer", "192.0.2.1:15006", "--mesh-peer", "192.0.2.1:31000"); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, podDir)
	if !slices.Equal(doc.Pod.MeshPeers, []string{"192.0.2.1:15006", "192.0.2.1:31000"}) {
		t.Fatalf("signed mesh peers = %v", doc.Pod.MeshPeers)
	}
	if doc.Role != Pod || doc.Node.Name != "p-"+testPodUID || doc.Pod.Namespace != "tenant" {
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
