package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func testCAPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// testWorkerDocument returns a worker document, the pool's launch key and
// its public key.
func testWorkerDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, key, pub := testDocument(t, platform, Agent)
	doc.Role = Worker
	doc.Node = Node{}
	doc.RKE2 = RKE2{}
	doc.Kubernetes = &Kubernetes{
		APIServer: "c-0123.k8s.example", CACertificate: testCAPEM(t, true),
		ClusterDNS: "10.96.0.10", PodCIDR: "10.244.0.0/16", ServiceCIDR: "10.96.0.0/12",
	}
	return doc, key, pub
}

func TestStageWorkerRole(t *testing.T) {
	for _, platform := range []string{"snp", "tdx"} {
		t.Run(platform, func(t *testing.T) {
			doc, key, pub := testWorkerDocument(t, platform)
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
			requirePresent(t, cfg.path(workerMarker))
			for _, path := range []string{serverMarker, agentMarker, podMarker, serverTokenPath, agentTokenPath, rke2FragmentPath, nodePasswordPath} {
				requireAbsent(t, cfg.path(path))
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.Role != Worker || staged.Kubernetes.ClusterDomain != "cluster.local" {
				t.Fatalf("staged %s, cluster domain %q", staged.Role, staged.Kubernetes.ClusterDomain)
			}

			raw, err := os.ReadFile(cfg.path(workerBootstrapKubeconfig))
			if err != nil {
				t.Fatal(err)
			}
			var kubeconfig clientcmdv1.Config
			if err := yaml.UnmarshalStrict(raw, &kubeconfig); err != nil {
				t.Fatal(err)
			}
			cluster := kubeconfig.Clusters[0].Cluster
			if cluster.Server != "https://c-0123.k8s.example" || string(cluster.CertificateAuthorityData) != doc.Kubernetes.CACertificate {
				t.Fatalf("bootstrap kubeconfig trusts %s with another CA", cluster.Server)
			}
			exec := kubeconfig.AuthInfos[0].AuthInfo.Exec
			if exec == nil || !exec.ProvideClusterInfo || exec.Command != credentialPlugin || exec.InteractiveMode != clientcmdv1.NeverExecInteractiveMode {
				t.Fatalf("bootstrap user %+v", exec)
			}
			block, _ := pem.Decode([]byte(doc.Kubernetes.CACertificate))
			sum := sha256.Sum256(block.Bytes)
			want := []string{
				"node-credential",
				"--cds-url=https://10.0.0.1:30808",
				"--image-policy-file=" + Dir + "/cds.json",
				"--attestation-api-url=" + DefaultAttestationAPIURL,
				"--api-server=c-0123.k8s.example",
				"--api-ca-sha256=" + hex.EncodeToString(sum[:]),
			}
			if platform == "tdx" {
				want = append(want, "--measured-policies-file="+armtls.NodeJournal)
			}
			if !slices.Equal(exec.Args, want) {
				t.Fatalf("plugin args\n got %q\nwant %q", exec.Args, want)
			}

			dropIn, err := os.ReadFile(cfg.path(workerKubeletDropIn))
			if err != nil {
				t.Fatal(err)
			}
			var kubelet map[string]any
			if err := yaml.Unmarshal(dropIn, &kubelet); err != nil {
				t.Fatal(err)
			}
			if kubelet["kind"] != "KubeletConfiguration" || kubelet["clusterDomain"] != "cluster.local" || !slices.Equal(kubelet["clusterDNS"].([]any), []any{"10.96.0.10"}) {
				t.Fatalf("kubelet drop-in %s", dropIn)
			}
			// The drop-in sets the cluster's values and the CA, nothing the
			// baked file decides.
			if len(kubelet) != 5 || kubelet["authentication"].(map[string]any)["x509"].(map[string]any)["clientCAFile"] != workerCA {
				t.Fatalf("kubelet drop-in %s", dropIn)
			}
		})
	}
}

// A worker's launch key is one of the pool keys CDS admits as nodes, and
// never CDS's own.
func TestVerifyWorkerLaunchKey(t *testing.T) {
	doc, _, _ := testWorkerDocument(t, "tdx")
	serverKey, _ := testKey(t)
	other, otherPub := testKey(t)
	for name, signer := range map[string]struct {
		key *ecdsa.PrivateKey
		pub string
	}{
		"CDS's key":       {serverKey, doc.Server.OperatorPublicKey},
		"an unlisted key": {other, otherPub},
	} {
		t.Run(name, func(t *testing.T) {
			testLoader(t, doc, signer.pub)
			cfg := testConfig(t, doc, signer.key)
			if err := Stage(context.Background(), cfg); err == nil {
				t.Fatal("a worker staged under a launch key its pool does not list")
			}
		})
	}
}

func TestValidateWorkerRole(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"no kubernetes", func(d *Document) { d.Kubernetes = nil }, "requires a kubernetes section"},
		{"node name", func(d *Document) { d.Node.Name = "worker-1" }, "must not carry a node section"},
		{"node ip", func(d *Document) { d.Node.IP = "10.0.0.9" }, "must not carry a node section"},
		{"agent token", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "must not carry rke2 tokens"},
		{"node password", func(d *Document) { d.RKE2.NodePassword = strings.Repeat("c", 64) }, "rke2.nodePassword"},
		{"no pool keys", func(d *Document) { d.AgentOperatorPublicKeys = nil }, "requires agentOperatorPublicKeys"},
		{"no CDS address", func(d *Document) { d.Server.Address = "" }, "server.address"},
		{"router", func(d *Document) { d.Router = &Router{} }, "router is server-only"},
		{"pod", func(d *Document) { d.Pod = &PodSpec{} }, "pod section requires role pod"},
		// Whoever runs the cluster signs the pool's document, so it may not
		// add to what CDS's policy admits.
		{"workloads", func(d *Document) { d.Workloads = `{"version":"c8s.allowlist/v1","workloads":{}}` }, "takes no workloads"},
		{"api server URL", func(d *Document) { d.Kubernetes.APIServer = "https://c-0123.k8s.example" }, "kubernetes.apiServer"},
		{"api server IP", func(d *Document) { d.Kubernetes.APIServer = "192.0.2.1" }, "kubernetes.apiServer"},
		{"two CAs", func(d *Document) { d.Kubernetes.CACertificate += testCAPEM(t, true) }, "exactly one PEM certificate"},
		{"leaf CA", func(d *Document) { d.Kubernetes.CACertificate = testCAPEM(t, false) }, "not a CA certificate"},
		{"no CA", func(d *Document) { d.Kubernetes.CACertificate = "" }, "exactly one PEM certificate"},
		{"DNS outside services", func(d *Document) { d.Kubernetes.ClusterDNS = "10.244.0.10" }, "inside kubernetes.serviceCIDR"},
		{"DNS loopback", func(d *Document) { d.Kubernetes.ClusterDNS = "127.0.0.1" }, "kubernetes.clusterDNS"},
		{"overlap", func(d *Document) { d.Kubernetes.PodCIDR = "10.96.0.0/16" }, "overlap"},
		{"unmasked", func(d *Document) { d.Kubernetes.PodCIDR = "10.244.1.0/16" }, "kubernetes.podCIDR"},
		{"IPv6", func(d *Document) { d.Kubernetes.ServiceCIDR = "fd00::/108" }, "kubernetes.serviceCIDR"},
		{"domain", func(d *Document) { d.Kubernetes.ClusterDomain = "Cluster.Local" }, "kubernetes.clusterDomain"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testWorkerDocument(t, "tdx")
			tc.change(&doc)
			err := doc.validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validate = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("kubernetes on an agent", func(t *testing.T) {
		doc, _, _ := testDocument(t, "tdx", Agent)
		worker, _, _ := testWorkerDocument(t, "tdx")
		doc.Kubernetes = worker.Kubernetes
		if err := doc.validate(); err == nil || !strings.Contains(err.Error(), "requires role worker") {
			t.Fatalf("validate = %v", err)
		}
	})
}

func TestNewWorkerBundleStages(t *testing.T) {
	in := t.TempDir()
	ca := filepath.Join(in, "ca.crt")
	caPEM := testCAPEM(t, true)
	if err := os.WriteFile(ca, []byte(caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	serverPubPath, serverPub := writePodServerKey(t)
	dir := filepath.Join(t.TempDir(), "bundle")
	args := func(out string, extra ...string) []string {
		return append([]string{"new-worker", "--out", out, "--cluster-id", "cluster-one", "--image-manifest", writeManifest(t, "tdx"),
			"--server-address", "10.0.0.1", "--server-public-key", serverPubPath,
			"--api-server", "c-0123.k8s.example", "--api-ca", ca, "--cluster-dns", "10.96.0.10",
			"--pod-cidr", "10.244.0.0/16", "--service-cidr", "10.96.0.0/12"}, extra...)
	}
	if err := runBundleCmd(t, args(dir)...); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, workerDir)
	pub, err := os.ReadFile(filepath.Join(dir, workerDir, pubkeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Role != Worker || doc.Node != (Node{}) || !slices.Equal(doc.AgentOperatorPublicKeys, []string{string(pub)}) {
		t.Fatalf("worker document %+v", doc)
	}
	if doc.Server.Address != "10.0.0.1" || doc.Server.OperatorPublicKey != serverPub || doc.Kubernetes.CACertificate != caPEM {
		t.Fatal("worker bundle did not pin its CDS and CA")
	}
	requirePresent(t, filepath.Join(dir, workerKeyFile))

	// Every node of the pool stages the one document as it is.
	testLoader(t, *doc, string(pub))
	cfg := Config{
		Platform: "tdx", RootDir: t.TempDir(),
		DocumentPath:  filepath.Join(dir, workerDir, documentFile),
		SignaturePath: filepath.Join(dir, workerDir, signatureFile),
	}
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatalf("stage the pool's document: %v", err)
	}
	requirePresent(t, cfg.path(workerMarker))

	again := filepath.Join(t.TempDir(), "again")
	if err := runBundleCmd(t, args(again, "--launch-key", filepath.Join(dir, workerKeyFile))...); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, filepath.Join(again, workerKeyFile))
	second, _ := os.ReadFile(filepath.Join(again, workerDir, pubkeyFile))
	if string(second) != string(pub) {
		t.Fatal("--launch-key did not reuse the pool key")
	}
	shared := filepath.Join(t.TempDir(), "shared")
	if err := runBundleCmd(t, append(args(shared, "--launch-key", filepath.Join(dir, workerKeyFile)), "--server-public-key", filepath.Join(dir, workerDir, pubkeyFile))...); err == nil {
		t.Fatal("bundle accepted a pool key equal to CDS's")
	}
	requireAbsent(t, shared)
}
