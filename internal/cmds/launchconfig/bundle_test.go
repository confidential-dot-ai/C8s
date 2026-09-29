package launchconfig

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// writeManifest writes a build manifest of the given platform, with the
// register values every test compares against.
func writeManifest(t *testing.T, platform string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
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
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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

// runBundleCmd drives the real cobra command so flag wiring is under test.
func runBundleCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.Execute()
}

// stageBundleNode proves the bundle's document for node is what the guest
// accepts: Stage verifies the signature against the node's pubkey with the
// production code path and a self-report matching the manifest pins.
func stageBundleNode(t *testing.T, dir, node string) {
	t.Helper()
	// Staging a server mints the agent token into the rebased /run/confos,
	// a plain temp dir here; production checks the real mount is RAM-backed.
	oldOpen := openTokenDir
	t.Cleanup(func() { openTokenDir = oldOpen })
	openTokenDir = func(_, dir string) (*os.Root, error) { return os.OpenRoot(dir) }
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

func TestNewBundleBootsServerAndAgentsOnBothPlatforms(t *testing.T) {
	for _, platform := range []string{"tdx", "snp"} {
		t.Run(platform, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := []string{"new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, platform),
				"--server-address", "10.0.0.10", "--agent", "demo-f1", "--agent", "demo-f2"}
			if platform == "snp" {
				args = append(args, "--vcpus", "8")
			}
			if err := runBundleCmd(t, args...); err != nil {
				t.Fatal(err)
			}
			server, _ := readBundleDocument(t, dir, serverDir)
			if server.Role != Server || server.Node.Name != "demo-server" || server.ClusterID != "demo" || server.TLSSAN != defaultTLSSAN {
				t.Fatalf("unexpected server document: %+v", server)
			}
			if server.Image.Platform != platform {
				t.Fatalf("server image platform %q", server.Image.Platform)
			}
			if platform == "tdx" {
				if server.Image.Measurement != strings.Repeat("11", 48) || server.Image.RTMRs[1] != strings.Repeat("22", 48) || server.Image.RTMRs[2] != strings.Repeat("33", 48) {
					t.Fatalf("TDX pins not taken from the manifest: %+v", server.Image)
				}
			} else if server.Image.Measurement != strings.Repeat("55", 48) || len(server.Image.RTMRs) != 0 {
				t.Fatalf("SNP pin is not the 8-vCPU variant: %+v", server.Image)
			}
			// The bundle is public policy: no join credential may appear in
			// any document the operator attaches to a node.
			_, serverData := readBundleDocument(t, dir, serverDir)
			if bytes.Contains(serverData, []byte("rke2")) || bytes.Contains(serverData, []byte("Token")) {
				t.Fatalf("server document carries a credential: %s", serverData)
			}
			for _, name := range []string{"demo-f1", "demo-f2"} {
				agent, data := readBundleDocument(t, dir, name)
				if agent.Role != Agent || agent.Node.Name != name || agent.Server.Address != "10.0.0.10" {
					t.Fatalf("unexpected agent %s: %+v", name, agent)
				}
				if bytes.Contains(data, []byte("rke2")) || bytes.Contains(data, []byte("Token")) {
					t.Fatalf("agent %s carries a credential: %s", name, data)
				}
				if !reflect.DeepEqual(agent.Image, server.Image) ||
					agent.Server.OperatorPublicKey != server.Server.OperatorPublicKey ||
					agent.AgentOperatorPublicKeys[0] != server.AgentOperatorPublicKeys[0] {
					t.Fatalf("agent %s diverges from the server's cluster facts", name)
				}
				pub, _ := os.ReadFile(filepath.Join(dir, name, pubkeyFile))
				if string(pub) != server.AgentOperatorPublicKeys[0] {
					t.Fatalf("agent %s pubkey is not the trusted agent key", name)
				}
			}
			// The server's pubkey is the exact PEM the server document names.
			pub, _ := os.ReadFile(filepath.Join(dir, serverDir, pubkeyFile))
			if string(pub) != server.Server.OperatorPublicKey {
				t.Fatal("server pubkey differs from server.operatorPublicKey")
			}
			for _, node := range []string{serverDir, "demo-f1", "demo-f2"} {
				stageBundleNode(t, dir, node)
			}
			// server.key is the key the server document was signed with, so it
			// also serves get-kubeconfig --operator-key.
			key, err := certutil.LoadECPrivateKeyFile(filepath.Join(dir, serverKeyFile))
			if err != nil {
				t.Fatal(err)
			}
			wantPub, _ := publicKeyPEM(key)
			if wantPub != server.Server.OperatorPublicKey {
				t.Fatal("server.key does not match the server's launch public key")
			}
			// The client policy pins exactly the server entry Stage derives.
			policy, err := refvalues.Load(filepath.Join(dir, serverPolicy))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := server.referenceValues()
			if len(policy.Images) != 1 || policy.Family != want.Family || !bytes.Equal(policy.Images[0].Anchor, want.Images[0].Anchor) ||
				!bytes.Equal(policy.Images[0].Digest, want.Images[0].Digest) {
				t.Fatalf("server.json pins %+v, want the server entry %+v", policy, want.Images[0])
			}
			for _, f := range []string{serverKeyFile, agentKeyFile, filepath.Join(serverDir, documentFile), filepath.Join("demo-f1", signatureFile)} {
				info, err := os.Stat(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("%s is %v, want 0600", f, info.Mode().Perm())
				}
			}
		})
	}
}

func TestAddAgentExtendsAnExistingBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, "tdx")); err != nil {
		t.Fatal(err)
	}
	if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "late"); err == nil || !strings.Contains(err.Error(), "--server-address") {
		t.Fatalf("an agent of an autodetecting server needs an explicit address, got %v", err)
	}
	if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "late", "--server-address", "10.0.0.10"); err != nil {
		t.Fatal(err)
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	agent, _ := readBundleDocument(t, dir, "late")
	if agent.Role != Agent || agent.Server.Address != "10.0.0.10" || agent.ClusterID != server.ClusterID {
		t.Fatalf("unexpected late agent: %+v", agent)
	}
	stageBundleNode(t, dir, "late")
	for _, bad := range []string{"late", serverDir, "demo-server", "Not_A_Label"} {
		if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", bad, "--server-address", "10.0.0.10"); err == nil {
			t.Fatalf("add-agent accepted %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, serverDir, documentFile)); err != nil {
		t.Fatal("a rejected agent must not disturb the bundle:", err)
	}
}

func TestNewBundleRefusesBadInputsAndLeavesNothingBehind(t *testing.T) {
	tdx, snp := writeManifest(t, "tdx"), writeManifest(t, "snp")
	base := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"snp without vcpus", []string{"--image-manifest", snp}, "--vcpus is required"},
		{"snp unknown vcpus", []string{"--image-manifest", snp, "--vcpus", "6"}, "no SNP launch digest"},
		{"tdx with vcpus", []string{"--image-manifest", tdx, "--vcpus", "4"}, "SNP manifests only"},
		{"agent without address", []string{"--image-manifest", tdx, "--agent", "f1"}, "--server-address is required"},
		{"bad cluster id", []string{"--image-manifest", tdx, "--cluster-id", "Demo"}, "clusterID"},
		{"bad agent name", []string{"--image-manifest", tdx, "--server-address", "10.0.0.10", "--agent", "server"}, "reserved"},
		{"loopback server", []string{"--image-manifest", tdx, "--server-address", "127.0.0.1"}, "server.address"},
		{"not a manifest", []string{"--image-manifest", filepath.Join(base, "missing.json")}, "--image-manifest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "-"))
			args := append([]string{"new", "--out", dir, "--cluster-id", "demo"}, tc.args...)
			err := runBundleCmd(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("failed bundle left %s behind", dir)
			}
		})
	}
	dir := filepath.Join(base, "existing")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", tdx); err == nil {
		t.Fatal("an existing directory must not be reused for a new bundle")
	}
}

func TestNewBundleCarriesAnInitialAllowlist(t *testing.T) {
	workloads := filepath.Join(t.TempDir(), "workloads.json")
	if err := os.WriteFile(workloads, []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, "tdx"),
		"--tls-san", "cluster.example", "--workloads", workloads)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	if server.TLSSAN != "cluster.example" || server.Workloads == "" {
		t.Fatalf("SAN or workloads not carried: %+v", server)
	}
	stageBundleNode(t, dir, serverDir)
}
