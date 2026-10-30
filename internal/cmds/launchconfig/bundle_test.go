package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
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

// componentSeed is the release asset `launch-config new` takes the cluster's
// component entries from.
const componentSeed = `{"schema":"c8s.allowlist/v1","workloads":{"c8s-operator":{"containers":[{"digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `"}]}}}`

const tenantWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"tenant-app":{"containers":[{"digest":"sha256:` +
	"2222222222222222222222222222222222222222222222222222222222222222" + `"}]}}}`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeCDSManifest writes the CDS guest image's own manifest: a TDX image
// whose measurements differ from every node manifest, so a pin built from one
// cannot pass for the other.
func writeCDSManifest(t *testing.T) string {
	t.Helper()
	body := `{"version":1,"build":{"platform":"tdx"},"tdx":{"mrtd":"` + strings.Repeat("c1", 48) +
		`","rtmr1":"` + strings.Repeat("c2", 48) + `","rtmr2":"` + strings.Repeat("c3", 48) + `"}}`
	return writeFile(t, "cds-manifest.json", body)
}

// cdsInputs name the CDS VM every bundle trusts: a TDX VM, whose TEE family
// need not be the one its nodes boot on.
func cdsInputs(t *testing.T) []string {
	t.Helper()
	return []string{
		"--cds-address", "192.0.2.50:8443",
		"--cds-image-manifest", writeCDSManifest(t),
		"--cds-platform", "tdx",
		"--cds-node-cidr", "10.0.0.0/24",
		"--cds-allowlist-seed", writeFile(t, "allowlist-seed-tdx.json", componentSeed),
	}
}

// bundleArgs are the flags `new` always needs: an output directory, a cluster,
// the node image its nodes boot and the CDS VM they trust.
func bundleArgs(t *testing.T, dir, platform string) []string {
	t.Helper()
	args := []string{"new", "--out", dir, "--cluster-id", "demo", "--image-manifest", writeManifest(t, platform)}
	return append(args, cdsInputs(t)...)
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

// readBundleCDSConfig parses the launch file the bundle's CDS VM boots on.
func readBundleCDSConfig(t *testing.T, dir string) *cdsconfig.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, cdsconfig.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := cdsconfig.Parse(data)
	if err != nil {
		t.Fatalf("the bundle's CDS configuration does not parse: %v", err)
	}
	return cfg
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
	if staged.Node.Name != doc.Node.Name || staged.Role != doc.Role || !reflect.DeepEqual(staged.Router, doc.Router) {
		t.Fatalf("staged %s %q for bundle entry %q", staged.Role, staged.Node.Name, node)
	}
}

func TestNewBundleBootsServerAndAgentsOnBothPlatforms(t *testing.T) {
	for _, platform := range []string{"tdx", "snp"} {
		t.Run(platform, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := append(bundleArgs(t, dir, platform),
				"--server-address", "10.0.0.10", "--agent", "demo-f1", "--agent", "demo-f2")
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
			if server.RKE2.ServerToken == server.RKE2.AgentToken || !tokenRE.MatchString(server.RKE2.ServerToken) {
				t.Fatalf("tokens not generated independently: %+v", server.RKE2)
			}
			// Every node has its own node password, carried only in its own
			// document: the shared agent token opens no other node's name.
			passwords := map[string]string{server.RKE2.NodePassword: serverDir}
			if !tokenRE.MatchString(server.RKE2.NodePassword) {
				t.Fatalf("server node password %q", server.RKE2.NodePassword)
			}
			for _, name := range []string{"demo-f1", "demo-f2"} {
				agent, data := readBundleDocument(t, dir, name)
				if p := agent.RKE2.NodePassword; !tokenRE.MatchString(p) || passwords[p] != "" {
					t.Fatalf("agent %s node password %q is missing or shared", name, p)
				}
				passwords[agent.RKE2.NodePassword] = name
				if bytes.Contains(data, []byte(server.RKE2.NodePassword)) {
					t.Fatalf("agent %s carries the server's node password", name)
				}
				if agent.Role != Agent || agent.Node.Name != name || agent.Server.Address != "10.0.0.10" {
					t.Fatalf("unexpected agent %s: %+v", name, agent)
				}
				if bytes.Contains(data, []byte(server.RKE2.ServerToken)) || bytes.Contains(data, []byte("serverToken")) {
					t.Fatalf("agent %s carries the server token", name)
				}
				if agent.RKE2.AgentToken != server.RKE2.AgentToken || !reflect.DeepEqual(agent.Image, server.Image) ||
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
			if len(policy.Images) != 1 || policy.Family != want.Family || string(policy.Images[0].Anchor) != server.Server.OperatorPublicKey ||
				!bytes.Equal(policy.Images[0].Digest, mustDecodeHex(server.Image.Measurement)) {
				t.Fatalf("server.json does not pin the server image and launch key: %+v", policy)
			}
			// peers.json is the full set CDS admits and serves: the server
			// entry plus one agent entry under the bundle's agent key.
			peers, err := refvalues.Load(filepath.Join(dir, peersPolicy))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(peers, want) {
				t.Fatalf("peers.json = %+v, want server.referenceValues() %+v", peers, want)
			}
			if len(peers.Images) != 2 || bytes.Equal(peers.Images[0].Anchor, peers.Images[1].Anchor) {
				t.Fatalf("peers.json must hold two entries with distinct launch-key anchors: %+v", peers.Images)
			}
			if missing, _ := refvalues.Diff(policy, peers); len(missing) != 0 {
				t.Fatal("server.json is missing from peers.json")
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

// Every node document names one CDS VM and carries the pin binding it to the
// configuration the bundle wrote, which is what makes that VM an identity and
// not just an address. The VM's TEE family is its own, not the nodes'.
func TestNewBundleNamesOneCDSEveryNodeTrusts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	args := append(bundleArgs(t, dir, "snp"), "--vcpus", "8", "--server-address", "10.0.0.10", "--agent", "demo-f1")
	if err := runBundleCmd(t, args...); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(dir, cdsconfig.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := refvalues.Load(filepath.Join(dir, cdsconfig.PinFile))
	if err != nil {
		t.Fatal(err)
	}
	if pin.Family != teetypes.FamilyTDX || len(pin.Images) == 0 {
		t.Fatalf("CDS pin = %+v, want the TDX VM the bundle names", pin)
	}
	for _, image := range pin.Images {
		if !bytes.Equal(image.LaunchFile, config) {
			t.Fatalf("CDS pin entry %s does not bind the configuration that was written", image.Name)
		}
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	cds := readBundleCDSConfig(t, dir)
	if string(cds.OperatorKeys.PEM()) != server.Server.OperatorPublicKey {
		t.Fatal("the CDS configuration does not authorize this cluster's operator key")
	}
	peers, err := refvalues.Load(filepath.Join(dir, peersPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cds.Nodes, peers) {
		t.Fatalf("the CDS configuration admits %+v, want the bundle's peer policy %+v", cds.Nodes, peers)
	}
	for _, node := range []string{serverDir, "demo-f1"} {
		doc, _ := readBundleDocument(t, dir, node)
		if doc.CDS.Address != "192.0.2.50:8443" {
			t.Fatalf("%s names CDS at %+v", node, doc.CDS)
		}
		named, err := refvalues.Parse([]byte(doc.CDS.Measurements))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(named, pin) {
			t.Fatalf("%s carries a CDS pin other than the bundle's", node)
		}
		stageBundleNode(t, dir, node)
	}
}

func TestAddAgentExtendsAnExistingBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, bundleArgs(t, dir, "tdx")...); err != nil {
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
	if agent.Role != Agent || agent.Server.Address != "10.0.0.10" || agent.RKE2.AgentToken != server.RKE2.AgentToken {
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
		{"dns mirror", []string{"--image-manifest", tdx, "--registry-mirror", "ghcr.io=http://cache.example"}, "registryMirrors"},
		{"duplicate mirror", []string{"--image-manifest", tdx, "--registry-mirror", "ghcr.io=http://10.43.0.5", "--registry-mirror", "ghcr.io=http://10.43.0.6"}, "more than once"},
		{"mirror without endpoint", []string{"--image-manifest", tdx, "--registry-mirror", "ghcr.io"}, "registry=http"},
		{"cds platform alias", []string{"--image-manifest", tdx, "--cds-platform", "snp"}, "want sev-snp or tdx"},
		{"snp cds without vcpus", []string{"--image-manifest", tdx, "--cds-image-manifest", snp, "--cds-platform", "sev-snp"}, "name the counts"},
		{"cds address without port", []string{"--image-manifest", tdx, "--cds-address", "192.0.2.50"}, "--cds-address"},
		{"node external ip not an ip", []string{"--image-manifest", tdx, "--node-external-ip", "not-an-ip"}, "--node-external-ip"},
		{"node external ip outside node cidr", []string{"--image-manifest", tdx, "--node-external-ip", "198.51.100.7"}, "outside every --cds-node-cidr"},
		{"tenant entry takes a component name", []string{"--image-manifest", tdx, "--tenant-workloads", writeFile(t, "workloads.json", componentSeed)}, "is a component entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "-"))
			args := append(append([]string{"new", "--out", dir, "--cluster-id", "demo"}, cdsInputs(t)...), tc.args...)
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
	if err := runBundleCmd(t, bundleArgs(t, dir, "tdx")...); err == nil {
		t.Fatal("an existing directory must not be reused for a new bundle")
	}
}

// A node subnet reaching into the pod or service range the node image's RKE2
// configuration fixes would let a pod there answer as a node's admission
// inventory. The subnets are this run's only ones, so nothing else admits it.
func TestNewBundleRefusesANodeSubnetHoldingClusterAddresses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "demo",
		"--image-manifest", writeManifest(t, "tdx"),
		"--cds-address", "192.0.2.50:8443",
		"--cds-image-manifest", writeCDSManifest(t),
		"--cds-platform", "tdx",
		"--cds-node-cidr", "10.52.0.0/24",
		"--cds-allowlist-seed", writeFile(t, "allowlist-seed-tdx.json", componentSeed))
	if err == nil || !strings.Contains(err.Error(), "overlaps the cluster range") {
		t.Fatalf("got %v, want the overlapping node subnet refused", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("the refused bundle left %s behind", dir)
	}
}

// The front-door name a cluster is installed with is what its CDS may sign
// onto a leaf, and the tenant workloads join the component entries CDS serves.
func TestNewBundleCarriesTheFrontDoorNameAndTenantWorkloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	args := append(bundleArgs(t, dir, "tdx"),
		"--tls-san", "cluster.example", "--tenant-workloads", writeFile(t, "workloads.json", tenantWorkloads))
	if err := runBundleCmd(t, args...); err != nil {
		t.Fatal(err)
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	if server.TLSSAN != "cluster.example" {
		t.Fatalf("front-door name not carried: %+v", server)
	}
	cds := readBundleCDSConfig(t, dir)
	if len(cds.DNSSANPatterns) != 2 || !cds.DNSSANPatterns[0].MatchString("mesh.c8s-system.svc") || !cds.DNSSANPatterns[1].MatchString("cluster.example") {
		t.Fatalf("CDS leaf DNS rules = %v", cds.DNSSANPatterns)
	}
	for _, name := range []string{"c8s-operator", "tenant-app"} {
		if _, served := cds.Workloads.Workloads[name]; !served {
			t.Fatalf("the CDS configuration does not serve %s: %v", name, cds.Workloads.Workloads)
		}
	}
	stageBundleNode(t, dir, serverDir)
}

func TestNewBundleCarriesASignedServerRouter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"),
		"--server-address", "10.0.0.10", "--agent", "worker-1",
		"--router-hostname", "candidate.api.confidential.ai", "--router-hostname", "api.confidential.ai",
		"--acme-email", "ops@confidential.ai",
		"--acme-directory-url", "https://acme-staging-v02.api.letsencrypt.org/directory")...)
	if err != nil {
		t.Fatal(err)
	}
	server, data := readBundleDocument(t, dir, serverDir)
	want := Router{
		Hostnames:        []string{"candidate.api.confidential.ai", "api.confidential.ai"},
		ACMEEmail:        "ops@confidential.ai",
		ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
	}
	if server.Router == nil || !reflect.DeepEqual(*server.Router, want) {
		t.Fatalf("server router = %+v", server.Router)
	}
	// The router block sits in the signed bytes: Stage verifies the detached
	// signature over the whole document, and the staged copy keeps the block.
	if !bytes.Contains(data, []byte("candidate.api.confidential.ai")) {
		t.Fatal("router block missing from the signed document")
	}
	stageBundleNode(t, dir, serverDir)
	agent, _ := readBundleDocument(t, dir, "worker-1")
	if agent.Router != nil {
		t.Fatalf("agent inherited the server-only router block: %+v", agent.Router)
	}
	stageBundleNode(t, dir, "worker-1")
}

func TestNewBundleCarriesARouterBodyLimitAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"), "--router-max-request-body-bytes", "67108864")...)
	if err != nil {
		t.Fatal(err)
	}
	server, data := readBundleDocument(t, dir, serverDir)
	if server.Router == nil || server.Router.MaxRequestBodyBytes != 64<<20 || len(server.Router.Hostnames) != 0 {
		t.Fatalf("server router = %+v", server.Router)
	}
	if !bytes.Contains(data, []byte("maxRequestBodyBytes: 67108864")) {
		t.Fatal("body limit missing from the signed document")
	}
	stageBundleNode(t, dir, serverDir)
}

func TestNewBundleCarriesRegistryMirrorsToEveryNode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"),
		"--server-address", "10.0.0.10", "--agent", "demo-agent-1", "--registry-mirror", "ghcr.io=http://10.43.0.5:5000")...)
	if err != nil {
		t.Fatal(err)
	}
	if err := runBundleCmd(t, "add-agent", "--bundle", dir, "--name", "late"); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{serverDir, "demo-agent-1", "late"} {
		doc, _ := readBundleDocument(t, dir, node)
		if doc.RegistryMirrors["ghcr.io"] != "http://10.43.0.5:5000" {
			t.Fatalf("%s lost the registry mirror: %+v", node, doc.RegistryMirrors)
		}
		stageBundleNode(t, dir, node)
	}
}

func TestNewBundleCarriesTheServerNodeExternalIP(t *testing.T) {
	// The external IP must fall inside a --cds-node-cidr (the test's is
	// 10.0.0.0/24, see cdsInputs), the same constraint CDS enforces.
	dir := filepath.Join(t.TempDir(), "bundle")
	err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"),
		"--server-address", "10.0.0.10", "--node-external-ip", "10.0.0.77")...)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, serverDir)
	if doc.Node.ExternalIP != "10.0.0.77" {
		t.Fatalf("server node.externalIP = %q, want 10.0.0.77", doc.Node.ExternalIP)
	}
	stageBundleNode(t, dir, serverDir)
}

// writeOperatorKey writes a P-256 key and its public half the way
// `c8s keys new` does, returning both paths.
func writeOperatorKey(t *testing.T) (keyPath, pubPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, pubPath = filepath.Join(dir, "op.key"), filepath.Join(dir, "op.pub")
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyPath, pubPath
}

// An existing operator key becomes the server launch key unchanged: the
// server's pubkey is the pinned file byte for byte, and the node boots.
func TestNewBundleReusesTheOperatorKey(t *testing.T) {
	keyPath, pubPath := writeOperatorKey(t)
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, append(bundleArgs(t, dir, "tdx"),
		"--server-address", "10.0.0.10", "--agent", "demo-f1",
		"--operator-key", keyPath, "--operator-pubkey", pubPath)...); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(pubPath)
	got, err := os.ReadFile(filepath.Join(dir, serverDir, pubkeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("server pubkey is not the operator's public key")
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	if server.Server.OperatorPublicKey != string(want) {
		t.Fatal("server.operatorPublicKey is not the operator's public key")
	}
	if _, err := os.Stat(filepath.Join(dir, serverKeyFile)); !os.IsNotExist(err) {
		t.Fatal("the bundle holds a copy of the operator key")
	}
	agentPub, _ := os.ReadFile(filepath.Join(dir, "demo-f1", pubkeyFile))
	if bytes.Equal(agentPub, want) {
		t.Fatal("the agent reuses the operator key")
	}
	stageBundleNode(t, dir, serverDir)
	stageBundleNode(t, dir, "demo-f1")
}

func TestNewBundleRefusesAMismatchedOperatorPubkey(t *testing.T) {
	keyPath, _ := writeOperatorKey(t)
	_, otherPub := writeOperatorKey(t)
	_, samePub := writeOperatorKey(t)
	// The same key in a different encoding would change SNP HOST_DATA.
	key, _ := certutil.LoadECPrivateKeyFile(keyPath)
	pub, _ := publicKeyPEM(key)
	if err := os.WriteFile(samePub, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384PEM, err := certutil.MarshalECKeyPEM(p384)
	if err != nil {
		t.Fatal(err)
	}
	p384Key := filepath.Join(t.TempDir(), "p384.key")
	if err := os.WriteFile(p384Key, p384PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"other key", []string{"--operator-key", keyPath, "--operator-pubkey", otherPub}, "does not match"},
		{"other encoding", []string{"--operator-key", keyPath, "--operator-pubkey", samePub}, "another encoding"},
		{"pubkey alone", []string{"--operator-pubkey", otherPub}, "--operator-key"},
		{"not a key", []string{"--operator-key", otherPub}, "--operator-key"},
		{"not P-256", []string{"--operator-key", p384Key, "--operator-pubkey", otherPub}, "P-256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := append(bundleArgs(t, dir, "tdx"), tc.args...)
			err := runBundleCmd(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("a refused bundle left its directory behind")
			}
		})
	}
}
