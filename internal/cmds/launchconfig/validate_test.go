package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

func TestValidateRejectsEachMalformedField(t *testing.T) {
	_, otherPub := testKey(t)
	tests := []struct {
		name   string
		role   Role
		change func(*Document)
		want   string
	}{
		{"schema", Server, func(d *Document) { d.SchemaVersion = "c8s-launch/v0" }, "schemaVersion"},
		{"cluster label", Server, func(d *Document) { d.ClusterID = "Cluster_One" }, "clusterID"},
		{"node label", Server, func(d *Document) { d.Node.Name = "-node" }, "node.name"},
		{"platform", Server, func(d *Document) { d.Image.Platform = "sgx" }, "image.platform"},
		{"measurement length", Server, func(d *Document) { d.Image.Measurement = "abcd" }, "image.measurement"},
		{"measurement case", Server, func(d *Document) { d.Image.Measurement = strings.Repeat("AB", 48) }, "image.measurement"},
		{"measurement hex", Server, func(d *Document) { d.Image.Measurement = strings.Repeat("zz", 48) }, "image.measurement"},
		{"snp with rtmrs", Server, func(d *Document) {
			d.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
		}, "SNP image cannot"},
		{"server address", Server, func(d *Document) { d.Server.Address = "224.0.0.1" }, "server.address"},
		{"server address v6", Server, func(d *Document) { d.Server.Address = "2001:db8::1" }, "server.address"},
		{"node ip", Server, func(d *Document) { d.Node.IP = "not-an-ip" }, "node.ip"},
		{"external ip", Server, func(d *Document) { d.Node.ExternalIP = "127.0.0.1" }, "node.externalIP"},
		{"agent token", Server, func(d *Document) { d.RKE2.AgentToken = "short" }, "rke2.agentToken"},
		{"missing server token", Server, func(d *Document) { d.RKE2.ServerToken = "" }, "rke2.serverToken"},
		{"server key", Server, func(d *Document) { d.Server.OperatorPublicKey = "not a key" }, "server.operatorPublicKey"},
		{"agent key", Server, func(d *Document) { d.AgentOperatorPublicKeys = []string{"not a key"} }, "agentOperatorPublicKeys"},
		{"duplicate agent keys", Server, func(d *Document) {
			d.AgentOperatorPublicKeys = append(d.AgentOperatorPublicKeys, d.AgentOperatorPublicKeys[0])
		}, "nonduplicated"},
		{"too many agent keys", Server, func(d *Document) {
			d.AgentOperatorPublicKeys = make([]string, maxAgentKeys+1)
			for i := range d.AgentOperatorPublicKeys {
				d.AgentOperatorPublicKeys[i] = otherPub
			}
		}, "too many"},
		{"agent without keys", Agent, func(d *Document) { d.AgentOperatorPublicKeys = nil }, "requires agentOperatorPublicKeys"},
		{"tls san length", Server, func(d *Document) { d.TLSSAN = strings.Repeat("a", 254) }, "DNS name length"},
		{"tls san label", Server, func(d *Document) { d.TLSSAN = "C8S.Local" }, "lowercase DNS hostname"},
		{"workloads json", Server, func(d *Document) { d.Workloads = "{" }, "valid JSON"},
		{"workloads schema", Server, func(d *Document) { d.Workloads = `{"schema":"other/v1","workloads":{}}` }, "workloads:"},
		{"router on agent", Agent, func(d *Document) { d.Router = &Router{Upstream: testUpstream} }, "router is server-only"},
		{"empty router on agent", Agent, func(d *Document) { d.Router = &Router{} }, "router is server-only"},
		{"router upstream unmeshed", Server, func(d *Document) {
			d.Router = &Router{Upstream: "gateway.confidential-inference.svc.cluster.local:8080"}
		}, "router.upstream"},
		{"router upstream scheme", Server, func(d *Document) { d.Router = &Router{Upstream: "http://" + testUpstream} }, "router.upstream"},
		{"router upstream injection", Server, func(d *Document) { d.Router = &Router{Upstream: testUpstream + `"; return 200 "x`} }, "router.upstream"},
		{"router upstream port", Server, func(d *Document) { d.Router = &Router{Upstream: "c8s-gateway.ns.svc.cluster.local:70000"} }, "port"},
		{"router hostname ip", Server, func(d *Document) { d.Router = &Router{Hostnames: []string{"10.0.0.1"}} }, "router.hostnames"},
		{"router hostname wildcard", Server, func(d *Document) { d.Router = &Router{Hostnames: []string{"*.example.com"}} }, "router.hostnames"},
		{"router hostname case", Server, func(d *Document) { d.Router = &Router{Hostnames: []string{"API.example.com"}} }, "router.hostnames"},
		{"router hostname injection", Server, func(d *Document) { d.Router = &Router{Hostnames: []string{"a.example.com;"}} }, "router.hostnames"},
		{"router hostname duplicate", Server, func(d *Document) { d.Router = &Router{Hostnames: []string{"a.example.com", "a.example.com"}} }, "twice"},
		{"router acme without hostnames", Server, func(d *Document) { d.Router = &Router{ACMEEmail: "ops@example.com"} }, "require router.hostnames"},
		{"router acme email", Server, func(d *Document) {
			d.Router = &Router{Hostnames: []string{"a.example.com"}, ACMEEmail: "Ops <ops@example.com>"}
		}, "router.acmeEmail"},
		{"router acme directory", Server, func(d *Document) {
			d.Router = &Router{Hostnames: []string{"a.example.com"}, ACMEDirectoryURL: "http://acme.example/dir"}
		}, "router.acmeDirectoryURL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testDocument(t, "snp", tc.role)
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
}

const testUpstream = "c8s-gateway.confidential-inference.svc.cluster.local:9443"

func TestParseAcceptsServerRouter(t *testing.T) {
	doc, _, _ := testDocument(t, "snp", Server)
	doc.Router = &Router{
		Upstream:         testUpstream,
		Hostnames:        []string{"candidate.api.confidential.ai", "api.confidential.ai"},
		ACMEEmail:        "ops@confidential.ai",
		ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Router == nil || parsed.Router.Upstream != testUpstream || len(parsed.Router.Hostnames) != 2 {
		t.Fatalf("router = %+v", parsed.Router)
	}
}

// The Go rule must stay the chart's router.meshWrappedUpstream rule.
func TestRouterUpstreamRuleMatchesChart(t *testing.T) {
	data, err := os.ReadFile("../../helmchart/c8s/templates/router-helpers.tpl")
	if err != nil {
		t.Fatal(err)
	}
	chartRule := strings.ReplaceAll(meshWrappedUpstreamPattern, `\`, `\\`)
	if !strings.Contains(string(data), `regexMatch "`+chartRule+`"`) {
		t.Fatalf("router-helpers.tpl no longer carries %s", chartRule)
	}
}

func TestParseRejectsEmptyAndMalformedYAML(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            nil,
		"oversized":        bytes.Repeat([]byte("a"), MaxDocumentSize+1),
		"invalid":          []byte("role: [server"),
		"merge key":        []byte("base: &b {}\nrole: server\n<<: *b\n"),
		"non-scalar key":   []byte("? [a, b]\n: server\n"),
		"deep nesting":     []byte(strings.Repeat("[", 40) + strings.Repeat("]", 40)),
		"rtmr index alias": []byte("image:\n  rtmrs:\n    0x1: a\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatalf("accepted %s input", name)
			}
		})
	}
}

func TestYAMLPathPresent(t *testing.T) {
	var tree yaml.Node
	if err := yaml.Unmarshal([]byte("rke2:\n  agentToken: a\nrole: server\n"), &tree); err != nil {
		t.Fatal(err)
	}
	if !yamlPathPresent(&tree, "rke2", "agentToken") {
		t.Error("present nested key not found")
	}
	if yamlPathPresent(&tree, "rke2", "serverToken") {
		t.Error("absent nested key reported present")
	}
	if yamlPathPresent(&tree, "role", "nested") {
		t.Error("descended into a scalar")
	}
}

func TestParseLaunchKeyShape(t *testing.T) {
	_, valid := testKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	badDER := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}))
	withHeaders := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"a": "b"}, Bytes: der}))
	for name, raw := range map[string]string{
		"too large":     strings.Repeat("x", 8193),
		"not pem":       "not a key",
		"wrong type":    strings.ReplaceAll(valid, "PUBLIC KEY", "CERTIFICATE"),
		"headers":       withHeaders,
		"trailing data": valid + "trailing",
		"bad der":       badDER,
		"wrong curve":   wrongCurve,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLaunchKey(raw); err == nil {
				t.Fatalf("accepted %s key", name)
			}
		})
	}
	if _, err := parseLaunchKey(valid); err != nil {
		t.Fatal(err)
	}
}

func TestReadBoundedRejectsIrregularFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := readBounded(dir, 16); err == nil {
		t.Error("read a directory")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(empty, 16); err == nil {
		t.Error("read an empty file")
	}
	if _, err := readBounded(filepath.Join(dir, "missing"), 16); err == nil {
		t.Error("read a missing file")
	}
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readBounded(small, 16); err != nil || string(data) != "ok" {
		t.Errorf("got %q, %v", data, err)
	}
}

func TestVerifyRejectsBadConfigBeforeReadingFiles(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)

	bad := cfg
	bad.Platform = "sgx"
	if _, err := Verify(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("platform: %v", err)
	}
	bad = cfg
	bad.SignaturePath = ""
	if _, err := Verify(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "--signature") {
		t.Fatalf("missing signature path: %v", err)
	}
	bad = cfg
	bad.SignaturePath = filepath.Join(t.TempDir(), "missing.sig")
	if _, err := Verify(context.Background(), bad); err == nil {
		t.Fatal("missing signature file accepted")
	}

	old := loadMeasuredIdentity
	t.Cleanup(func() { loadMeasuredIdentity = old })
	loadMeasuredIdentity = func(context.Context, string, string) (credrelease.MeasuredIdentity, error) {
		return credrelease.MeasuredIdentity{}, errors.New("attestation-api unreachable")
	}
	if _, err := Verify(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "verify this boot's identity") {
		t.Fatalf("self-report failure: %v", err)
	}
	loadMeasuredIdentity = func(context.Context, string, string) (credrelease.MeasuredIdentity, error) {
		return testMeasuredIdentity(t, doc, "not a key"), nil
	}
	if _, err := Verify(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "measured launch key") {
		t.Fatalf("malformed measured key: %v", err)
	}
}

func TestLoadStagedTrustsOnlyCompleteArtifacts(t *testing.T) {
	doc, _, _ := testDocument(t, "snp", Server)
	write := func(t *testing.T, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	encode := func(t *testing.T, d Document) []byte {
		t.Helper()
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := LoadStaged(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("loaded a missing artifact")
	}
	if _, err := LoadStaged(write(t, []byte(`{"schema_version":"c8s-launch/v1","unknown":1}`))); err == nil || !strings.Contains(err.Error(), "decode staged") {
		t.Errorf("unknown field: %v", err)
	}
	// The staged artifact is JSON, so its camelCase YAML spelling is an
	// unknown field here: a decoder that accepted both would not be strict.
	if _, err := LoadStaged(write(t, []byte(`{"schemaVersion":"c8s-launch/v1"}`))); err == nil || !strings.Contains(err.Error(), "decode staged") {
		t.Errorf("camelCase staged field: %v", err)
	}
	if _, err := LoadStaged(write(t, append(encode(t, doc), []byte("{}")...))); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("trailing data: %v", err)
	}
	invalid := doc
	invalid.Role = "observer"
	if _, err := LoadStaged(write(t, encode(t, invalid))); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("invalid document: %v", err)
	}
	unresolved := doc
	unresolved.Server.Address = ""
	if _, err := LoadStaged(write(t, encode(t, unresolved))); err == nil || !strings.Contains(err.Error(), "resolved server address") {
		t.Errorf("unresolved server: %v", err)
	}
	staged, err := LoadStaged(write(t, encode(t, doc)))
	if err != nil || staged.ClusterID != doc.ClusterID {
		t.Fatalf("got %v, %v", staged, err)
	}
}

func TestPrimaryIPv4FollowsTheHostRoute(t *testing.T) {
	old := chooseHostInterface
	t.Cleanup(func() { chooseHostInterface = old })
	chooseHostInterface = func() (net.IP, error) { return nil, errors.New("no default route") }
	if _, err := PrimaryIPv4(); err == nil {
		t.Fatal("route failure ignored")
	}
	chooseHostInterface = func() (net.IP, error) { return net.ParseIP("192.0.2.9"), nil }
	if ip, err := PrimaryIPv4(); err != nil || ip != "192.0.2.9" {
		t.Fatalf("got %q, %v", ip, err)
	}

	// Stage consults it only when a server omits both addresses and no
	// resolver is configured.
	doc, key, pub := testDocument(t, "snp", Server)
	doc.Server.Address = ""
	doc.Node.IP = ""
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil || staged.Server.Address != "192.0.2.9" {
		t.Fatalf("got %v, %v", staged, err)
	}
}

func TestConfigPathWithoutRootIsAbsolute(t *testing.T) {
	if got := (Config{}).path(serverMarker); got != serverMarker {
		t.Fatalf("got %q", got)
	}
	if got := (Config{RootDir: "/tmp/root"}).path(serverMarker); got != filepath.Join("/tmp/root", serverMarker) {
		t.Fatalf("got %q", got)
	}
}

func TestStageCommandFailsClosed(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)

	cmd := NewCmd()
	cmd.SetArgs([]string{"stage", "--platform", "snp", "--config", cfg.DocumentPath})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("missing required flag: %v", err)
	}

	cmd = NewCmd()
	cmd.SetArgs([]string{"stage", "--platform", "sgx", "--config", cfg.DocumentPath, "--signature", cfg.SignaturePath})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("unsupported platform: %v", err)
	}
}

// The self-report loader compares against the verified family name, which for
// SNP ("sev-snp") differs from the launch platform tag ("snp").
func TestVerifyPassesTheFamilyNameToTheSelfReport(t *testing.T) {
	for platform, family := range map[string]string{"snp": "sev-snp", "tdx": "tdx"} {
		t.Run(platform, func(t *testing.T) {
			doc, key, pub := testDocument(t, platform, Server)
			testLoader(t, doc, pub)
			inner := loadMeasuredIdentity
			var got string
			loadMeasuredIdentity = func(ctx context.Context, platform, api string) (credrelease.MeasuredIdentity, error) {
				got = platform
				return inner(ctx, platform, api)
			}
			if _, err := Verify(context.Background(), testConfig(t, doc, key)); err != nil {
				t.Fatal(err)
			}
			if got != family {
				t.Fatalf("self-report asked for platform %q, want family %q", got, family)
			}
		})
	}
}
