package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func testManagedDocument(t *testing.T, platform string, role Role) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, key, pub := testDocument(t, platform, role)
	_, managementPub := testKey(t)
	doc.SchemaVersion = SchemaVersionManaged
	doc.RKE2 = RKE2{}
	doc.Node.Name = "circle-cp-x7k2p"
	doc.Managed = &Managed{
		Pool:            "control-plane",
		MachineName:     doc.Node.Name,
		MachineUID:      "0f9e3a52-6c1d-4b8e-9a77-2d5c0e4f1b63",
		Policy:          Policy{Digest: "sha256:" + strings.Repeat("ab", 32), Epoch: 1},
		BootstrapDigest: "sha256:" + strings.Repeat("cd", 32),
		Enrollment: Enrollment{
			URL: "https://10.0.0.9:8444",
			Management: []ManagementPin{{
				Image:     Image{Platform: "tdx", Measurement: strings.Repeat("44", 48), RTMRs: map[int]string{1: strings.Repeat("55", 48), 2: strings.Repeat("66", 48)}},
				LaunchKey: managementPub,
			}},
		},
	}
	return doc, key, pub
}

func TestStageManagedLeavesTheRoleToEnrollment(t *testing.T) {
	for _, role := range []Role{Server, Agent} {
		t.Run(string(role), func(t *testing.T) {
			doc, key, pub := testManagedDocument(t, "snp", role)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			if err := Stage(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			requirePresent(t, cfg.path(enrollMarker))
			for _, p := range []string{serverMarker, agentMarker, serverTokenPath, agentTokenPath, nodePasswordPath} {
				requireAbsent(t, cfg.path(p))
			}
			fragment, err := os.ReadFile(cfg.path(rke2FragmentPath))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(fragment, []byte("node-name: circle-cp-x7k2p")) || bytes.Contains(fragment, []byte("token")) || bytes.Contains(fragment, []byte("server:")) {
				t.Fatalf("managed role fragment:\n%s", fragment)
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if !staged.IsManaged() || staged.Managed.MachineUID != doc.Managed.MachineUID {
				t.Fatal("staged document lost its managed section")
			}
		})
	}
}

func TestValidateManagedRejectsEachMalformedField(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"rke2 tokens", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "must not carry rke2"},
		{"no managed section", func(d *Document) { d.Managed = nil }, "requires managed"},
		{"managed in v1", func(d *Document) {
			d.SchemaVersion = SchemaVersion
			d.RKE2 = RKE2{AgentToken: strings.Repeat("a", 64), ServerToken: strings.Repeat("b", 64)}
		}, "managed requires"},
		{"pool", func(d *Document) { d.Managed.Pool = "Control_Plane" }, "managed.pool"},
		{"machine name", func(d *Document) { d.Managed.MachineName = "other" }, "machineName"},
		{"machine uid", func(d *Document) { d.Managed.MachineUID = "not-a-uid" }, "machineUID"},
		{"policy digest", func(d *Document) { d.Managed.Policy.Digest = "md5:00" }, "managed.policy"},
		{"policy epoch", func(d *Document) { d.Managed.Policy.Epoch = 0 }, "managed.policy"},
		{"bootstrap digest", func(d *Document) { d.Managed.BootstrapDigest = strings.Repeat("cd", 32) }, "bootstrapDigest"},
		{"url scheme", func(d *Document) { d.Managed.Enrollment.URL = "http://10.0.0.9:8444" }, "enrollment.url"},
		{"url name", func(d *Document) { d.Managed.Enrollment.URL = "https://mgmt.example:8444" }, "enrollment.url"},
		{"url path", func(d *Document) { d.Managed.Enrollment.URL = "https://10.0.0.9:8444/v1" }, "enrollment.url"},
		{"url port", func(d *Document) { d.Managed.Enrollment.URL = "https://10.0.0.9" }, "enrollment.url"},
		{"url loopback", func(d *Document) { d.Managed.Enrollment.URL = "https://127.0.0.1:8444" }, "enrollment.url"},
		{"no management", func(d *Document) { d.Managed.Enrollment.Management = nil }, "1..8 images"},
		{"management platform", func(d *Document) { d.Managed.Enrollment.Management[0].Platform = "sgx" }, "management[0]: platform"},
		{"management registers", func(d *Document) { d.Managed.Enrollment.Management[0].RTMRs = nil }, "RTMR[1] and RTMR[2]"},
		{"management key", func(d *Document) { d.Managed.Enrollment.Management[0].LaunchKey = "not a key" }, "launchKey"},
		{"management measurement", func(d *Document) { d.Managed.Enrollment.Management[0].Measurement = "ab" }, "measurement"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, _, _ := testManagedDocument(t, "snp", Agent)
			tt.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("an empty rke2 block", func(t *testing.T) {
		doc, _, _ := testManagedDocument(t, "snp", Agent)
		data, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(append(data, []byte("rke2: {}\n")...)); err == nil || !strings.Contains(err.Error(), "must not carry rke2") {
			t.Fatalf("Parse error = %v", err)
		}
	})
}

// fakeEnrollment serves the enrollment contract and records what it saw.
type fakeEnrollment struct {
	material   []byte
	providerID string
	status     int
	challenges atomic.Int32
	enrolls    atomic.Int32
	nonce      []byte
	gotCert    []byte
}

func (f *fakeEnrollment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case challengePath:
		f.challenges.Add(1)
		var req challengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MachineUID == "" {
			http.Error(w, "bad challenge", http.StatusBadRequest)
			return
		}
		f.nonce = bytes.Repeat([]byte{7}, 32)
		_ = json.NewEncoder(w).Encode(challengeResponse{Nonce: f.nonce})
	case enrollPath:
		f.enrolls.Add(1)
		var req enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !bytes.Equal(req.Nonce, f.nonce) {
			http.Error(w, "stale challenge", http.StatusForbidden)
			return
		}
		f.gotCert = req.Certificate
		if f.status != 0 {
			http.Error(w, "refused: machine already enrolled", f.status)
			return
		}
		_ = json.NewEncoder(w).Encode(enrollResponse{Material: f.material, ProviderID: f.providerID})
	default:
		http.NotFound(w, r)
	}
}

type fakeCertProvider struct{ nonce []byte }

func (p *fakeCertProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return &tls.Certificate{Certificate: [][]byte{append([]byte("evidence bound to "), p.nonce...)}}, time.Minute, nil
}

// stageManagedNode stages a managed launch, points it at srv and installs the
// image's real base RKE2 config.
func stageManagedNode(t *testing.T, role Role, srv *httptest.Server, material []byte) (EnrollConfig, Document) {
	t.Helper()
	doc, key, pub := testManagedDocument(t, "tdx", role)
	sum := sha256.Sum256(material)
	doc.Managed.BootstrapDigest = "sha256:" + hex.EncodeToString(sum[:])
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join("..", "..", "..", "node-guest-image", "c8s", "mkosi.extra", "etc", "rancher", "rke2", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.path(rke2BaseConfig)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.path(rke2BaseConfig), base, 0o600); err != nil {
		t.Fatal(err)
	}

	oldClient, oldProvider := newEnrollClient, newCertProvider
	t.Cleanup(func() { newEnrollClient, newCertProvider = oldClient, oldProvider })
	var gotPolicy *armtls.VerifyPolicy
	newEnrollClient = func(policy *armtls.VerifyPolicy) (*http.Client, error) {
		gotPolicy = policy
		// The document names a routable address; the test service listens on
		// loopback.
		transport := srv.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.ServerName = "127.0.0.1"
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		return &http.Client{Transport: transport}, nil
	}
	newCertProvider = func(_ EnrollConfig, _ string, nonce []byte) armtls.CertProvider {
		return &fakeCertProvider{nonce: nonce}
	}
	t.Cleanup(func() {
		if gotPolicy != nil && (len(gotPolicy.Policy.Images) != 1 || !bytes.Equal(gotPolicy.Policy.Images[0].Anchor, []byte(doc.Managed.Enrollment.Management[0].LaunchKey))) {
			t.Error("the enrollment client does not pin the management image and its launch key")
		}
	})
	return EnrollConfig{Platform: "tdx", RootDir: cfg.RootDir, Timeout: 5 * time.Second}, doc
}

func marshalMaterial(t *testing.T, m Material) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func serverMaterial() Material {
	return Material{
		Role: Server,
		Config: map[string]any{
			"token":                    "test-token",
			"cni":                      []any{"cilium"},
			"cluster-cidr":             "10.52.0.0/16",
			"tls-san":                  []any{"198.51.100.10"},
			"cloud-provider-name":      "external",
			"disable-cloud-controller": true,
			"kube-apiserver-arg":       []any{"anonymous-auth=false"},
		},
		Files: []MaterialFile{
			{Path: "/var/lib/rancher/rke2/server/tls/server-ca.crt", Content: []byte("test certificate")},
			{Path: "/var/lib/rancher/rke2/server/tls/etcd/peer-ca.key", Content: []byte("test key")},
		},
	}
}

func TestEnrollStagesTheReleasedRole(t *testing.T) {
	material := marshalMaterial(t, serverMaterial())
	f := &fakeEnrollment{material: material, providerID: "cc://i-0a1b2c3d"}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	cfg, _ := stageManagedNode(t, Server, srv, material)
	if err := Enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(f.gotCert, f.nonce) {
		t.Fatal("the enrollment certificate is not bound to the challenge")
	}
	requirePresent(t, cfg.path(serverMarker))
	requireAbsent(t, cfg.path(agentMarker))
	var fragment map[string]any
	data, err := os.ReadFile(cfg.path(managedFragment))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &fragment); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"token":                    "test-token",
		"cloud-provider-name":      "external",
		"disable-cloud-controller": true,
		"tls-san+":                 []any{"198.51.100.10"},
		"kube-apiserver-arg+":      []any{"anonymous-auth=false"},
		"kubelet-arg+":             []any{"provider-id=cc://i-0a1b2c3d"},
	}
	if got, _ := json.Marshal(fragment); string(got) != mustJSON(t, want) {
		t.Fatalf("60-managed.yaml = %s, want %s", got, mustJSON(t, want))
	}
	for _, p := range []string{"/var/lib/rancher/rke2/server/tls/server-ca.crt", "/var/lib/rancher/rke2/server/tls/etcd/peer-ca.key", managedFragment} {
		info, err := os.Stat(cfg.path(p))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", p, info.Mode())
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEnrollRefusesMaterialTheLaunchDidNotName(t *testing.T) {
	agentMaterial := func(change func(*Material)) Material {
		m := Material{Role: Agent, Config: map[string]any{"token": "K10test::server:secret", "server": "https://10.0.0.1:9345"}}
		if change != nil {
			change(&m)
		}
		return m
	}
	tests := []struct {
		name     string
		role     Role
		material Material
		signed   []byte // what the launch's digest names; nil names the material
		provider string
		want     string
	}{
		{"other bytes than the digest", Agent, agentMaterial(nil), []byte("{}"), "cc://i-1", "launch document names"},
		{"another role", Agent, serverMaterial(), nil, "cc://i-1", "for a server"},
		{"files for an agent", Agent, agentMaterial(func(m *Material) {
			m.Files = []MaterialFile{{Path: "/var/lib/rancher/rke2/server/tls/server-ca.crt", Content: []byte("x")}}
		}), nil, "cc://i-1", "only a control-plane member"},
		{"a file outside the CA directories", Server, func() Material {
			m := serverMaterial()
			m.Files = append(m.Files, MaterialFile{Path: "/var/lib/rancher/rke2/server/manifests/evil.yaml", Content: []byte("x")})
			return m
		}(), nil, "cc://i-1", "not an RKE2 server CA file"},
		{"a path that climbs out", Server, func() Material {
			m := serverMaterial()
			m.Files = []MaterialFile{{Path: "/var/lib/rancher/rke2/server/tls/../../../../../etc/shadow.key", Content: []byte("x")}}
			return m
		}(), nil, "cc://i-1", "not an RKE2 server CA file"},
		{"another CNI", Agent, agentMaterial(func(m *Material) { m.Config["cni"] = []any{"calico"} }), nil, "cc://i-1", "cni is fixed by the image"},
		{"other address ranges", Agent, agentMaterial(func(m *Material) { m.Config["cluster-cidr"] = "10.42.0.0/16" }), nil, "cc://i-1", "cluster-cidr is fixed"},
		{"a setting management may not set", Agent, agentMaterial(func(m *Material) { m.Config["data-dir"] = "/tmp" }), nil, "cc://i-1", "not one management may set"},
		{"its own provider ID", Agent, agentMaterial(func(m *Material) { m.Config["kubelet-arg"] = []any{"provider-id=cc://other"} }), nil, "cc://i-1", "refused"},
		{"an unmeasured credential provider", Agent, agentMaterial(func(m *Material) {
			m.Config["kubelet-arg"] = []any{"--image-credential-provider-bin-dir=/tmp"}
		}), nil, "cc://i-1", "refused"},
		{"no token", Agent, agentMaterial(func(m *Material) { delete(m.Config, "token") }), nil, "cc://i-1", "no RKE2 token"},
		{"an agent without a server", Agent, agentMaterial(func(m *Material) { delete(m.Config, "server") }), nil, "cc://i-1", "names no server"},
		{"a host-chosen provider ID", Agent, agentMaterial(nil), nil, "aws:///i-1", "cc://<instance id>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := marshalMaterial(t, tt.material)
			signed := tt.signed
			if signed == nil {
				signed = material
			}
			f := &fakeEnrollment{material: material, providerID: tt.provider}
			srv := httptest.NewTLSServer(f)
			defer srv.Close()
			cfg, _ := stageManagedNode(t, tt.role, srv, signed)
			err := Enroll(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Enroll error = %v, want %q", err, tt.want)
			}
			requireAbsent(t, cfg.path(serverMarker))
			requireAbsent(t, cfg.path(agentMarker))
			requireAbsent(t, cfg.path(managedFragment))
		})
	}
}

func TestEnrollStopsAtARefusal(t *testing.T) {
	material := marshalMaterial(t, serverMaterial())
	f := &fakeEnrollment{material: material, providerID: "cc://i-1", status: http.StatusConflict}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	cfg, _ := stageManagedNode(t, Server, srv, material)
	if err := Enroll(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("Enroll error = %v", err)
	}
	if n := f.enrolls.Load(); n != 1 {
		t.Fatalf("enrolled %d times after a refusal, want 1", n)
	}
	requireAbsent(t, cfg.path(serverMarker))
}

func TestEnrollRetriesAnUnreachableService(t *testing.T) {
	material := marshalMaterial(t, serverMaterial())
	f := &fakeEnrollment{material: material, providerID: "cc://i-1"}
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	cfg, _ := stageManagedNode(t, Server, srv, material)
	if err := Enroll(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	requirePresent(t, cfg.path(serverMarker))
}

func TestEnrollNeedsAStagedManagedLaunch(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Agent)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := Enroll(context.Background(), EnrollConfig{Platform: "snp", RootDir: cfg.RootDir}); err == nil || !strings.Contains(err.Error(), "no managed launch") {
		t.Fatalf("Enroll error = %v", err)
	}
}

// testdata/provider-v2 is what Confidential Cloud's Cluster API provider
// renders for a first control-plane member from CAPRKE2's real bootstrap data,
// with the material's keys and token replaced. It pins the wire contract
// between the two: the document parses, and the material is accepted as is.
func TestProviderDocumentAndMaterialAreAccepted(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "provider-v2", "launch.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("the provider's document: %v", err)
	}
	if !doc.IsManaged() || doc.Role != Server || doc.Managed.MachineName != doc.Node.Name {
		t.Fatalf("parsed %+v", doc)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "provider-v2", "material.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Material
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	base, err := readBaseConfig(filepath.Join("..", "..", "..", "node-guest-image", "c8s", "mkosi.extra", "etc", "rancher", "rke2", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managedConfig(base, m, "cc://i-0a1b2c3d"); err != nil {
		t.Fatalf("the provider's material: %v", err)
	}
	for _, f := range m.Files {
		if err := checkMaterialFile(doc.Role, f); err != nil {
			t.Fatal(err)
		}
	}
	if m.Role != doc.Role || len(m.Files) != 8 {
		t.Fatalf("material for %s with %d files", m.Role, len(m.Files))
	}
}
