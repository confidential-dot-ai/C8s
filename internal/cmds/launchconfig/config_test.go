package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

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

func testDocument(t *testing.T, platform string, role Role) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	serverKey, serverPub := testKey(t)
	agentKey, agentPub := testKey(t)
	doc := Document{
		SchemaVersion: SchemaVersion, ClusterID: "cluster-one", Role: role,
		Image:                   Image{Platform: platform, Measurement: strings.Repeat("11", 48)},
		Node:                    Node{Name: "node-one", IP: "10.0.0.2", ExternalIP: "192.0.2.4"},
		Server:                  ServerConfig{Address: "10.0.0.1", OperatorPublicKey: serverPub},
		AgentOperatorPublicKeys: []string{agentPub},
	}
	if platform == "tdx" {
		doc.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
	}
	if role == Server {
		return doc, serverKey, serverPub
	}
	return doc, agentKey, agentPub
}

func testMeasuredIdentity(t *testing.T, doc Document, pub string) credrelease.MeasuredIdentity {
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
	return credrelease.MeasuredIdentity{OperatorKey: []byte(pub), Image: image}
}

func testLoader(t *testing.T, doc Document, pub string) {
	t.Helper()
	old := loadMeasuredIdentity
	t.Cleanup(func() { loadMeasuredIdentity = old })
	measured := testMeasuredIdentity(t, doc, pub)
	loadMeasuredIdentity = func(context.Context, string, string) (credrelease.MeasuredIdentity, error) {
		return measured, nil
	}
}

func testConfig(t *testing.T, doc Document, key *ecdsa.PrivateKey) Config {
	t.Helper()
	// The agent token is minted into the rebased /run/confos, which is a
	// plain temp dir here; production checks the real mount is RAM-backed.
	oldOpen := openTokenDir
	t.Cleanup(func() { openTokenDir = oldOpen })
	openTokenDir = func(_, dir string) (*os.Root, error) { return os.OpenRoot(dir) }
	cfg := Config{Platform: doc.Image.Platform, RootDir: t.TempDir()}
	cfg.DocumentPath = filepath.Join(t.TempDir(), "launch.yaml")
	cfg.SignaturePath = cfg.DocumentPath + ".sig"
	signDocument(t, cfg, doc, key)
	return cfg
}

func signDocument(t *testing.T, cfg Config, doc Document, key *ecdsa.PrivateKey) {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signBytes(t, cfg, data, key)
}

func signBytes(t *testing.T, cfg Config, data []byte, key *ecdsa.PrivateKey) {
	t.Helper()
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
}

func TestStageBothRolesAndPlatforms(t *testing.T) {
	for _, platform := range []string{"snp", "tdx"} {
		for _, role := range []Role{Server, Agent} {
			t.Run(platform+"/"+string(role), func(t *testing.T) {
				doc, key, pub := testDocument(t, platform, role)
				doc.Node.IP = "0.0.0.0"
				doc.Workloads = `{"schema":"c8s.allowlist/v1","workloads":{}}`
				testLoader(t, doc, pub)
				cfg := testConfig(t, doc, key)
				if err := Stage(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				staged, err := LoadStaged(cfg.path(DefaultStagedPath))
				if err != nil {
					t.Fatal(err)
				}
				if staged.Role != role || staged.TLSSAN != "c8s.local" || staged.Node.IP != "" {
					t.Fatalf("incorrect staged role/default/address")
				}
				peers, err := refvalues.Load(cfg.path(Dir + "/peers.json"))
				if err != nil {
					t.Fatal(err)
				}
				cds, err := refvalues.Load(cfg.path(Dir + "/cds.json"))
				if err != nil {
					t.Fatal(err)
				}
				if len(peers.Images) != 2 || len(cds.Images) != 1 || !bytes.Equal(cds.Images[0].Anchor, []byte(doc.Server.OperatorPublicKey)) {
					t.Fatal("node and server policy sets are not separated")
				}
				for _, entry := range peers.Images {
					if !bytes.Equal(entry.Digest, mustDecodeHex(doc.Image.Measurement)) {
						t.Fatal("peer policy changed the shared image")
					}
					if platform == "tdx" && len(entry.Registers) != 2 {
						t.Fatal("TDX peer omitted runtime image pins")
					}
				}
				fragment, err := os.ReadFile(cfg.path(rke2FragmentPath))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(fragment), "node-ip:") {
					t.Fatal("RKE2 must autodetect 0.0.0.0")
				}
				private := []string{DefaultStagedPath, Dir + "/workloads.json", rke2FragmentPath}
				var roleConfig roleFragment
				if err := yaml.Unmarshal(fragment, &roleConfig); err != nil {
					t.Fatal(err)
				}
				if role == Server {
					requirePresent(t, cfg.path(serverMarker))
					requireAbsent(t, cfg.path(agentMarker))
					// No credential comes from launch media: RKE2 mints its own
					// server token and the agent token is generated here.
					requirePresent(t, cfg.path(AgentTokenPath))
					private = append(private, AgentTokenPath, Dir+"/agents.json")
					if roleConfig.TokenFile != "" || roleConfig.AgentTokenFile != AgentTokenPath {
						t.Fatal("server must let RKE2 generate its token and configure the separate agent token")
					}
					agents, err := refvalues.Load(cfg.path(Dir + "/agents.json"))
					if err != nil {
						t.Fatal(err)
					}
					if len(agents.Images) != 1 || !bytes.Equal(agents.Images[0].Anchor, []byte(doc.AgentOperatorPublicKeys[0])) {
						t.Fatal("enrollment policy must contain exactly the authorized agents")
					}
				} else {
					requirePresent(t, cfg.path(agentMarker))
					requireAbsent(t, cfg.path(serverMarker))
					// Agents receive their token through attested enrollment,
					// never from staging.
					requireAbsent(t, cfg.path(AgentTokenPath))
					requireAbsent(t, cfg.path(Dir+"/agents.json"))
					if roleConfig.TokenFile != AgentTokenPath || !bytes.Contains(fragment, []byte("server: https://10.0.0.1:9345")) {
						t.Fatal("agent does not join signed server with the enrolled token")
					}
				}
				for _, path := range private {
					info, err := os.Stat(cfg.path(path))
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0o600 {
						t.Fatalf("%s mode = %v", path, info.Mode())
					}
				}
			})
		}
	}
}

func TestVerifyRejectsUnauthorizedRoleOrImage(t *testing.T) {
	tests := []struct {
		name   string
		role   Role
		change func(*Document)
		want   string
	}{
		{"MRTD", Server, func(d *Document) { d.Image.Measurement = strings.Repeat("44", 48) }, "measurement"},
		{"kernel RTMR", Server, func(d *Document) { d.Image.RTMRs[1] = strings.Repeat("44", 48) }, "RTMR[1]"},
		{"rootfs RTMR", Server, func(d *Document) { d.Image.RTMRs[2] = strings.Repeat("44", 48) }, "RTMR[2]"},
		{"missing RTMR", Server, func(d *Document) { delete(d.Image.RTMRs, 2) }, "exactly RTMR"},
		{"platform", Server, func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "platform"},
		{"agent as server", Agent, func(d *Document) { d.Role = Server }, "server launch key"},
		{"server as agent", Server, func(d *Document) { d.Role = Agent }, "different launch key"},
		{"shared role keys", Agent, func(d *Document) {
			d.AgentOperatorPublicKeys = []string{strings.TrimSpace(d.Server.OperatorPublicKey)}
		}, "distinct"},
		{"unlisted agent", Agent, func(d *Document) { _, pub := testKey(t); d.AgentOperatorPublicKeys = []string{pub} }, "not in"},
		{"missing role", Server, func(d *Document) { d.Role = "" }, "role"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, key, pub := testDocument(t, "tdx", tc.role)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			tc.change(&doc)
			signDocument(t, cfg, doc, key)
			_, err := Verify(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSignaturePrecedesParsing(t *testing.T) {
	doc, key, pub := testDocument(t, "tdx", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	wrong, _ := testKey(t)
	signBytes(t, cfg, []byte("invalid: [yaml"), wrong)
	_, err := Verify(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature rejection before parse, got %v", err)
	}
}

func TestParseRejectsAmbiguousOrUnexpectedFields(t *testing.T) {
	doc, _, _ := testDocument(t, "snp", Agent)
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate":      append(append([]byte{}, raw...), []byte("role: server\n")...),
		"multiple":       append(append([]byte{}, raw...), []byte("---\n{}\n")...),
		"unknown":        append(append([]byte{}, raw...), []byte("helmValues: {}\n")...),
		"nested unknown": bytes.Replace(raw, []byte("    name:"), []byte("    arbitraryFlag: hello\n    name:"), 1),
		"alias":          bytes.Replace(raw, []byte("role: agent"), []byte("role: &role agent"), 1),
		// v2 documents are public: any rke2 block is a credential leak, even an empty one.
		"empty server token": append(append([]byte{}, raw...), []byte("rke2: {serverToken: ''}\n")...),
		"null server token":  append(append([]byte{}, raw...), []byte("rke2: {serverToken: null}\n")...),
		"agent token":        append(append([]byte{}, raw...), []byte("rke2: {agentToken: secret}\n")...),
		"old schema":         bytes.Replace(raw, []byte(SchemaVersion), []byte("c8s-launch/v1"), 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatalf("accepted %s input", name)
			}
		})
	}
}

func TestParseRejectsNoncanonicalRTMRIndex(t *testing.T) {
	doc, _, _ := testDocument(t, "tdx", Server)
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Replace(raw, []byte("        1:"), []byte("        01:"), 1)
	if bytes.Equal(data, raw) {
		t.Fatal("fixture did not replace RTMR index")
	}
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("want noncanonical index rejection, got %v", err)
	}
}

func TestKeylessAndFailedAttestationNeverStageARole(t *testing.T) {
	for _, keyErr := range []error{credrelease.ErrNoOperatorKey, os.ErrNotExist, errors.New("binding mismatch")} {
		t.Run(keyErr.Error(), func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Server)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			loadMeasuredIdentity = func(context.Context, string, string) (credrelease.MeasuredIdentity, error) {
				measured := testMeasuredIdentity(t, doc, "")
				measured.OperatorKeyErr = keyErr
				return measured, nil
			}
			if err := Stage(context.Background(), cfg); err == nil {
				t.Fatal("accepted unauthenticated launch key")
			}
			requireAbsent(t, cfg.path(serverMarker))
			requireAbsent(t, cfg.path(agentMarker))
		})
	}
}

func TestFailedRestagingClosesGatesAndPreservesLocalCredential(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(cfg.path(AgentTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("accepted tampered signature")
	}
	// The minted agent token belongs to the running cluster: the role gates
	// close, but the credential agents already enrolled with is not rotated
	// underneath them by a failed restaging.
	requirePresent(t, cfg.path(AgentTokenPath))
	for _, path := range []string{serverMarker, agentMarker, DefaultStagedPath, rke2FragmentPath, Dir + "/agents.json"} {
		requireAbsent(t, cfg.path(path))
	}
	signDocument(t, cfg, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(cfg.path(AgentTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(token, again) || len(token) != 64 {
		t.Fatal("successful restaging must keep the same 64-hex agent token")
	}
}

func TestWriteFailureCannotPublishRole(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	verified, err := Verify(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.path("/etc/rancher/rke2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.path("/etc/rancher/rke2/config.yaml.d"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stageVerified(cfg, verified); err == nil {
		t.Fatal("expected RKE2 configuration output failure")
	}
	requireAbsent(t, cfg.path(serverMarker))
	requireAbsent(t, cfg.path(agentMarker))
}

func TestBoundedDocumentAndMissingConfig(t *testing.T) {
	doc, key, pub := testDocument(t, "snp", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := os.WriteFile(cfg.DocumentPath, bytes.Repeat([]byte("a"), MaxDocumentSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), cfg); err == nil {
		t.Fatal("accepted oversized input")
	}
	if err := os.Remove(cfg.DocumentPath); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("defaulted a missing launch to a role")
	}
}

func requireAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s must not exist: %v", path, err)
	}
}
func requirePresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
}

func TestServerAddressResolution(t *testing.T) {
	tests := []struct {
		name, nodeIP, resolved, want string
		resolveErr                   error
	}{
		{name: "signed node address", nodeIP: "10.0.0.8", want: "10.0.0.8"},
		{name: "primary route", resolved: "10.0.0.9", want: "10.0.0.9"},
		{name: "no route", resolveErr: errors.New("no default route")},
		{name: "IPv6 only", resolved: "2001:db8::1"},
		{name: "unspecified result", resolved: "0.0.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Server)
			doc.Server.Address = ""
			doc.Node.IP = tc.nodeIP
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			old := chooseHostInterface
			t.Cleanup(func() { chooseHostInterface = old })
			chooseHostInterface = func() (net.IP, error) {
				if tc.nodeIP != "" {
					t.Fatal("resolver should not replace signed node IP")
				}
				if tc.resolveErr != nil {
					return nil, tc.resolveErr
				}
				return net.ParseIP(tc.resolved), nil
			}
			err := Stage(context.Background(), cfg)
			if tc.want == "" {
				if err == nil {
					t.Fatal("expected address resolution failure")
				}
				requireAbsent(t, cfg.path(serverMarker))
				requireAbsent(t, cfg.path(agentMarker))
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.Server.Address != tc.want || staged.Node.IP != tc.want {
				t.Fatal("resolved address not staged consistently")
			}
		})
	}
	doc, _, _ := testDocument(t, "snp", Agent)
	doc.Server.Address = ""
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("agent requires an explicit server address")
	}
}

// An ImageIdentity implementation can omit launch variants; verification must
// reject that result before staging credentials or role authorization.
type identityWithoutDigests struct{ runtimemeasure.ImageIdentity }

func (identityWithoutDigests) LaunchDigests() []runtimemeasure.LaunchVariant { return nil }

func TestMissingMeasuredImageCannotStageARole(t *testing.T) {
	for _, missing := range []string{"image identity", "launch digests"} {
		t.Run(missing, func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Server)
			testLoader(t, doc, pub)
			measured := testMeasuredIdentity(t, doc, pub)
			if missing == "image identity" {
				measured.Image = nil
			} else {
				measured.Image = identityWithoutDigests{measured.Image}
			}
			loadMeasuredIdentity = func(context.Context, string, string) (credrelease.MeasuredIdentity, error) { return measured, nil }
			cfg := testConfig(t, doc, key)
			if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "contains no "+missing) {
				t.Fatalf("missing %s: %v", missing, err)
			}
			for _, path := range []string{serverMarker, agentMarker, AgentTokenPath, DefaultStagedPath} {
				requireAbsent(t, cfg.path(path))
			}
		})
	}
}

func TestAuthorizeKeyRejectsUnparsedServerKey(t *testing.T) {
	for _, role := range []Role{Server, Agent} {
		t.Run(string(role), func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", role)
			doc.Server.OperatorPublicKey = "not a public key"
			if role == Server {
				pub = doc.Server.OperatorPublicKey
			}
			if err := doc.authorizeKey([]byte(pub), &key.PublicKey); err == nil || !strings.Contains(err.Error(), "parse server operator public key") {
				t.Fatalf("authorized a document with an invalid server key: %v", err)
			}
		})
	}
}
