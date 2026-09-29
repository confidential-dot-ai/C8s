package nodeservices

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/join"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func testPins(t *testing.T) refvalues.ReferenceValues {
	t.Helper()
	pins, err := refvalues.Load("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func document(t *testing.T, role launchconfig.Role) *launchconfig.Document {
	t.Helper()
	pins := testPins(t)
	return &launchconfig.Document{Role: role, Image: launchconfig.Image{Platform: "tdx"}, Server: launchconfig.ServerConfig{Address: "192.0.2.10", OperatorPublicKey: string(pins.Images[0].Anchor)}, TLSSAN: "c8s.local"}
}

const floor = "platform: tdx\nallowlist:\n  base:\n    schema: c8s.allowlist/v1\n    workloads:\n      system:\n        containers:\n          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n            command: {policy: any}\n            args: {policy: any}\n  pull:\n    url: https://127.0.0.1:30808\n    timeout: 30s\n    cds_measurements: []\npolicy:\n  mode: fail-closed\n  enforce_existing: true\n"
const seed = `{"schema":"c8s.allowlist/v1","workloads":{"operator":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

func writeInput(t *testing.T, root, name string, data []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func prepareRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{"image-policy.yaml": floor, "allowlist-seed.json": seed} {
		writeInput(t, root, "/usr/lib/c8s/"+name, []byte(data))
	}
	pins := testPins(t)
	for _, name := range []string{"peers.json", "cds.json"} {
		if name == "cds.json" {
			pins.Images = pins.Images[:1]
		}
		data, err := refvalues.Format(pins)
		if err != nil {
			t.Fatal(err)
		}
		writeInput(t, root, launchDir+name, data)
	}
	writeInput(t, root, launchDir+"config.json", []byte(`{"rke2":{"serverToken":"SECRET-SERVER-TOKEN","agentToken":"SECRET-AGENT-TOKEN"}}`))
	return root
}

func basePolicy(t *testing.T, v any) *allowlist.Allowlist {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	base, err := allowlist.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func TestPreparePreservesFloorAndPinsServerBeforeRKE2(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		t.Run(string(role), func(t *testing.T) {
			root := prepareRoot(t)
			doc := document(t, role)
			if err := Prepare(root, doc); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var got, before map[string]any
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal([]byte(floor), &before); err != nil {
				t.Fatal(err)
			}
			ga := got["allowlist"].(map[string]any)
			if !reflect.DeepEqual(got["policy"], before["policy"]) {
				t.Fatal("changed baked enforcement policy")
			}
			base := basePolicy(t, ga["base"])
			original := basePolicy(t, before["allowlist"].(map[string]any)["base"])
			if !reflect.DeepEqual(base.Workloads["system"], original.Workloads["system"]) {
				t.Fatal("changed baked system workload")
			}
			if len(base.Workloads) != 2 || len(base.Workloads["operator"].Containers) != 1 {
				t.Fatalf("chart components missing from bootstrap base: %v", base.Workloads)
			}
			pull := ga["pull"].(map[string]any)
			if pull["url"] != doc.CDSURL() || pull["cds_measurements_config"] != launchDir+"cds.json" || pull["timeout"] != "30s" {
				t.Fatalf("bad pull config: %v", pull)
			}
			if _, exists := pull["cds_measurements"]; exists {
				t.Fatal("flat pins retained")
			}
			_, err = os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json"))
			if role == launchconfig.Agent && !os.IsNotExist(err) {
				t.Fatal("agent received server seed")
			}
			if role == launchconfig.Server && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPrepareCannotReplaceBakedWorkload(t *testing.T) {
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)
	doc.Workloads = seed
	if err := Prepare(root, doc); err == nil || !strings.Contains(err.Error(), "replaces a baked component") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "allowlist-seed.json")); !os.IsNotExist(err) {
		t.Fatal("published rejected seed")
	}

	doc.Workloads = strings.ReplaceAll(strings.ReplaceAll(seed, "operator", "application"), strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, PublicDir, "allowlist-seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := allowlist.ParseJSON(data)
	if err != nil || len(merged.Workloads) != 2 {
		t.Fatalf("merged policy: %v %v", merged, err)
	}
	data, err = os.ReadFile(filepath.Join(root, "/etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	base := basePolicy(t, policy["allowlist"].(map[string]any)["base"])
	if _, exists := base.Workloads["application"]; exists {
		t.Fatal("signed tenant workload entered the unconditional bootstrap base")
	}
}

func TestPublishNodeIPHonorsAuthenticatedAddress(t *testing.T) {
	root := t.TempDir()
	doc := document(t, launchconfig.Agent)
	doc.Node.IP = "192.0.2.22"
	if err := PublishNodeIP(root, doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, nodeIPPath))
	if err != nil || string(data) != "192.0.2.22\n" {
		t.Fatalf("got %q, %v", data, err)
	}
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "::1"} {
		doc.Node.IP = ip
		if err := PublishNodeIP(t.TempDir(), doc); err == nil {
			t.Errorf("accepted %s", ip)
		}
	}
}

func TestPreparePublishesOnlyPublicRoleInputs(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		t.Run(string(role), func(t *testing.T) {
			root := prepareRoot(t)
			doc := document(t, role)
			if err := Prepare(root, doc); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Join(root, PublicDir))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
				info, err := entry.Info()
				if err != nil || info.Mode().Perm() != 0644 {
					t.Fatalf("public file permissions: %v, %v", info, err)
				}
				data, err := os.ReadFile(filepath.Join(root, PublicDir, entry.Name()))
				if err != nil || bytes.Contains(data, []byte("SECRET-")) {
					t.Fatalf("secret or unreadable public file %s: %v", entry.Name(), err)
				}
			}
			want := []string{"cds.json", "peers.json"}
			if role == launchconfig.Server {
				want = []string{"allowlist-seed.json", "cds.json", "operator-pubkey", "peers.json", "tls-san"}
				for name, expected := range map[string]string{"operator-pubkey": doc.Server.OperatorPublicKey, "tls-san": doc.TLSSAN + "\n"} {
					data, err := os.ReadFile(filepath.Join(root, PublicDir, name))
					if err != nil || string(data) != expected {
						t.Fatalf("public %s does not match authenticated document: %v", name, err)
					}
				}
			}
			if !reflect.DeepEqual(names, want) {
				t.Fatalf("public files = %v, want %v", names, want)
			}
			for _, name := range []string{"peers.json", "cds.json"} {
				original, err := os.ReadFile(filepath.Join(root, launchDir, name))
				if err != nil {
					t.Fatal(err)
				}
				public, err := os.ReadFile(filepath.Join(root, PublicDir, name))
				if err != nil || !bytes.Equal(original, public) {
					t.Fatalf("changed authenticated %s: %v", name, err)
				}
			}
			private, err := os.Stat(filepath.Join(root, launchDir, "config.json"))
			if err != nil || private.Mode().Perm() != 0600 {
				t.Fatalf("private launch config permissions: %v, %v", private, err)
			}
		})
	}
}

func TestPrepareAgentRemovesServerOutputs(t *testing.T) {
	root := prepareRoot(t)
	if err := Prepare(root, document(t, launchconfig.Server)); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(root, document(t, launchconfig.Agent)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"operator-pubkey", "allowlist-seed.json", "tls-san"} {
		if _, err := os.Stat(filepath.Join(root, PublicDir, name)); !os.IsNotExist(err) {
			t.Fatalf("agent retained server output %s: %v", name, err)
		}
	}
}

func TestPrepareRejectsChartFloorNameCollision(t *testing.T) {
	collision := strings.ReplaceAll(seed, "operator", "system")
	for name, incoming := range map[string]string{
		"different image":  strings.ReplaceAll(collision, strings.Repeat("a", 64), strings.Repeat("b", 64)),
		"different args":   strings.ReplaceAll(collision, `"args":{"policy":"any"}`, `"args":{"policy":"deny"}`),
		"different mounts": strings.ReplaceAll(collision, `"args":{"policy":"any"}`, `"args":{"policy":"any"},"mounts":{"policy":"any"}`),
	} {
		for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
			t.Run(name+"/"+string(role), func(t *testing.T) {
				root := prepareRoot(t)
				writeInput(t, root, "/usr/lib/c8s/allowlist-seed.json", []byte(incoming))
				if err := Prepare(root, document(t, role)); err == nil || !strings.Contains(err.Error(), "replaces a baked component") {
					t.Fatalf("accepted chart replacing system floor: %v", err)
				}
			})
		}
	}
}

func TestPrepareAllowsIdenticalMeasuredFloorEntry(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		root := prepareRoot(t)
		writeInput(t, root, "/usr/lib/c8s/allowlist-seed.json", []byte(strings.ReplaceAll(seed, "operator", "system")))
		if err := Prepare(root, document(t, role)); err != nil {
			t.Fatalf("%s: identical measured floor entry: %v", role, err)
		}
		data, err := os.ReadFile(filepath.Join(root, "/etc/nri/conf.d/image-policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := yaml.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		base := basePolicy(t, got["allowlist"].(map[string]any)["base"])
		if len(base.Workloads) != 1 {
			t.Fatalf("duplicate bootstrap entry: %v", base.Workloads)
		}
	}
}

func TestJoinConfigIsAgentOnlyAndPinsTheDesignatedServer(t *testing.T) {
	if _, err := JoinConfig(document(t, launchconfig.Server)); err == nil {
		t.Fatal("server can run agent enrollment")
	}
	cfg, err := JoinConfig(document(t, launchconfig.Agent))
	if err != nil {
		t.Fatal(err)
	}
	want := join.JoinConfig{ServerAddr: "192.0.2.10:8444", AttestationAPIURL: launchconfig.DefaultAttestationAPIURL,
		Platform: "tdx", MeasurementsConfig: launchDir + "cds.json", TokenOut: "/run/confos/rke2-agent-token", Timeout: join.DefaultTimeout}
	if cfg != want {
		t.Fatalf("enrollment config = %+v, want %+v", cfg, want)
	}
}
