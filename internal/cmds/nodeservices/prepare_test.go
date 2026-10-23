package nodeservices

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func TestPreparationRequiresAStagedRole(t *testing.T) {
	for _, run := range []func(string, *launchconfig.Document) error{Prepare, PublishNodeIP} {
		if err := run(t.TempDir(), document(t, "observer")); err == nil || !strings.Contains(err.Error(), "invalid staged role") {
			t.Fatalf("unknown role: %v", err)
		}
	}
}

func TestPublishNodeIPResolvesTheHostRoute(t *testing.T) {
	old := primaryIPv4
	t.Cleanup(func() { primaryIPv4 = old })
	doc := document(t, launchconfig.Agent)

	primaryIPv4 = func() (string, error) { return "", errors.New("no default route") }
	if err := PublishNodeIP(t.TempDir(), doc); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("route failure: %v", err)
	}
	primaryIPv4 = func() (string, error) { return "2001:db8::1", nil }
	if err := PublishNodeIP(t.TempDir(), doc); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 route: %v", err)
	}
	primaryIPv4 = func() (string, error) { return "192.0.2.30", nil }
	root := t.TempDir()
	if err := PublishNodeIP(root, doc); err != nil {
		t.Fatal(err)
	}
	if ip, err := os.ReadFile(filepath.Join(root, nodeIPPath)); err != nil || string(ip) != "192.0.2.30\n" {
		t.Fatalf("got %q, %v", ip, err)
	}

	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "run"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PublishNodeIP(blocked, doc); err == nil {
		t.Fatal("published through a blocked parent directory")
	}
}

func TestPrepareFailsClosedOnBrokenBakedInputs(t *testing.T) {
	overwrite := func(root, name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s", name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		role   launchconfig.Role
		break_ func(root string)
		want   string
	}{
		{"missing policy", launchconfig.Agent, func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/image-policy.yaml")) }, "image-policy.yaml"},
		{"invalid policy yaml", launchconfig.Agent, func(root string) { overwrite(root, "image-policy.yaml", "allowlist: [") }, "baked NRI policy"},
		{"policy without allowlist", launchconfig.Agent, func(root string) { overwrite(root, "image-policy.yaml", "platform: tdx\n") }, "missing allowlist"},
		{"policy without pull", launchconfig.Agent, func(root string) { overwrite(root, "image-policy.yaml", "allowlist:\n  base: {}\n") }, "missing pull"},
		{"missing seed", launchconfig.Server, func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/allowlist-seed.json")) }, "allowlist-seed.json"},
		{"invalid seed", launchconfig.Server, func(root string) { overwrite(root, "allowlist-seed.json", "{") }, "baked workload seed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			tc.break_(root)
			err := Prepare(root, document(t, tc.role))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published a seed from broken inputs")
			}
		})
	}
}

func TestPrepareRejectsInvalidLaunchWorkloads(t *testing.T) {
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)
	doc.Workloads = `{"schema":"c8s.allowlist/v1","workloads":`
	err := Prepare(root, doc)
	if err == nil || !strings.Contains(err.Error(), "launch workloads") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published a seed with rejected launch workloads")
	}
}

func TestMissingLaunchDocumentHasNoBootSideEffects(t *testing.T) {
	old := primaryIPv4
	t.Cleanup(func() { primaryIPv4 = old })
	primaryIPv4 = func() (string, error) {
		t.Fatal("resolved a host route without a launch document")
		return "", nil
	}
	for name, run := range map[string]func(string, *launchconfig.Document) error{
		"prepare":         Prepare,
		"publish node IP": PublishNodeIP,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := run(root, nil); err == nil || !strings.Contains(err.Error(), "missing staged launch configuration") {
				t.Fatalf("missing document: %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("missing document created boot state: %v", entries)
			}
		})
	}
}

func TestPrepareRejectsMissingOrPartialIdentityPolicies(t *testing.T) {
	for _, name := range []string{"peers.json", "cds.json"} {
		for _, corruption := range []string{"missing", "malformed", "unanchored", "missing-rtmr", "server-includes-agent", "wrong-family"} {
			t.Run(name+"/"+corruption, func(t *testing.T) {
				root := prepareRoot(t)
				path := filepath.Join(root, launchDir, name)
				pins, err := refvalues.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				switch corruption {
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "malformed":
					writeInput(t, root, launchDir+name, []byte("{"))
				default:
					switch corruption {
					case "unanchored":
						pins.Images[0].Anchor = nil
					case "missing-rtmr":
						delete(pins.Images[0].Registers, 2)
					case "server-includes-agent":
						if name != "cds.json" {
							return
						}
						pins = testPins(t)
					case "wrong-family":
						pins.Family = teetypes.FamilySNP
						for i := range pins.Images {
							pins.Images[i].Registers = nil
						}
					}
					data, err := refvalues.Format(pins)
					if err != nil {
						t.Fatal(err)
					}
					writeInput(t, root, launchDir+name, data)
				}
				if err := Prepare(root, document(t, launchconfig.Agent)); err == nil {
					t.Fatal("accepted broken staged identity policy")
				}
				if _, err := os.Stat(filepath.Join(root, PublicDir)); !os.IsNotExist(err) {
					t.Fatal("published public state despite invalid identity policy")
				}
			})
		}
	}
}
