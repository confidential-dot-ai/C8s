package nodeservices

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// stubPrimaryIPv4Source replaces the one seam over the host's routes.
func stubPrimaryIPv4Source(t *testing.T, source func() (netip.Addr, error)) {
	t.Helper()
	old := cmdsutil.PrimaryIPv4
	t.Cleanup(func() { cmdsutil.PrimaryIPv4 = old })
	cmdsutil.PrimaryIPv4 = source
}

func TestPreparationRequiresAStagedRole(t *testing.T) {
	for _, run := range []func(string, *launchconfig.Document) error{PrepareNode, PublishNodeIP} {
		if err := run(t.TempDir(), document(t, "observer")); err == nil || !strings.Contains(err.Error(), "invalid staged role") {
			t.Fatalf("unknown role: %v", err)
		}
	}
}

func TestPublishNodeIPResolvesTheHostRoute(t *testing.T) {
	doc := document(t, launchconfig.Agent)

	stubPrimaryIPv4Source(t, func() (netip.Addr, error) { return netip.Addr{}, errors.New("no default route") })
	if err := PublishNodeIP(t.TempDir(), doc); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("route failure: %v", err)
	}
	stubPrimaryIPv4Source(t, func() (netip.Addr, error) { return netip.MustParseAddr("192.0.2.30"), nil })
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
			err := PrepareNode(root, document(t, tc.role))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published a seed from broken inputs")
			}
		})
	}
}

func TestMissingLaunchDocumentHasNoBootSideEffects(t *testing.T) {
	stubPrimaryIPv4Source(t, func() (netip.Addr, error) {
		t.Fatal("resolved a host route without a launch document")
		return netip.Addr{}, nil
	})
	for name, run := range map[string]func(string, *launchconfig.Document) error{
		"prepare":         PrepareNode,
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

func TestPrepareRejectsMissingOrPartialPeerPolicy(t *testing.T) {
	for _, corruption := range []string{"missing", "malformed", "unanchored", "missing-rtmr", "wrong-family"} {
		t.Run(corruption, func(t *testing.T) {
			root := prepareRoot(t)
			path := filepath.Join(root, launchDir, "peers.json")
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
				writeInput(t, root, launchDir+"peers.json", []byte("{"))
			default:
				switch corruption {
				case "unanchored":
					pins.Images[0].Anchor = nil
				case "missing-rtmr":
					delete(pins.Images[0].Registers, 2)
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
				writeInput(t, root, launchDir+"peers.json", data)
			}
			if err := PrepareNode(root, document(t, launchconfig.Agent)); err == nil {
				t.Fatal("accepted broken staged identity policy")
			}
			if _, err := os.Stat(filepath.Join(root, PublicDir)); !os.IsNotExist(err) {
				t.Fatal("published public state despite invalid identity policy")
			}
		})
	}
}

// The document names the cluster's CDS, so the plugin pulls from the address
// it carries, the credential clients reach only that endpoint, and the policy
// pods read is the document's own: every launch digest of the CDS image, on
// that VM's own TEE family.
func TestPrepareNamesTheExternalCDS(t *testing.T) {
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)

	if err := PrepareNode(root, doc); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Allowlist struct {
			Pull map[string]any `yaml:"pull"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	if got := staged.Allowlist.Pull["url"]; got != "https://cds.example.org:8443" {
		t.Errorf("pull url = %v, want the CDS the document names", got)
	}
	roles := stagedMeshPolicy(t, root).Roles
	if len(roles) != 2 {
		t.Fatalf("staged roles = %+v, want the measured mesh role plus the credential role", roles)
	}
	if roles[1].Port != 8443 {
		t.Errorf("credential role port = %d, want the port the document's CDS serves on", roles[1].Port)
	}
	published, err := refvalues.Load(filepath.Join(root, PublicDir, "cds.json"))
	if err != nil {
		t.Fatal(err)
	}
	if published.Family != teetypes.FamilySNP || len(published.Images) != 2 {
		t.Fatalf("published CDS policy = %+v, want both SNP launch digests", published)
	}
	for _, image := range published.Images {
		if len(image.LaunchFile) == 0 {
			t.Fatalf("published CDS pin %s lost its launch file", image.Name)
		}
	}
}

// A document whose CDS pins cannot be rendered publishes nothing: the node
// services would otherwise hand every pod an unusable policy.
func TestPrepareRefusesAnUnrenderableCDSPolicy(t *testing.T) {
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)
	doc.CDS = cmdsutil.CDS{Address: "192.0.2.50:8443", Measurements: "{"}

	if err := PrepareNode(root, doc); err == nil {
		t.Fatal("accepted a document whose CDS policy does not parse")
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published public state despite an invalid CDS policy")
	}
}

// externalCDSPin is the pin document of a CDS VM on another TEE family than
// this node's, with one entry per vCPU count it may boot with.
func externalCDSPin(t *testing.T) []byte {
	t.Helper()
	launchFile := []byte("schemaVersion: c8s-cds/v1\n")
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{
			{Name: "cds-smp4", Digest: bytes.Repeat([]byte{0x50}, 48), LaunchFile: launchFile},
			{Name: "cds-smp8", Digest: bytes.Repeat([]byte{0x51}, 48), LaunchFile: launchFile},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A caller's cluster ranges complete the baked mesh policy, which may declare
// the same set in any order but no other.
func TestPrepareBindsClusterRangesTheBakedPolicyAllows(t *testing.T) {
	baked := strings.Replace(goldenFloor, `cluster_ranges: ["10.52.0.0/16", "10.53.0.0/16"]`, "cluster_ranges: %s", 1)
	for _, tc := range []struct {
		name   string
		baked  string
		ranges []string
		want   string
	}{
		{"the same set reordered", `["10.53.0.0/16", "10.52.0.0/16"]`, []string{"10.52.0.0/16", "10.53.0.0/16"}, ""},
		{"another set", `["10.52.0.0/16", "10.53.0.0/16"]`, []string{"10.100.0.0/16", "10.53.0.0/16"}, "contradict"},
		{"a baked string, not a list", `"10.52.0.0/16"`, []string{"10.52.0.0/16"}, "not a list"},
		{"a baked list of mappings", `[{range: 10.52.0.0/16}]`, []string{"10.52.0.0/16"}, "not a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(fmt.Sprintf(baked, tc.baked)))
			err := Prepare(root, FloorInputs{CDS: document(t, launchconfig.Agent).CDS, ClusterRanges: tc.ranges, Placeholders: nodeValues(launchconfig.Node{Name: "n1"})})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if got := stagedMeshRanges(t, root); !slices.Equal(got, tc.ranges) {
					t.Fatalf("cluster_ranges = %v, want %v", got, tc.ranges)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published public state for refused cluster ranges")
			}
		})
	}
}

// stagedMeshRanges are the staged mesh policy's cluster ranges.
func stagedMeshRanges(t *testing.T, root string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Mesh struct {
			ClusterRanges []string `yaml:"cluster_ranges"`
		} `yaml:"mesh"`
	}
	if err := yaml.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	return staged.Mesh.ClusterRanges
}

// Every output Prepare publishes is one it clears, so none outlives the
// preparation that wrote it.
func TestPrepareRefusesAnOutputItDoesNotClear(t *testing.T) {
	for _, name := range []string{"cds.json", "kubeconfig", "router/../peers.json"} {
		root := prepareRoot(t)
		in := FloorInputs{
			CDS:     document(t, launchconfig.Agent).CDS,
			Outputs: map[string][]byte{name: []byte("x")},
		}
		if err := Prepare(root, in); err == nil {
			t.Errorf("published %q", name)
		}
	}
}

// A caller's cluster DNS address completes the baked mesh policy, which may
// declare that address but no other.
func TestPrepareBindsTheResolverTheBakedPolicyAllows(t *testing.T) {
	const bakedResolver = `  resolver: "10.53.0.10"` + "\n"
	if !strings.Contains(goldenFloor, bakedResolver) {
		t.Fatal("goldenFloor declares no resolver to replace")
	}
	for _, tc := range []struct {
		name, baked, resolver, want string
	}{
		{"the baked address", bakedResolver, "10.53.0.10", ""},
		{"none baked", "", "10.200.0.10", ""},
		{"another address", bakedResolver, "10.200.0.10", "contradicts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(goldenFloor, bakedResolver, tc.baked, 1)))
			err := Prepare(root, FloorInputs{CDS: document(t, launchconfig.Agent).CDS, Resolver: tc.resolver, Placeholders: nodeValues(launchconfig.Node{Name: "n1"})})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var staged struct {
				Mesh struct {
					Resolver string `yaml:"resolver"`
				} `yaml:"mesh"`
			}
			if err := yaml.Unmarshal(data, &staged); err != nil {
				t.Fatal(err)
			}
			if staged.Mesh.Resolver != tc.resolver {
				t.Fatalf("resolver = %q, want %q", staged.Mesh.Resolver, tc.resolver)
			}
		})
	}
}
