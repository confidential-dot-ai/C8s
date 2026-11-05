package nodeservices

import (
	"bytes"
	"errors"
	"fmt"
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
)

func TestPrepareFailsClosedOnBrokenBakedInputs(t *testing.T) {
	overwrite := func(root, name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s", name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		break_ func(root string)
		want   string
	}{
		{"missing policy", func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/image-policy.yaml")) }, "image-policy.yaml"},
		{"invalid policy yaml", func(root string) { overwrite(root, "image-policy.yaml", "allowlist: [") }, "baked NRI policy"},
		{"policy without allowlist", func(root string) { overwrite(root, "image-policy.yaml", "platform: tdx\n") }, "missing allowlist"},
		{"policy without pull", func(root string) { overwrite(root, "image-policy.yaml", "allowlist:\n  base: {}\n") }, "missing pull"},
		{"missing seed", func(root string) { os.Remove(filepath.Join(root, "usr/lib/c8s/allowlist-seed.json")) }, "allowlist-seed.json"},
		{"invalid seed", func(root string) { overwrite(root, "allowlist-seed.json", "{") }, "baked workload seed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			tc.break_(root)
			err := Prepare(root, FloorInputs{CDS: testCDS(t)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(root, PublicDir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published a seed from broken inputs")
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

	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err != nil {
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
	unrenderable := cmdsutil.CDS{Address: "192.0.2.50:8443", Measurements: "{"}

	if err := Prepare(root, FloorInputs{CDS: unrenderable}); err == nil {
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
	baked := strings.Replace(placeholderFloor, `cluster_ranges: ["10.52.0.0/16", "10.53.0.0/16"]`, "cluster_ranges: %s", 1)
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
			err := Prepare(root, FloorInputs{
				CDS:           testCDS(t),
				ClusterRanges: tc.ranges,
				Placeholders:  floorValues(),
			})
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

// Staging writes its own CDS pin, and every other output it takes is one it
// also clears, so none outlives the staging that wrote it.
func TestPrepareRefusesAnOutputItCannotManage(t *testing.T) {
	for _, tc := range []struct {
		name string
		want error
	}{
		{CDSOutput, errOutputIsCDSPin},
		{"kubeconfig", errOutputNotCleared},
		{"router/../peers.json", errOutputNotCleared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			in := FloorInputs{
				CDS:     testCDS(t),
				Outputs: map[string][]byte{tc.name: []byte("x")},
			}
			if err := Prepare(root, in); !errors.Is(err, tc.want) {
				t.Errorf("Prepare with output %q = %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

// A caller's cluster DNS address completes the baked mesh policy, which may
// declare that address but no other.
func TestPrepareBindsTheResolverTheBakedPolicyAllows(t *testing.T) {
	const bakedResolver = `  resolver: "10.53.0.10"` + "\n"
	if !strings.Contains(placeholderFloor, bakedResolver) {
		t.Fatal("placeholderFloor declares no resolver to replace")
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
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(strings.Replace(placeholderFloor, bakedResolver, tc.baked, 1)))
			err := Prepare(root, FloorInputs{
				CDS:          testCDS(t),
				Resolver:     tc.resolver,
				Placeholders: floorValues(),
			})
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

// placeholderFloor is a baked config whose base pins both node placeholders and
// whose mesh policy declares the cluster's ranges.
const placeholderFloor = `platform: tdx
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      kube-apiserver:
        containers:
          - digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
            command: {policy: any}
            args:
              policy: exact
              argv: ["--advertise-address=${NODE_ADVERTISE_ADDRESS}", "--node-name=${NODE_NAME}", "--secure-port=6443"]
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
policy:
  mode: fail-closed
  enforce_existing: true
` + meshPolicy + `  cluster_ranges: ["10.52.0.0/16", "10.53.0.0/16"]
`
