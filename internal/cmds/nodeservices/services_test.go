package nodeservices

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// testCDS is the CDS block a staged document carries: the cluster's CDS on
// another TEE family than this node's, at the pin floor its launch named.
func testCDS(t *testing.T) cmdsutil.CDS {
	t.Helper()
	return cmdsutil.CDS{
		Address:      "cds.example.org:8443",
		Measurements: string(externalCDSPin(t)),
		PinFloor:     9,
	}
}

const floor = "platform: tdx\nallowlist:\n  base:\n    schema: c8s.allowlist/v1\n    workloads:\n      system:\n        containers:\n          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n            command: {policy: any}\n            args: {policy: any}\n  pull:\n    url: https://127.0.0.1:30808\n    timeout: 30s\npolicy:\n  mode: fail-closed\n  enforce_existing: true\n"
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
	for name, data := range map[string]string{"image-policy.yaml": meshFloor, "allowlist-seed.json": seed} {
		writeInput(t, root, "/usr/lib/c8s/"+name, []byte(data))
	}
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

// Staging completes the measured floor: the baked enforcement policy and
// system workload stay as they are, the chart's components join the base, and
// the pull section names the CDS the document carries.
func TestPreparePreservesTheMeasuredFloor(t *testing.T) {
	root := prepareRoot(t)
	cds := testCDS(t)
	if err := Prepare(root, FloorInputs{CDS: cds}); err != nil {
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
	if pull["url"] != cmdsutil.CDSURL(cds.Address) || pull["cds_measurements_config"] != PublicDir+"/cds.json" || pull["timeout"] != "30s" {
		t.Fatalf("bad pull config: %v", pull)
	}
	// The floor must arrive as the number the enforcer reads.
	if floor := publishedPinFloor(t, pull); floor != cds.PinFloor {
		t.Fatalf("pull cds_pin_floor = %d, want the document's %d", floor, cds.PinFloor)
	}
}

// The address a node publishes is world-readable, so every non-root component
// can read the attestation-api address, and one no peer can dial is refused.
func TestPublishNodeAddressWritesAReadableRoutableAddress(t *testing.T) {
	root := t.TempDir()
	if err := PublishNodeAddress(root, netip.MustParseAddr("192.0.2.22")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, nodeIPPath))
	if err != nil || string(data) != "192.0.2.22\n" {
		t.Fatalf("got %q, %v", data, err)
	}
	// Non-root components read the address (cmdsutil.NodeIPPath).
	if info, err := os.Stat(filepath.Join(root, nodeIPPath)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("node-ip mode = %v, %v, want 0644", info.Mode().Perm(), err)
	}
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "::1", "224.0.0.1"} {
		if err := PublishNodeAddress(t.TempDir(), netip.MustParseAddr(ip)); err == nil {
			t.Errorf("accepted %s", ip)
		}
	}
}

// Every file Prepare publishes is world-readable, and one it published before
// is removed when the next staging does not name it.
func TestPreparePublishesWorldReadableOutputsAndClearsTheRest(t *testing.T) {
	root := prepareRoot(t)
	router, err := RouterOutputs(launchconfig.Router{})
	if err != nil {
		t.Fatal(err)
	}
	if len(router) != len(routerOutputNames) {
		t.Fatalf("the router inputs are %d files, want the %d staging clears", len(router), len(routerOutputNames))
	}
	if err := Prepare(root, FloorInputs{CDS: testCDS(t), Outputs: router}); err != nil {
		t.Fatal(err)
	}
	for _, name := range routerOutputNames {
		info, err := os.Stat(filepath.Join(root, PublicDir, name))
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("public %s mode = %v, %v, want 0644", name, info, err)
		}
	}
	if info, err := os.Stat(filepath.Join(root, PublicDir, CDSOutput)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("public %s mode = %v, %v, want 0644", CDSOutput, info, err)
	}

	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range routerOutputNames {
		if _, err := os.Stat(filepath.Join(root, PublicDir, name)); !os.IsNotExist(err) {
			t.Fatalf("staging kept %s, which it did not publish: %v", name, err)
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
		t.Run(name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/allowlist-seed.json", []byte(incoming))
			if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err == nil || !strings.Contains(err.Error(), "replaces a baked component") {
				t.Fatalf("accepted chart replacing system floor: %v", err)
			}
		})
	}
}

func TestPrepareAllowsIdenticalMeasuredFloorEntry(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/allowlist-seed.json", []byte(strings.ReplaceAll(seed, "operator", "system")))
	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err != nil {
		t.Fatalf("identical measured floor entry: %v", err)
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

func TestPrepareWritesRouterInputs(t *testing.T) {
	tests := []struct {
		name   string
		router launchconfig.Router
		want   map[string]string
	}{
		{"unset", launchconfig.Router{}, map[string]string{
			"tls.conf":           "include /usr/lib/c8s/router-nginx/tls-cds.conf;\n",
			"hostnames":          "",
			"acme-email":         "",
			"acme-directory-url": "",
			"front-door-mode":    "cds\n",
			"request-body.conf":  "client_max_body_size 1048576;\n",
		}},
		{"body limit", launchconfig.Router{MaxRequestBodyBytes: 64 << 20}, map[string]string{
			"front-door-mode":   "cds\n",
			"request-body.conf": "client_max_body_size 67108864;\n",
		}},
		{"public", launchconfig.Router{
			Hostnames:        []string{"candidate.api.confidential.ai", "api.confidential.ai"},
			ACMEEmail:        "ops@confidential.ai",
			ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}, map[string]string{
			"hostnames":          "candidate.api.confidential.ai\napi.confidential.ai\n",
			"acme-email":         "ops@confidential.ai\n",
			"acme-directory-url": "https://acme-staging-v02.api.letsencrypt.org/directory\n",
			"front-door-mode":    "acme\n",
			"tls.conf":           "include /usr/lib/c8s/router-nginx/tls-acme.conf;\n",
			"request-body.conf":  "client_max_body_size 1048576;\n",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			outputs, err := RouterOutputs(tc.router)
			if err != nil {
				t.Fatal(err)
			}
			if err := Prepare(root, FloorInputs{CDS: testCDS(t), Outputs: outputs}); err != nil {
				t.Fatal(err)
			}
			for name, want := range tc.want {
				path := filepath.Join(root, PublicDir, "router", name)
				data, err := os.ReadFile(path)
				if err != nil || string(data) != want {
					t.Fatalf("%s = %q, %v; want %q", name, data, err, want)
				}
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0644 {
					t.Fatalf("%s permissions: %v, %v", name, info, err)
				}
			}
		})
	}

	// An unvalidated document still cannot publish nginx syntax.
	if _, err := RouterOutputs(launchconfig.Router{Hostnames: []string{`a.example.com; return 200 "x"`}}); err == nil {
		t.Fatal("an injected hostname became a router input")
	}
}

// A launched node completes its measured mesh policy with the one binding only
// a launch knows: the injected credential clients reach this cluster's CDS. The
// measured parts are untouched, so staging cannot widen them.
func TestPrepareBindsTheCredentialRoleToTheStagedCDS(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(meshFloor))
	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err != nil {
		t.Fatal(err)
	}

	staged := stagedMeshPolicy(t, root)
	if got, want := staged.ExemptNamespaces, []string{"kube-system"}; !reflect.DeepEqual(got, want) {
		t.Errorf("staged exempt namespaces = %v, want the measured %v", got, want)
	}
	wantCapture := stagedCapture{
		Outbound: 15001,
		Inbound:  15006,
		Health:   15021,
	}
	if got := staged.Capture; got != wantCapture {
		t.Errorf("staging changed the measured capture ports: %+v", got)
	}
	if len(staged.Roles) != 2 {
		t.Fatalf("staged roles = %+v, want the measured mesh role plus the credential role", staged.Roles)
	}
	if got := staged.Roles[0]; got.Name != "mesh" || got.UID != workloadclaims.MeshUID {
		t.Errorf("staging changed the measured mesh role: %+v", got)
	}
	credentials := staged.Roles[1]
	if credentials.Name != nriimagepolicy.CredentialRole || credentials.UID != workloadclaims.CredentialsUID {
		t.Errorf("credential role = %+v, want %s on the reserved uid %d", credentials, nriimagepolicy.CredentialRole, workloadclaims.CredentialsUID)
	}
	if credentials.Port != 8443 {
		t.Errorf("credential role port = %d, want the port this cluster's CDS serves on", credentials.Port)
	}
}

// A baked config without a mesh policy is staged by no launch.
func TestPrepareRefusesABakedConfigWithoutAMeshPolicy(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(floor))

	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err == nil {
		t.Fatal("staging completed a baked config with no mesh policy")
	}
}

// A measured policy that already binds the credential role, or its reserved
// identity, is one this step would contradict rather than complete.
func TestPrepareRefusesToRebindTheCredentialRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		role string
	}{
		{"the role bound twice", "    - name: " + nriimagepolicy.CredentialRole + "\n      uid: 1400\n      destinations: [\"192.0.2.9:8443\"]\n"},
		{"its uid held by another role", "    - name: router\n      uid: 1338\n      destinations: [\"192.0.2.9:8443\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(meshFloor+tc.role))

			if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err == nil {
				t.Fatal("staging completed a policy that already binds the credential role")
			}
		})
	}
}

// A declared platform role survives staging: it is the measured base's own
// field, and the enforcer grants a role from nowhere else.
func TestPrepareKeepsTheMeasuredRoles(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(roleFloor))

	if err := Prepare(root, FloorInputs{CDS: testCDS(t)}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	endpoint := allowlist.RunningContainer{Digest: "sha256:" + strings.Repeat("b", 64)}
	if got := staged.Allowlist.Base.BuildIndex().RoleOf(endpoint); got != "mesh" {
		t.Fatalf("the staged base grants the mesh endpoint the role %q, want mesh", got)
	}
}

// roleFloor is a baked config whose measured base tags the mesh endpoint with
// its platform role.
const roleFloor = `platform: tdx
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      mesh-endpoint:
        containers:
          - digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            role: "mesh"
            command: {policy: any}
            args: {policy: any}
            mounts: {policy: any}
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
policy:
  mode: fail-closed
  enforce_existing: true
` + meshPolicy

// stagedMeshPolicy reads the mesh policy out of the staged boot config as the
// plugin's own loader would type it.
func stagedMeshPolicy(t *testing.T, root string) stagedMesh {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var staged struct {
		Mesh stagedMesh `yaml:"mesh"`
	}
	if err := yaml.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	return staged.Mesh
}

type stagedMesh struct {
	ExemptNamespaces []string      `yaml:"exempt_namespaces"`
	Capture          stagedCapture `yaml:"capture"`
	Roles            []stagedRole  `yaml:"roles"`
}

type stagedCapture struct {
	Outbound uint16 `yaml:"outbound"`
	Inbound  uint16 `yaml:"inbound"`
	Health   uint16 `yaml:"health"`
}

type stagedRole struct {
	Name string `yaml:"name"`
	UID  uint32 `yaml:"uid"`
	Port uint16 `yaml:"port"`
}

// meshPolicy is the measured mesh policy a baked config carries: its own role
// bound and the credential destination left to the launch.
const meshPolicy = `mesh:
  exempt_namespaces: [kube-system]
  resolver: "10.53.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`

// meshFloor is the baked config of a node, as the image always writes one.
const meshFloor = floor + meshPolicy

// publishedPinFloor is the floor the enforcer reads out of the pull section.
func publishedPinFloor(t *testing.T, pull map[string]any) cmdsutil.ClusterVersion {
	t.Helper()
	data, err := yaml.Marshal(pull)
	if err != nil {
		t.Fatal(err)
	}
	var read struct {
		PinFloor cmdsutil.ClusterVersion `yaml:"cds_pin_floor"`
	}
	if err := yaml.Unmarshal(data, &read); err != nil {
		t.Fatal(err)
	}
	return read.PinFloor
}
