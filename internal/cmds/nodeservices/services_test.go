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
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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
const cdsFloor = `{"schema":"c8s.allowlist/v1","workloads":{"cds-ha-replica":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"exact","argv":["/c8s","cds"]},"args":{"policy":"exact","argv":["--ha-config=/run/c8s-node/cds-ha.json"]}}]}}}`
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
	// Non-root components read the address (cmdsutil.NodeIPPath).
	if info, err := os.Stat(filepath.Join(root, nodeIPPath)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("node-ip mode = %v, %v, want 0644", info.Mode().Perm(), err)
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
				if entry.IsDir() {
					continue // router/, covered by TestPrepareWritesRouterInputs
				}
				info, err := entry.Info()
				if err != nil || info.Mode().Perm() != 0644 {
					t.Fatalf("public file permissions: %v, %v", info, err)
				}
				data, err := os.ReadFile(filepath.Join(root, PublicDir, entry.Name()))
				if err != nil || bytes.Contains(data, []byte("SECRET-")) {
					t.Fatalf("secret or unreadable public file %s: %v", entry.Name(), err)
				}
			}
			want := []string{"cds-mode", "cds.json", "peers.json"}
			if role == launchconfig.Server {
				want = []string{"allowlist-seed.json", "cds-mode", "cds.json", "operator-pubkey", "peers.json", "router", "tls-san"}
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
	for _, name := range serverOutputNames {
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

func TestPrepareWritesRouterInputs(t *testing.T) {
	tests := []struct {
		name   string
		router *launchconfig.Router
		want   map[string]string
	}{
		{"unset", nil, map[string]string{
			"tls.conf":           "include /usr/lib/c8s/router-nginx/tls-cds.conf;\n",
			"hostnames":          "",
			"acme-email":         "",
			"acme-directory-url": "",
			"front-door-mode":    "cds\n",
		}},
		{"public", &launchconfig.Router{
			Hostnames:        []string{"candidate.api.confidential.ai", "api.confidential.ai"},
			ACMEEmail:        "ops@confidential.ai",
			ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		}, map[string]string{
			"hostnames":          "candidate.api.confidential.ai\napi.confidential.ai\n",
			"acme-email":         "ops@confidential.ai\n",
			"acme-directory-url": "https://acme-staging-v02.api.letsencrypt.org/directory\n",
			"front-door-mode":    "acme\n",
			"tls.conf":           "include /usr/lib/c8s/router-nginx/tls-acme.conf;\n",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := prepareRoot(t)
			doc := document(t, launchconfig.Server)
			doc.Router = tc.router
			if err := Prepare(root, doc); err != nil {
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
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)
	doc.Router = &launchconfig.Router{Hostnames: []string{`a.example.com; return 200 "x"`}}
	if err := Prepare(root, doc); err == nil {
		t.Fatal("injected hostname was published")
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "router", "hostnames")); !os.IsNotExist(err) {
		t.Fatalf("rejected document published router input: %v", err)
	}
}

// A launched node completes its measured mesh policy with the one binding only
// a launch knows: the injected credential clients reach this cluster's CDS. The
// measured parts are untouched, so staging cannot widen them.
func TestPrepareBindsTheCredentialRoleToTheStagedCDS(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(meshFloor))
	doc := document(t, launchconfig.Server)

	if err := Prepare(root, doc); err != nil {
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
	if want := []string{"192.0.2.10:30808"}; !reflect.DeepEqual(credentials.Destinations, want) {
		t.Errorf("credential destinations = %v, want this cluster's CDS %v", credentials.Destinations, want)
	}
}

// A baked config without a mesh policy is staged by no launch.
func TestPrepareRefusesABakedConfigWithoutAMeshPolicy(t *testing.T) {
	root := prepareRoot(t)
	writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(floor))

	if err := Prepare(root, document(t, launchconfig.Server)); err == nil {
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

			if err := Prepare(root, document(t, launchconfig.Server)); err == nil {
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

	if err := Prepare(root, document(t, launchconfig.Server)); err != nil {
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
	Name         string   `yaml:"name"`
	UID          uint32   `yaml:"uid"`
	Destinations []string `yaml:"destinations"`
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

// TestPrepareHACluster: with cdsHA, cds.json pins the server and the cds
// launch key; the server publishes cds-mode=ha; a cds node gets cds-ha.json
// and an NRI policy without the served-allowlist pull.
func TestPrepareHACluster(t *testing.T) {
	pins := testPins(t)
	if len(pins.Images) < 2 {
		t.Skip("testdata needs two identities")
	}
	haRoot := func(t *testing.T, cdsImages int) string {
		root := prepareRoot(t)
		writeInput(t, root, "/usr/lib/c8s/cds-floor.json", []byte(cdsFloor))
		p := pins
		p.Images = pins.Images[:cdsImages]
		data, err := refvalues.Format(p)
		if err != nil {
			t.Fatal(err)
		}
		writeInput(t, root, launchDir+"cds.json", data)
		return root
	}
	haDoc := func(role launchconfig.Role) *launchconfig.Document {
		d := document(t, role)
		d.ClusterID = "cdsha"
		d.CDSOperatorPublicKeys = []string{string(pins.Images[1].Anchor)}
		d.CDSHA = &launchconfig.CDSHA{DecreeKey: string(pins.Images[1].Anchor), Replicas: 3, PinFloor: 5}
		d.Image.Measurement = strings.Repeat("11", 48)
		d.Image.RTMRs = map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}
		return d
	}
	t.Run("server", func(t *testing.T) {
		root := haRoot(t, 2)
		writeInput(t, root, PublicDir+"/"+cdsHAFile, []byte("{}"))
		if err := Prepare(root, haDoc(launchconfig.Server)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, PublicDir, cdsHAFile)); !os.IsNotExist(err) {
			t.Fatal("a server kept a stale cds-ha.json")
		}
		mode, _ := os.ReadFile(filepath.Join(root, PublicDir, CDSModeFile))
		if string(mode) != "ha\n" {
			t.Fatalf("cds-mode %q", mode)
		}
		manifests := filepath.Join(root, rke2ManifestsDir)
		if _, err := os.Stat(filepath.Join(manifests, "c8s-cds-singleton.yaml.skip")); err != nil {
			t.Fatal("HA server does not skip the singleton CDS")
		}
		if _, err := os.Stat(filepath.Join(manifests, "c8s-cds-ha.yaml.skip")); err == nil {
			t.Fatal("HA server skips the HA CDS")
		}
		// CDS clients learn how to follow the operator's pin decrees.
		var info cmdsutil.CDSDecreesInfo
		raw, err := os.ReadFile(filepath.Join(root, PublicDir, CDSDecreesFile))
		if err != nil || json.Unmarshal(raw, &info) != nil || info.ClusterID != "cdsha" || info.DecreeKey != string(pins.Images[1].Anchor) || info.PinFloor != 5 {
			t.Fatalf("cds-decrees.json: %s %v", raw, err)
		}
		policy, err := os.ReadFile(filepath.Join(root, "/etc/nri/conf.d/image-policy.yaml"))
		if err != nil || !bytes.Contains(policy, []byte("cds_decrees_file: "+PublicDir+"/"+CDSDecreesFile)) {
			t.Fatalf("NRI pull does not follow pin decrees:\n%s", policy)
		}
		// Without HA the file goes.
		noHA := haDoc(launchconfig.Server)
		noHA.CDSHA, noHA.CDSOperatorPublicKeys = nil, nil
		root1 := haRoot(t, 1)
		writeInput(t, root1, PublicDir+"/"+CDSDecreesFile, raw)
		if err := Prepare(root1, noHA); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root1, PublicDir, CDSDecreesFile)); !os.IsNotExist(err) {
			t.Fatal("a cluster without HA CDS kept cds-pins.json")
		}
	})
	t.Run("cds node binds the credential role", func(t *testing.T) {
		// The measured base names the credential workloads on every node, and
		// the runtime refuses a base whose credential role is unbound: a cds
		// node without the binding could start no pod at all (found on TDX).
		root := haRoot(t, 2)
		writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(meshFloor))
		if err := Prepare(root, haDoc(launchconfig.CDS)); err != nil {
			t.Fatal(err)
		}
		staged := stagedMeshPolicy(t, root)
		if len(staged.Roles) != 2 || staged.Roles[1].Name != nriimagepolicy.CredentialRole {
			t.Fatalf("cds node roles = %+v", staged.Roles)
		}
	})
	t.Run("cds", func(t *testing.T) {
		root := haRoot(t, 2)
		if err := Prepare(root, haDoc(launchconfig.CDS)); err != nil {
			t.Fatal(err)
		}
		var ha CDSHAConfig
		raw, err := os.ReadFile(filepath.Join(root, PublicDir, cdsHAFile))
		if err != nil || json.Unmarshal(raw, &ha) != nil || ha.ClusterID != "cdsha" || ha.Replicas != 3 {
			t.Fatalf("cds-ha.json: %s %v", raw, err)
		}
		policy, err := os.ReadFile(filepath.Join(root, "/etc/nri/conf.d/image-policy.yaml"))
		if err != nil || bytes.Contains(policy, []byte("pull:")) {
			t.Fatalf("cds node NRI policy must not pull the served allowlist:\n%s", policy)
		}
		// The cds floor replaces the chart seed: the replica entry is in, the
		// operator image (same c8s binary, any argv) is out.
		if !bytes.Contains(policy, []byte("cds-ha-replica")) || bytes.Contains(policy, []byte("operator:")) {
			t.Fatalf("cds node NRI floor is not the cds floor:\n%s", policy)
		}
	})
	t.Run("cds.json without the cds pin", func(t *testing.T) {
		if err := Prepare(haRoot(t, 1), haDoc(launchconfig.Server)); err == nil {
			t.Fatal("accepted a cds.json that does not pin the cds launch key")
		}
	})
}
