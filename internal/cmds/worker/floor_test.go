package worker

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// nodeFloorTemplate is the node image's floor, as the worker image's build
// reads it.
const nodeFloorTemplate = "../../../images/node-guest/c8s/image-policy.yaml.in"

const testRouterEntry = "c8s-router-0123456789ab"

// renderedNodeFloor is the node image's floor with its digests filled, as the
// image build fills them.
func renderedNodeFloor(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(nodeFloorTemplate)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.NewReplacer(
		"@PLATFORM@", "snp",
		"@MESH_REPO@", "ghcr.io/confidential-dot-ai/armtls-mesh",
		"@MESH_DIGEST@", "sha256:"+strings.Repeat("b", 64),
		"@OPERATOR_REPO@", "ghcr.io/confidential-dot-ai/c8s-operator",
		"@OPERATOR_DIGEST@", "sha256:"+strings.Repeat("a", 64),
		"@ROUTER_REPO@", "docker.io/nginxinc/nginx-unprivileged",
		"@ROUTER_DIGEST@", "sha256:"+strings.Repeat("c", 64),
	).Replace(string(data)))
}

// withoutKey is floor without the key at path.
func withoutKey(t *testing.T, floor []byte, path ...string) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	parent := doc
	for _, key := range path[:len(path)-1] {
		parent = parent[key].(map[string]any)
	}
	delete(parent, path[len(path)-1])
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// settingsOf is floor without its allowlist base, its worker key and the
// mesh keys named.
func settingsOf(t *testing.T, floor []byte, meshKeys ...string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["allowlist"].(map[string]any), "base")
	delete(doc, "worker")
	for _, key := range meshKeys {
		delete(doc["mesh"].(map[string]any), key)
	}
	return doc
}

// routerHostPorts are the router entry's host ports, as the chart seeds them.
const routerHostPorts = `"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"TCP","hostPort":80,"containerPort":8080}]`

// routerSeed is a chart seed holding the router's entry, which reads the
// files named, and another component's.
func routerSeed(files ...string) []byte {
	var args []string
	for _, f := range files {
		args = append(args, `"--file=`+f+`"`)
	}
	return []byte(`{"schema":"c8s.allowlist/v1","workloads":{
  "` + testRouterEntry + `":{` + routerHostPorts + `,"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `",
    "command":{"policy":"exact","argv":["/c8s"]},"args":{"policy":"exact","argv":[` + strings.Join(args, ",") + `]},
    "mounts":{"policy":"exact","rules":[{"destination":"/run/c8s-node","kind":"host","source":"/run/c8s-node","readOnly":true}]},
    "env":{"policy":"exact","values":{"PATH":"/bin"}}}]},
  "c8s-operator-0123":{"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `","command":{"policy":"exact","argv":["/c8s","operator"]},"args":{"policy":"deny"}}]}}}`)
}

// workloadsOf decodes a floor's base workloads, roles included.
func workloadsOf(t *testing.T, floor []byte) map[string]allowlist.Workload {
	t.Helper()
	var doc struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	if err := doc.Allowlist.Base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return doc.Allowlist.Base.Workloads
}

// platformRoleEntries are the node floor's entries a member pod's injected
// containers run under.
var platformRoleEntries = []string{
	"c8s-acme", "c8s-allowlist-proxy", "c8s-get-cert", "c8s-get-secret", "c8s-get-volume",
	"c8s-mesh-endpoint", "c8s-probe-file", "c8s-router-nginx", "c8s-router-upstream",
}

// A worker's floor holds the node floor's platform roles unchanged and the
// router's entry as the seed has it, and no server or agent workload; staged
// from a worker document, it is a floor the plugin runs as a worker's.
func TestFloorKeepsThePlatformRolesAndTheRouter(t *testing.T) {
	nodeFloor := renderedNodeFloor(t)
	seed := routerSeed("/run/c8s-node/cds.json", "/run/c8s-node/operator-pubkey", "/run/c8s-node/router/hostnames")
	floor, err := Floor(nodeFloor, seed)
	if err != nil {
		t.Fatal(err)
	}
	node, worker := workloadsOf(t, nodeFloor), workloadsOf(t, floor)
	if got, want := slices.Sorted(maps.Keys(worker)), slices.Sorted(slices.Values(append(slices.Clone(platformRoleEntries), testRouterEntry))); !slices.Equal(got, want) {
		t.Fatalf("workloads = %v, want the platform roles and the router, %v", got, want)
	}
	for _, name := range platformRoleEntries {
		if !reflect.DeepEqual(worker[name], node[name]) {
			t.Errorf("platform role %s =\n%+v\nwant the node floor's\n%+v", name, worker[name], node[name])
		}
	}
	parsed, err := allowlist.ParseJSON(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(worker[testRouterEntry], parsed.Workloads[testRouterEntry]) {
		t.Errorf("router entry =\n%+v\nwant the seed's\n%+v", worker[testRouterEntry], parsed.Workloads[testRouterEntry])
	}

	if len(worker[testRouterEntry].HostPorts) != 2 {
		t.Errorf("router host ports = %v, want the seed's two", worker[testRouterEntry].HostPorts)
	}
	var doc struct {
		Worker bool `yaml:"worker"`
	}
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := settingsOf(t, floor), settingsOf(t, nodeFloor, "exempt_namespaces", "exits", "resolver", "cluster_ranges"); !reflect.DeepEqual(got, want) {
		t.Errorf("settings =\n%v\nwant the node floor's without what stage fills or a worker refuses\n%v", got, want)
	}
	if !doc.Worker {
		t.Fatal("the floor does not set worker: true")
	}

	root := workerRoot(t)
	if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s/image-policy.yaml"), floor, 0o644); err != nil {
		t.Fatal(err)
	}
	data := workerDocumentBytes(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatalf("stage of the generated floor = %v", err)
	}
}

// A key the node floor leaves out stays out of the worker's.
func TestFloorWritesNoSettingTheNodeFloorLacks(t *testing.T) {
	dropped := []string{"exempt_namespaces", "exits", "resolver", "cluster_ranges"}
	for _, path := range [][]string{
		{"platform"}, {"plugin"}, {"workload_claims"}, {"containerd"}, {"policy"}, {"logging"},
		{"allowlist", "node_tcb"}, {"allowlist", "pull"}, {"mesh", "capture"}, {"mesh", "roles"},
	} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			nodeFloor := withoutKey(t, renderedNodeFloor(t), path...)
			floor, err := Floor(nodeFloor, routerSeed("/run/c8s-node/cds.json"))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := settingsOf(t, floor), settingsOf(t, nodeFloor, dropped...); !reflect.DeepEqual(got, want) {
				t.Errorf("settings =\n%v\nwant the node floor's\n%v", got, want)
			}
		})
	}
}

func TestFloorRefusesInputsItCannotBuildAWorkersFloorFrom(t *testing.T) {
	nodeFloor := renderedNodeFloor(t)
	seed := routerSeed("/run/c8s-node/cds.json")
	// An entry declaring host ports pins its launch, so the open one declares none.
	unpinnedRouter := []byte(strings.Replace(strings.Replace(string(seed), routerHostPorts+",", "", 1), `"env":{"policy":"exact","values":{"PATH":"/bin"}}`, `"env":{"policy":"any"}`, 1))
	for _, tc := range []struct {
		name            string
		nodeFloor, seed []byte
		want            string
	}{
		{"no router entry", nodeFloor, []byte(strings.ReplaceAll(string(seed), testRouterEntry, "other")), "want one c8s-router-* entry"},
		{"two router entries", nodeFloor, []byte(strings.Replace(string(seed), `"c8s-operator-0123"`, `"c8s-router-other"`, 1)), "want one c8s-router-* entry"},
		{"a router reading a server's file", nodeFloor, routerSeed("/run/c8s-node/peers.json"), "/run/c8s-node/peers.json, which worker stage does not publish"},
		{"no platform role", regexp.MustCompile(`(?m)^ +role: .*\n`).ReplaceAll(nodeFloor, nil), seed, "no platform-role entry"},
		{"a base field the allowlist does not have", []byte(strings.Replace(string(nodeFloor), "    schema: c8s.allowlist/v1\n", "    schema: c8s.allowlist/v1\n    extra: 1\n", 1)), seed, "field extra not found"},
		{"no mesh policy", withoutKey(t, nodeFloor, "mesh"), seed, "no allowlist base or mesh policy"},
		{"no allowlist", withoutKey(t, nodeFloor, "allowlist"), seed, "no allowlist base or mesh policy"},
		{"no allowlist base", withoutKey(t, nodeFloor, "allowlist", "base"), seed, "no allowlist base or mesh policy"},
		{"a top-level key it does not know", append(slices.Clone(nodeFloor), "extra: 1\n"...), seed, "field extra not found in type worker.nodeFloor"},
		{"an allowlist key it does not know", []byte(strings.Replace(string(nodeFloor), "\n  node_tcb: true\n", "\n  node_tcb: true\n  extra: 1\n", 1)), seed, "field extra not found in type worker.floorAllowlist"},
		{"a mesh key it does not know", []byte(strings.Replace(string(nodeFloor), "\nmesh:\n", "\nmesh:\n  extra: 1\n", 1)), seed, "field extra not found in type worker.nodeMesh"},
		{"a router entry named as a platform role", nodeFloor, []byte(strings.ReplaceAll(string(seed), testRouterEntry, "c8s-router-nginx")), "a platform role is named c8s-router-nginx"},
		{"a router reading a server's file through its environment", nodeFloor, []byte(strings.Replace(string(seed), `"values":{"PATH":"/bin"}`, `"values":{"PATH":"/bin","PEERS":"/run/c8s-node/peers.json"}`, 1)), "/run/c8s-node/peers.json"},
		{"a router mounting a server's file", nodeFloor, []byte(strings.Replace(string(seed), `"source":"/run/c8s-node"`, `"source":"/run/c8s-node/peers.json"`, 1)), "/run/c8s-node/peers.json"},
		{"a router reading a file by a doubled slash", nodeFloor, routerSeed("/run//c8s-node/peers.json"), "which worker stage does not publish"},
		{"a router reading outside by dot-dot", nodeFloor, routerSeed("/run/c8s-node/../nri-image-policy/x"), "which worker stage does not publish"},
		{"an open router launch", nodeFloor, unpinnedRouter, "does not pin its launch"},
		{"a router mounting operator data", nodeFloor, []byte(strings.Replace(string(seed), `"rules":[`, `"rules":[{"destination":"/mnt/c8s-data/keys","kind":"data"},`, 1)), "mounts data, which the control plane fills"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Floor(tc.nodeFloor, tc.seed); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Floor = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
