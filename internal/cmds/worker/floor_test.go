package worker

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// floorTemplateFile is the worker image's floor template, as its build reads
// it.
const floorTemplateFile = "../../../images/node-guest/worker/image-policy.yaml.in"

// renderedTemplate is the image's floor template with its digests filled, as
// the image build fills them.
func renderedTemplate(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(floorTemplateFile)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.NewReplacer(
		"@PLATFORM@", "snp",
		"@MESH_REPO@", "ghcr.io/confidential-dot-ai/armtls-mesh",
		"@MESH_DIGEST@", "sha256:"+strings.Repeat("b", 64),
		"@OPERATOR_REPO@", "ghcr.io/confidential-dot-ai/c8s-operator",
		"@OPERATOR_DIGEST@", "sha256:"+strings.Repeat("a", 64),
		"@ROUTER_REPO@", "docker.io/nginx/nginx-unprivileged",
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

// measured is a floor's settings with served allowlists measured, as a
// worker's are.
func measured(settings map[string]any) map[string]any {
	settings["allowlist"].(map[string]any)["pull"].(map[string]any)["measure_policies"] = true
	return settings
}

// settingsOf is floor without its allowlist base and its worker key.
func settingsOf(t *testing.T, floor []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["allowlist"].(map[string]any), "base")
	delete(doc, "worker")
	return doc
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

// A worker's floor holds an entry for each of the image's static pod
// templates and nothing else: the template's role entries are published in
// the release's component set. Staged from a worker document, it is a floor
// the plugin runs as a worker's.
func TestFloorHoldsTheStaticPodsAlone(t *testing.T) {
	template := renderedTemplate(t)
	floor, err := Floor(template, map[string][]byte{"agent.yaml": []byte(agentTemplate)})
	if err != nil {
		t.Fatal(err)
	}
	worker := workloadsOf(t, floor)
	if got := slices.Sorted(maps.Keys(worker)); !slices.Equal(got, []string{"agent"}) {
		t.Fatalf("workloads = %v, want the image's static pod alone", got)
	}
	if !worker["agent"].StaticPod {
		t.Error("the static pod's entry is not marked as one")
	}
	var doc struct {
		Worker bool `yaml:"worker"`
	}
	if err := yaml.Unmarshal(floor, &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := settingsOf(t, floor), measured(settingsOf(t, template)); !reflect.DeepEqual(got, want) {
		t.Errorf("settings =\n%v\nwant the template's, measuring served allowlists\n%v", got, want)
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
	staged, err := os.ReadFile(filepath.Join(root, nriimagepolicy.DefaultConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := nriimagepolicy.CheckWorkerConfig(staged); err != nil {
		t.Errorf("the plugin refuses the staged floor: %v", err)
	}
	// The posture the measured floor carries into the plugin: a container
	// already running when it registers is fatal, every launch outside the
	// base is sandboxed, and denials reach the journal.
	var posture struct {
		Policy struct {
			FatalExisting   bool   `yaml:"fatal_existing"`
			Sandbox         string `yaml:"sandbox"`
			BootMarkerPath  string `yaml:"boot_marker_path"`
			EnforceExisting bool   `yaml:"enforce_existing"`
		} `yaml:"policy"`
		Logging struct {
			Syslog string `yaml:"syslog"`
		} `yaml:"logging"`
	}
	if err := yaml.Unmarshal(staged, &posture); err != nil {
		t.Fatal(err)
	}
	if !posture.Policy.FatalExisting || !posture.Policy.EnforceExisting || posture.Policy.Sandbox != "enforce" {
		t.Errorf("staged policy = %+v, want existing containers fatal, enforced, and every launch sandboxed", posture.Policy)
	}
	if posture.Policy.BootMarkerPath == "" || posture.Logging.Syslog == "" {
		t.Errorf("staged floor names no boot marker (%q) or no syslog (%q)", posture.Policy.BootMarkerPath, posture.Logging.Syslog)
	}
}

// A key the template leaves out stays out of the worker's floor.
func TestFloorWritesNoSettingTheTemplateLacks(t *testing.T) {
	for _, path := range [][]string{
		{"platform"}, {"plugin"}, {"workload_claims"}, {"containerd"}, {"policy"}, {"logging"},
		{"allowlist", "node_tcb"}, {"mesh", "capture"}, {"mesh", "roles"},
	} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			template := withoutKey(t, renderedTemplate(t), path...)
			floor, err := Floor(template, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := settingsOf(t, floor), measured(settingsOf(t, template)); !reflect.DeepEqual(got, want) {
				t.Errorf("settings =\n%v\nwant the template's\n%v", got, want)
			}
		})
	}
}

func TestFloorRefusesInputsItCannotBuildAWorkersFloorFrom(t *testing.T) {
	template := renderedTemplate(t)
	for _, tc := range []struct {
		name     string
		template []byte
		want     string
	}{
		{"a base field the allowlist does not have", []byte(strings.Replace(string(template), "    schema: c8s.allowlist/v1\n", "    schema: c8s.allowlist/v1\n    extra: 1\n", 1)), "field extra not found"},
		{"no mesh policy", withoutKey(t, template, "mesh"), "no allowlist base or mesh policy"},
		{"no allowlist", withoutKey(t, template, "allowlist"), "no allowlist base or mesh policy"},
		{"no allowlist base", withoutKey(t, template, "allowlist", "base"), "no allowlist base or mesh policy"},
		{"no pull", withoutKey(t, template, "allowlist", "pull"), "no allowlist.pull"},
		{"a top-level key it does not know", append(slices.Clone(template), "extra: 1\n"...), "field extra not found in type worker.floorTemplate"},
		{"an allowlist key it does not know", []byte(strings.Replace(string(template), "\n  node_tcb: true\n", "\n  node_tcb: true\n  extra: 1\n", 1)), "field extra not found in type worker.floorAllowlist"},
		{"a mesh key it does not know", []byte(strings.Replace(string(template), "\nmesh:\n", "\nmesh:\n  extra: 1\n", 1)), "field extra not found in type worker.workerMesh"},
		{"a mesh key worker staging fills", []byte(strings.Replace(string(template), "\nmesh:\n", "\nmesh:\n  resolver: \"10.53.0.10\"\n", 1)), "field resolver not found in type worker.workerMesh"},
		{"a mesh key only a node has", []byte(strings.Replace(string(template), "\nmesh:\n", "\nmesh:\n  exempt_namespaces: [kube-system]\n", 1)), "field exempt_namespaces not found in type worker.workerMesh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Floor(tc.template, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Floor = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// Two static pod templates naming one pod would leave the floor describing
// one of them.
func TestFloorRefusesTwoTemplatesOfOnePod(t *testing.T) {
	pods := map[string][]byte{"agent.yaml": []byte(agentTemplate), "agent-copy.yaml": []byte(agentTemplate)}
	if _, err := Floor(renderedTemplate(t), pods); err == nil || !strings.Contains(err.Error(), "pod agent is named as another entry") {
		t.Fatalf("Floor = %v, want a refusal over the second template of pod agent", err)
	}
}
