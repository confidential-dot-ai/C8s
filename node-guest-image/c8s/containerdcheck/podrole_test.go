package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
	"sigs.k8s.io/yaml"
)

func TestPodRoleKubeletLeavesPacketRulesToNRI(t *testing.T) {
	data, err := os.ReadFile("../mkosi.extra/usr/lib/c8s/pod-runtime/kubelet.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		MakeIPTablesUtilChains *bool `json:"makeIPTablesUtilChains"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.MakeIPTablesUtilChains == nil || *config.MakeIPTablesUtilChains {
		t.Fatal("standalone kubelet must explicitly disable utility iptables chains; NRI owns the guest packet rules")
	}
}

// podRoleConfig is the pod role's hand-written containerd config.
const podRoleConfig = "../mkosi.extra/usr/lib/c8s/pod-runtime/containerd.toml"

// podRoleDifferences lists every key, as a "/"-joined TOML path, on which the
// pod role's config may differ from RKE2's rendered base template, and why.
// Every other key must match, so a template re-vendor that changes a key
// fails here until containerd.toml follows it or the key is added with a
// reason.
var podRoleDifferences = map[string]string{
	"plugins/io.containerd.cri.v1.images/pinned_images/sandbox": "pinned by digest to the core bundle's pause image, which " +
		"podcvm-containerd imports from pause.tar at start; renderData carries k3s's default, not RKE2's",
	"plugins/io.containerd.cri.v1.runtime/cni/bin_dirs": "the CNI plugins mkosi.sync stages into the image; " +
		"/opt/cni/bin is filled by Canal, which never runs in a pod boot",
	"plugins/io.containerd.cri.v1.runtime/cni/conf_dir": "the image's baked pod network, not Canal's",
	"plugins/io.containerd.cri.v1.runtime/containerd/runtimes/runhcs-wcow-process/runtime_type": "Windows-only " +
		"handler with no binary on Linux; the pod role enables no handler it cannot run",
}

// The pod role's config mirrors what RKE2 renders on a node, so the shared
// drop-ins and the paths c8s-runc and NRI hard-code apply unchanged. Compared
// structurally: every leaf of either config must equal the other's, except
// the documented pod-role differences.
func TestPodRoleConfigFollowsRKE2Base(t *testing.T) {
	rendered, err := render(filepath.Join(bakedConfigDir, userTemplateName), nil)
	if err != nil {
		t.Fatal(err)
	}
	rke2 := flattenTOML(t, "RKE2's rendered base", []byte(rendered))
	pod, err := os.ReadFile(podRoleConfig)
	if err != nil {
		t.Fatal(err)
	}
	podLeaves := flattenTOML(t, podRoleConfig, pod)

	for _, path := range diffLeaves(rke2, podLeaves) {
		if _, ok := podRoleDifferences[path]; ok {
			continue
		}
		t.Errorf("%s: RKE2 renders %s, the pod role has %s; follow RKE2 in containerd.toml or add the key to podRoleDifferences with a reason",
			path, show(rke2, path), show(podLeaves, path))
	}
	for path := range podRoleDifferences {
		if _, inRKE2 := rke2[path]; !inRKE2 {
			if _, inPod := podLeaves[path]; !inPod {
				t.Errorf("podRoleDifferences lists %s, which neither config has; remove it", path)
			}
		}
	}
}

// The comparison must catch a key the pod config does not follow, in either
// direction and at any depth.
func TestDiffLeaves(t *testing.T) {
	a := map[string]any{"version": int64(3), "imports": []any{"x"}, "p": map[string]any{"q.r": map[string]any{"s": "1"}}}
	b := map[string]any{"version": int64(3), "imports": []any{"x"}, "p": map[string]any{"q.r": map[string]any{"s": "2", "t": true}}}
	la, lb := map[string]any{}, map[string]any{}
	flatten("", a, la)
	flatten("", b, lb)
	if got, want := diffLeaves(la, lb), []string{"p/q.r/s", "p/q.r/t"}; !slices.Equal(got, want) {
		t.Fatalf("diffLeaves = %v, want %v", got, want)
	}
	if got := diffLeaves(la, la); len(got) != 0 {
		t.Fatalf("diffLeaves(identical) = %v, want none", got)
	}
}

func flattenTOML(t *testing.T, name string, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	leaves := map[string]any{}
	flatten("", m, leaves)
	return leaves
}

// flatten records every non-table value under its "/"-joined path. Plugin
// names contain dots, so the path cannot use TOML's own separator.
func flatten(prefix string, m map[string]any, out map[string]any) {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "/" + k
		}
		if sub, ok := v.(map[string]any); ok {
			flatten(path, sub, out)
			continue
		}
		out[path] = v
	}
}

// diffLeaves returns, sorted, every path present in only one of a and b or
// holding different values.
func diffLeaves(a, b map[string]any) []string {
	var diff []string
	for path, v := range a {
		if w, ok := b[path]; !ok || !reflect.DeepEqual(v, w) {
			diff = append(diff, path)
		}
	}
	for path := range b {
		if _, ok := a[path]; !ok {
			diff = append(diff, path)
		}
	}
	slices.Sort(diff)
	return diff
}

func show(leaves map[string]any, path string) string {
	v, ok := leaves[path]
	if !ok {
		return "<absent>"
	}
	return strings.TrimSpace(fmt.Sprintf("%#v", v))
}
