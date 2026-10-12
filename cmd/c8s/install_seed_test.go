//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// TestSeedWorkloadsMatchesTheChart: the seed install checks adoptions
// against is the one the chart renders, less its argv-pinned entries, and in
// that seed the entry install writes names the adopted pod alone.
func TestSeedWorkloadsMatchesTheChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	resetCLIState(t)
	dir, err := extractChart()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	chart := filepath.Join(dir, helmchart.ChartRoot)
	ctx := context.Background()
	components, err := chartComponents(ctx, chart)
	if err != nil {
		t.Fatal(err)
	}

	always := corev1.ContainerRestartPolicyAlways
	memory := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}
	scratch := []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}
	tmpl := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "scratch", VolumeSource: memory}},
		InitContainers: []corev1.Container{
			{Name: "prep", Image: "busybox@sha256:" + strings.Repeat("b", 64), VolumeMounts: scratch},
			{Name: "proxy", Image: "proxy@sha256:" + strings.Repeat("e", 64), RestartPolicy: &always},
		},
		Containers: []corev1.Container{
			{Name: "app", Image: "app@sha256:" + strings.Repeat("a", 64), VolumeMounts: scratch},
			{Name: "tools", Image: "busybox@sha256:" + strings.Repeat("b", 64)},
		},
	}}
	adoptArgs, entries, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{
		workloadAdoption: workloadAdoption{cwID: "web", ref: workloadRef{kind: "deployment", name: "web", namespace: "ws"}},
		template:         tmpl,
	}}, "", io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, router := range []bool{true, false} {
		t.Run(fmt.Sprintf("router.enabled=%t", router), func(t *testing.T) {
			set := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true", "--set", fmt.Sprintf("router.enabled=%t", router)}
			for i, c := range components {
				set = append(set, "--set-string", fmt.Sprintf("%s.digest=sha256:%064x", c.valuePrefix, i+1))
			}
			set, err := appendCvmModeInstallArgs(set, "bare-metal", "sev-snp")
			if err != nil {
				t.Fatal(err)
			}
			set = append(set, adoptArgs...)
			values, err := effectiveValues(ctx, chart, set)
			if err != nil {
				t.Fatal(err)
			}
			model, err := seedWorkloads(values, components)
			if err != nil {
				t.Fatal(err)
			}
			rendered := renderedSeed(t, chart, set)
			checkSeedModel(t, model, rendered, values)
			if name, _, err := rendered.MatchWorkload(entries["web"].pod); err != nil || name != "web" {
				t.Fatalf("rendered seed matches the adopted pod as %q, %v, want web", name, err)
			}
			if err := checkAdoptedEntries(entries, values, components); err != nil {
				t.Fatalf("checkAdoptedEntries() = %v", err)
			}
		})
	}
}

// TestSeedWorkloadsSharedDigest: components sharing a digest under different
// repositories get one entry, named after the last reference as in the chart,
// so an override of that name leaves no other entry describing the pod.
func TestSeedWorkloadsSharedDigest(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	resetCLIState(t)
	dir, err := extractChart()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	chart := filepath.Join(dir, helmchart.ChartRoot)
	ctx := context.Background()
	components, err := chartComponents(ctx, chart)
	if err != nil {
		t.Fatal(err)
	}
	var shared []c8sComponent
	for _, c := range components {
		if !c.argvPinned && c.enabledPath == "" {
			shared = append(shared, c)
		}
	}
	if len(shared) < 2 {
		t.Fatalf("chart has %d always-rendered any-argv components, want two to share a digest", len(shared))
	}

	digest := "sha256:" + strings.Repeat("d", 64)
	adoptArgs, entries, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{
		workloadAdoption: workloadAdoption{cwID: "solo", ref: workloadRef{kind: "deployment", name: "solo", namespace: "ws"}},
		template:         templateRunning("example/solo@" + digest),
	}}, "", io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	set := []string{"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"}
	for i, c := range components {
		set = append(set, "--set-string", fmt.Sprintf("%s.digest=sha256:%064x", c.valuePrefix, i+1))
	}
	for i, c := range shared[:2] {
		set = append(set, "--set-string", c.valuePrefix+".digest="+digest, "--set-string", fmt.Sprintf("%s.repository=example/shared-%d", c.valuePrefix, i))
	}
	// The override requires a second main, so it describes no pod running
	// the shared image alone.
	solo := entries["solo"].workload
	override := pkgallowlist.Workload{Label: "override", Containers: append(slices.Clone(solo.Containers), solo.Containers[0])}
	override.Containers[1].Digest = want2digest(t, "sha256:"+strings.Repeat("f", 64))
	last := pkgallowlist.DigestEntryName(want2digest(t, digest), "example/shared-1@"+digest)
	raw, err := json.Marshal(map[string]any{"nriImagePolicy": map[string]any{"bootstrapAllowlist": map[string]any{"workloads": map[string]any{last: override}}}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(file, raw, 0o600); err != nil { // JSON is YAML
		t.Fatal(err)
	}
	installValues = []string{file}
	set, err = appendCvmModeInstallArgs(set, "bare-metal", "sev-snp")
	if err != nil {
		t.Fatal(err)
	}
	set = append(set, adoptArgs...)
	values, err := effectiveValues(ctx, chart, set)
	if err != nil {
		t.Fatal(err)
	}
	model, err := seedWorkloads(values, components)
	if err != nil {
		t.Fatal(err)
	}
	checkSeedModel(t, model, renderedSeed(t, chart, append([]string{"-f", file}, set...)), values)
	if err := checkAdoptedEntries(entries, values, components); err != nil {
		t.Fatalf("checkAdoptedEntries() = %v, want the adoption accepted", err)
	}
}

// checkSeedModel fails unless model holds exactly the rendered seed's entries
// that leave args open, less the chart's argv-pinned system images: the
// component entries, pinned to their entrypoint, and the operator's.
func checkSeedModel(t *testing.T, model map[string]pkgallowlist.Workload, rendered *pkgallowlist.Allowlist, values map[string]any) {
	t.Helper()
	pinned := argvPinnedDigests(values)
	var want []string
	for name, w := range rendered.Workloads {
		if !slices.ContainsFunc(append(slices.Clone(w.Containers), w.InitContainers...), func(c pkgallowlist.Container) bool {
			return c.Args.Policy != pkgallowlist.PolicyAny || slices.Contains(pinned, c.Digest.String())
		}) {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	if got := slices.Sorted(maps.Keys(model)); !slices.Equal(got, want) {
		t.Fatalf("seedWorkloads() entries = %v, want the chart's any-argv entries %v", got, want)
	}
	for _, name := range want {
		if got, want := normalized(t, model[name]), normalized(t, rendered.Workloads[name]); got != want {
			t.Errorf("seedWorkloads()[%s] = %s, want %s", name, got, want)
		}
	}
}

// renderedSeed is the allowlist seed the chart renders with set.
func renderedSeed(t *testing.T, chart string, set []string) *pkgallowlist.Allowlist {
	t.Helper()
	args := append([]string{"template", "c8s", chart, "--skip-tests", "--kube-version", "v1.34.5"}, set...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(nodeImageDocuments(t, out)["ConfigMap/c8s-cds-allowlist-seed"], &cm); err != nil {
		t.Fatal(err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

// normalized is w as CDS stores it.
func normalized(t *testing.T, w pkgallowlist.Workload) string {
	t.Helper()
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkgallowlist.ParseWorkloadJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
