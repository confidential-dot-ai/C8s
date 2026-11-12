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

// chartCDSValues point a rendered release at a placeholder CDS outside the
// cluster: the chart refuses a release that names none.
func chartCDSValues() map[string]any {
	pin := `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + strings.Repeat("ab", 48) + `","launch_file":"clusterID: test\n"}]}`
	return map[string]any{"cds": map[string]any{"address": "10.9.9.9:8443", "measurementsConfig": pin}}
}

// TestSeedWorkloadsMatchesTheChart: the seed install checks adoptions
// against is the one the chart renders, less its entries that pin args, and in
// that seed the entry install writes names the adopted pod alone.
func TestSeedWorkloadsMatchesTheChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	resetCLIState(t)
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	chart := filepath.Join(dir, helmchart.CloudChartFSPath)
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
	adoptValues, entries, err := buildWorkloadImageValues([]adoptedWorkload{{
		workloadAdoption: workloadAdoption{cwID: "web", ref: workloadRef{kind: "deployment", name: "web", namespace: "ws"}},
		template:         tmpl,
	}}, "", io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}

	computed := map[string]any{
		"nriImagePolicy": map[string]any{"mesh": map[string]any{
			"resolver":      "10.43.0.10",
			"clusterRanges": []any{"10.42.0.0/16"},
		}},
	}
	for i, c := range components {
		helmchart.MergeValues(computed, valuesAtPath(c.valuesPath+".digest", fmt.Sprintf("sha256:%064x", i+1)))
	}
	helmchart.MergeValues(computed, chartCDSValues())
	helmchart.MergeValues(computed, adoptValues)
	valuesFiles := append(orderedValuesFiles(chart, "aks-snp", nil), computedValuesFile(t, computed))
	values, err := effectiveValues(ctx, chart, valuesFiles)
	if err != nil {
		t.Fatal(err)
	}
	model, err := seedWorkloads(values)
	if err != nil {
		t.Fatal(err)
	}
	rendered := renderedSeed(t, chart, "-f", valuesFiles[0], "-f", valuesFiles[1])
	checkSeedModel(t, model, rendered)
	if name, _, err := rendered.MatchWorkload(entries["web"].pod); err != nil || name != "web" {
		t.Fatalf("rendered seed matches the adopted pod as %q, %v, want web", name, err)
	}
	if err := checkAdoptedEntries(entries, values); err != nil {
		t.Fatalf("checkAdoptedEntries() = %v", err)
	}
}

// checkSeedModel fails unless model holds exactly the rendered seed's entries
// that leave command and args open: the operator's. The chart's platform
// entries pin their command lines.
func checkSeedModel(t *testing.T, model map[string]pkgallowlist.Workload, rendered *pkgallowlist.Allowlist) {
	t.Helper()
	var want []string
	for name, w := range rendered.Workloads {
		if !slices.ContainsFunc(append(slices.Clone(w.Containers), w.InitContainers...), func(c pkgallowlist.Container) bool {
			return c.Command.Policy != pkgallowlist.PolicyAny || c.Args.Policy != pkgallowlist.PolicyAny
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
func renderedSeed(t *testing.T, chart string, set ...string) *pkgallowlist.Allowlist {
	t.Helper()
	args := append([]string{"template", "c8s", chart, "--skip-tests", "--kube-version", "v1.34.5", "--namespace", "c8s-system"}, set...)
	out := helmRenderOnly(t, args...)
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(nodeImageDocuments(t, out)["c8s-system/ConfigMap/c8s-allowlist-seed"], &cm); err != nil {
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
