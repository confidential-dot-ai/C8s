package helmchart

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

var hostDaemonVirtualNodeExclusion = corev1.NodeSelectorRequirement{
	Key: "confidential.ai/pod-cvm", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"},
}

func TestChartHostDaemonsExcludeVirtualNodes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "defaults with provider disabled",
			want: []string{"c8s-attestation-api", "c8s-nri-image-policy-uninstall", "c8s-nri-image-policy-worker"},
		},
		{
			name: "all host daemons and provider enabled",
			args: []string{"--set", "volumed.enabled=true", "--set", "operator.podCVMProvider.enabled=true", "--set", "operator.podCVMProvider.existingSecret=provider-config"},
			want: []string{"c8s-attestation-api", "c8s-nri-image-policy-uninstall", "c8s-nri-image-policy-worker", "c8s-volumed", "c8s-volumed-teardown"},
		},
		{
			name: "baked plugin pins installer",
			args: []string{"--set", "nriImagePolicy.baked=true", "--set", "attestationApi.enabled=false"},
			want: []string{"c8s-nri-image-policy-worker"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var names []string
			iterateManifests(t, out, func(doc []byte) bool {
				var ds appsv1.DaemonSet
				if err := sigsyaml.Unmarshal(doc, &ds); err != nil {
					t.Fatal(err)
				}
				if ds.Kind != "DaemonSet" {
					return false
				}
				names = append(names, ds.Name)
				assertHostDaemonExcludesVirtualNodes(t, ds)
				return false
			})
			slices.Sort(names)
			if !slices.Equal(names, tc.want) {
				t.Fatalf("rendered DaemonSets = %v, want %v (including uninstall hooks)", names, tc.want)
			}
		})
	}
}

func assertHostDaemonExcludesVirtualNodes(t *testing.T, ds appsv1.DaemonSet) {
	t.Helper()
	affinity := ds.Spec.Template.Spec.Affinity
	if affinity == nil || affinity.NodeAffinity == nil || affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		t.Fatalf("DaemonSet %s has no required host-node affinity", ds.Name)
	}
	terms := affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 {
		t.Fatalf("DaemonSet %s cannot schedule on any host", ds.Name)
	}
	for i, term := range terms {
		if !slices.ContainsFunc(term.MatchExpressions, func(requirement corev1.NodeSelectorRequirement) bool {
			return reflect.DeepEqual(requirement, hostDaemonVirtualNodeExclusion)
		}) {
			t.Errorf("DaemonSet %s OR term %d can select a virtual node: %+v", ds.Name, i, term)
		}
	}
}

func TestChartHostDaemonsPreserveNodeConstraints(t *testing.T) {
	t.Parallel()
	values := `volumed:
  enabled: true
  nodeSelector:
    storage.example/attached: "true"
nriImagePolicy:
  nodeAffinity:
    excludeLabels:
      - key: node.example/pool
        values: [edge, drained]
      - key: confidential.ai/pod-cvm
        values: [custom-exclusion]
`
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "-f", path)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	wantExpressions := []corev1.NodeSelectorRequirement{
		{Key: "kubernetes.io/os", Operator: corev1.NodeSelectorOpIn, Values: []string{"linux"}},
		{Key: "node.example/pool", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"edge", "drained"}},
		{Key: "confidential.ai/pod-cvm", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"custom-exclusion"}},
		hostDaemonVirtualNodeExclusion,
	}
	for _, name := range []string{"c8s-nri-image-policy-worker", "c8s-nri-image-policy-uninstall"} {
		ds := renderedDaemonSet(t, out, name)
		assertHostDaemonExcludesVirtualNodes(t, ds)
		terms := ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 1 || !reflect.DeepEqual(terms[0].MatchExpressions, wantExpressions) {
			t.Errorf("%s changed configured host constraints: %+v", name, terms)
		}
	}
	for _, name := range []string{"c8s-volumed", "c8s-volumed-teardown"} {
		ds := renderedDaemonSet(t, out, name)
		assertHostDaemonExcludesVirtualNodes(t, ds)
		want := map[string]string{"kubernetes.io/os": "linux", "storage.example/attached": "true"}
		if !reflect.DeepEqual(ds.Spec.Template.Spec.NodeSelector, want) {
			t.Errorf("%s node selector = %v, want %v", name, ds.Spec.Template.Spec.NodeSelector, want)
		}
	}
}

func TestHostDaemonAffinityPreservesAlternativesAndInput(t *testing.T) {
	t.Parallel()
	template, err := os.ReadFile("c8s/templates/_helpers.tpl")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: host-affinity\nversion: 0.0.1\n",
		"templates/_helpers.tpl": string(template),
		"templates/affinity.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: host-affinity
data:
  before: |
    {{- toYaml .Values.affinity | nindent 4 }}
  result: |
    {{- include "c8s.hostDaemonAffinity" .Values.affinity | nindent 4 }}
  repeated: |
    {{- include "c8s.hostDaemonAffinity" .Values.affinity | nindent 4 }}
  after: |
    {{- toYaml .Values.affinity | nindent 4 }}
`,
	} {
		path := filepath.Join(dir, "c8s", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ name, input string }{
		{"absent", `{}`},
		{"null required selector", `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":null}}`},
		{"empty required selector", `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{}}}`},
		{"empty alternatives", `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[]}}}`},
		{"empty term", `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{}]}}}`},
		{"preferred only", `{"nodeAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":50,"preference":{"matchExpressions":[{"key":"disk","operator":"In","values":["ssd"]}]}}]}}`},
		{"multiple terms and pod affinity", `{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"zone","operator":"In","values":["a"]}]},{"matchFields":[{"key":"metadata.name","operator":"In","values":["worker-b"]}]},{}]},"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":50,"preference":{"matchExpressions":[{"key":"disk","operator":"In","values":["ssd"]}]}}]},"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"topologyKey":"zone","labelSelector":{"matchLabels":{"app":"peer"}}}]},"podAntiAffinity":{"preferredDuringSchedulingIgnoredDuringExecution":[{"weight":10,"podAffinityTerm":{"topologyKey":"zone","labelSelector":{"matchLabels":{"app":"other"}}}}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateIn(t, dir, "--set-json", "affinity="+tc.input)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var result corev1.ConfigMap
			if !findDoc(t, out, "ConfigMap", "host-affinity", &result) {
				t.Fatal("missing helper result")
			}
			if result.Data["before"] != result.Data["after"] || result.Data["result"] != result.Data["repeated"] {
				t.Fatal("helper mutated shared affinity input")
			}
			var original, actual corev1.Affinity
			if err := sigsyaml.Unmarshal([]byte(result.Data["before"]), &original); err != nil {
				t.Fatal(err)
			}
			if err := sigsyaml.Unmarshal([]byte(result.Data["result"]), &actual); err != nil {
				t.Fatal(err)
			}
			if original.NodeAffinity == nil || original.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
				terms := actual.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
				want := []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{hostDaemonVirtualNodeExclusion}}}
				if !reflect.DeepEqual(terms, want) {
					t.Fatalf("unconstrained affinity = %+v, want %+v", terms, want)
				}
				actual.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = nil
				if original.NodeAffinity == nil {
					actual.NodeAffinity = nil
				}
			} else {
				oldTerms := original.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
				terms := actual.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
				if len(terms) != len(oldTerms) {
					t.Fatalf("OR alternatives changed from %d to %d", len(oldTerms), len(terms))
				}
				for i, term := range terms {
					if len(oldTerms[i].MatchExpressions) == 0 && len(oldTerms[i].MatchFields) == 0 {
						continue
					}
					n := len(term.MatchExpressions)
					if n == 0 || !reflect.DeepEqual(term.MatchExpressions[n-1], hostDaemonVirtualNodeExclusion) {
						t.Fatalf("OR alternative %d can select a virtual node: %+v", i, term)
					}
					terms[i].MatchExpressions = term.MatchExpressions[:n-1]
					if len(terms[i].MatchExpressions) == 0 {
						terms[i].MatchExpressions = nil
					}
				}
			}
			if !reflect.DeepEqual(actual, original) {
				t.Fatalf("helper changed existing affinity constraints:\ngot: %+v\nwant: %+v", actual, original)
			}
		})
	}
}
