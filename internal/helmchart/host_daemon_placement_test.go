package helmchart

import (
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
			want: []string{"c8s-attestation-api", "c8s-nri-image-policy-worker"},
		},
		{
			name: "all host daemons and provider enabled",
			args: []string{"--set", "volumed.enabled=true", "--set", "operator.podCVMProvider.enabled=true", "--set", "operator.podCVMProvider.existingSecret=provider-config"},
			want: []string{"c8s-attestation-api", "c8s-nri-image-policy-worker", "c8s-volumed"},
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
				t.Fatalf("rendered DaemonSets = %v, want %v", names, tc.want)
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
