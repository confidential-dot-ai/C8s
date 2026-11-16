package webhook

import (
	"maps"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// A confidential node's labels, as the chart passes them to the operator.
const (
	confidentialNodeLabel = "c8s.test/confidential"
	confidentialNodeValue = "true"
)

// confidentialNodeConfig is the operator's configuration on a cloud release,
// whose platform marks a confidential node with a label.
func confidentialNodeConfig() Config {
	cfg := meshConfig()
	cfg.ConfidentialNodeSelector = map[string]string{confidentialNodeLabel: confidentialNodeValue}
	return cfg
}

// An injected pod selects a confidential node and keeps the placement it
// declared itself.
func TestInjectedPodSelectsAConfidentialNode(t *testing.T) {
	zone := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
			MatchExpressions: []corev1.NodeSelectorRequirement{{
				Key:      "topology.kubernetes.io/zone",
				Operator: corev1.NodeSelectorOpIn,
				Values:   []string{"zone-a"},
			}},
		}}},
	}}
	tests := map[string]struct {
		declared map[string]string
		want     map[string]string
	}{
		"no selector of its own": {
			want: map[string]string{confidentialNodeLabel: confidentialNodeValue},
		},
		"its own node pinned": {
			declared: map[string]string{"kubernetes.io/hostname": "node-a"},
			want:     map[string]string{"kubernetes.io/hostname": "node-a", confidentialNodeLabel: confidentialNodeValue},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			m, _ := meshHandlers(t, confidentialNodeConfig())
			pod := podWithApp()
			pod.Spec.NodeSelector = tc.declared
			pod.Spec.Affinity = zone

			mutated := admit(t, m, pod, "tenant")

			if !maps.Equal(mutated.Spec.NodeSelector, tc.want) {
				t.Errorf("nodeSelector = %v, want %v", mutated.Spec.NodeSelector, tc.want)
			}
			if !reflect.DeepEqual(mutated.Spec.Affinity, zone) {
				t.Errorf("affinity = %+v, want the pod's own %+v", mutated.Spec.Affinity, zone)
			}
		})
	}
}

// A release that marks no confidential node leaves placement to the pod: on
// the measured image every node is a CVM.
func TestInjectedPodKeepsItsPlacementWithoutConfidentialNodeLabels(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())

	mutated := admit(t, m, podWithApp(), "tenant")

	if mutated.Spec.NodeSelector != nil {
		t.Errorf("nodeSelector = %v, want the pod's own, which is none", mutated.Spec.NodeSelector)
	}
}

// Both webhooks refuse a pod that selects a confidential-node label under
// another value, so the injector replaces no value a pod chose.
func TestWebhooksRefuseAContradictingNodeSelector(t *testing.T) {
	m, v := meshHandlers(t, confidentialNodeConfig())
	pod := podWithApp()
	pod.Spec.NodeSelector = map[string]string{confidentialNodeLabel: "false"}

	resp := mutationResponse(t, m, pod)
	if resp.Allowed {
		t.Fatal("the mutator admitted a pod selecting a plain node")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, confidentialNodeLabel) {
		t.Fatalf("denial = %+v, want it to name the label", resp.Result)
	}
	denies(t, v, pod, confidentialNodeLabel)
}

// An injected pod whose confidential-node labels are gone is refused: the
// scheduler would place it on a node running no C8s agent.
func TestValidatorRefusesAnInjectedPodOffTheConfidentialNodes(t *testing.T) {
	m, v := meshHandlers(t, confidentialNodeConfig())
	injected := admit(t, m, podWithApp(), "tenant")

	delete(injected.Spec.NodeSelector, confidentialNodeLabel)

	denies(t, v, injected, confidentialNodeLabel)
}
