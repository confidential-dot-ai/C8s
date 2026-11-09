package webhook

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// The mutator meets the privilege floor for the author's containers, init and
// regular, and leaves what the author already stated.
func TestMutatePodDefaultsThePrivilegeFloor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		given    *corev1.SecurityContext
		wantDrop []corev1.Capability
		wantAdd  []corev1.Capability
	}{
		{
			name:     "nothing set",
			wantDrop: []corev1.Capability{"NET_RAW", "SETGID", "SETUID"},
		},
		{
			name:     "drops every capability",
			given:    &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			wantDrop: []corev1.Capability{"ALL"},
		},
		{
			name: "drops one of them, escalation already refused",
			given: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}},
			},
			wantDrop: []corev1.Capability{"NET_RAW", "SETGID", "SETUID"},
		},
		{
			name:     "adds a declarable capability",
			given:    &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}}},
			wantDrop: []corev1.Capability{"NET_RAW", "SETGID", "SETUID"},
			wantAdd:  []corev1.Capability{"NET_BIND_SERVICE"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Spec.Containers[0].SecurityContext = tc.given.DeepCopy()
			pod.Spec.InitContainers = []corev1.Container{
				{
					Name:            "migrate",
					SecurityContext: tc.given.DeepCopy(),
				},
			}

			mutatePod(pod, &injection{WorkloadID: "api"}, meshConfig())

			for _, name := range []string{"app", "migrate"} {
				sc := appContainerNamed(t, pod, name).SecurityContext
				if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
					t.Errorf("container %q allowPrivilegeEscalation = %v, want false", name, sc.AllowPrivilegeEscalation)
				}
				if !slices.Equal(sc.Capabilities.Drop, tc.wantDrop) {
					t.Errorf("container %q capabilities.drop = %v, want %v", name, sc.Capabilities.Drop, tc.wantDrop)
				}
				if !slices.Equal(sc.Capabilities.Add, tc.wantAdd) {
					t.Errorf("container %q capabilities.add = %v, want %v", name, sc.Capabilities.Add, tc.wantAdd)
				}
			}
		})
	}
}
