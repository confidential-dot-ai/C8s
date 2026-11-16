package webhook

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDiscoveryVolumeValidationBoundaries(t *testing.T) {
	disk := corev1.Volume{
		Name:     "discovery",
		EmptyDir: &corev1.EmptyDirVolumeSource{},
	}
	wrongKind := corev1.Volume{
		Name:   "discovery",
		Secret: &corev1.SecretVolumeSource{SecretName: "public-tls"},
	}
	const wrongKindError = "invalid c8s injection annotation: confidential.ai/c8s-discovery-volume \"discovery\" must be an emptyDir (medium: Memory unless the node has encrypted scratch): the get-cert sidecar's mount rules admit no other kind there, so the node would refuse it"
	for _, tc := range []struct {
		name      string
		requested string
		volumes   []corev1.Volume
		wantError string
	}{
		{
			name:    "unconfigured with invalid unnamed volume",
			volumes: []corev1.Volume{{}},
		},
		{
			name:      "requested volume absent",
			requested: "discovery",
			volumes:   []corev1.Volume{{Name: "unrelated"}},
			wantError: "invalid c8s injection annotation: confidential.ai/c8s-discovery-volume \"discovery\" names no volume of the pod",
		},
		{
			name:      "first match permits disk",
			requested: "discovery",
			volumes:   []corev1.Volume{disk, wrongKind},
		},
		{
			name:      "first match rejects secret",
			requested: "discovery",
			volumes:   []corev1.Volume{wrongKind, disk},
			wantError: wrongKindError,
		},
		{
			name:      "missing source",
			requested: "discovery",
			volumes:   []corev1.Volume{{Name: "discovery"}},
			wantError: wrongKindError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: tc.volumes}}
			inj := &injection{Discovery: discoverySpec{Volume: tc.requested}}
			err := rejectUnpinnableSidecarVolumes(pod, inj)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("volume rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, errInvalidInjectionAnnotation) {
				t.Fatalf("error = %v, want invalid injection annotation", err)
			}
			if err.Error() != tc.wantError {
				t.Fatalf("error = %q, want %q", err, tc.wantError)
			}
		})
	}
}
