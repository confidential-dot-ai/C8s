package webhook

import (
	"errors"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestReservedVolumeValidationBoundaries(t *testing.T) {
	for _, guard := range []struct {
		name      string
		volume    string
		check     func(*corev1.Pod) error
		wantError string
	}{
		{
			name:   "certificates",
			volume: "custom-certs",
			check: func(pod *corev1.Pod) error {
				return rejectReservedCertVolume(pod, "custom-certs")
			},
			wantError: "invalid c8s injection annotation: volume %q is reserved for the injected in-memory cert store; it must be a memory-backed emptyDir (medium: Memory) or omitted",
		},
		{
			name:      "secrets",
			volume:    secretsVolumeName,
			check:     rejectReservedSecretsVolume,
			wantError: "invalid c8s injection annotation: volume %q is reserved for released secrets; it must be a memory-backed emptyDir (medium: Memory) or omitted",
		},
	} {
		t.Run(guard.name, func(t *testing.T) {
			memory := corev1.Volume{
				Name:     guard.volume,
				EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
			}
			disk := corev1.Volume{
				Name:     guard.volume,
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			}
			for _, tc := range []struct {
				name    string
				volumes []corev1.Volume
				refused bool
			}{
				{
					name: "omitted",
				},
				{
					name: "unrelated disk volume",
					volumes: []corev1.Volume{{
						Name:     "unrelated",
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					}},
				},
				{
					name:    "missing source",
					volumes: []corev1.Volume{{Name: guard.volume}},
					refused: true,
				},
				{
					name:    "memory followed by disk",
					volumes: []corev1.Volume{memory, disk},
					refused: true,
				},
				{
					name:    "disk followed by memory",
					volumes: []corev1.Volume{disk, memory},
					refused: true,
				},
				{
					name:    "both memory",
					volumes: []corev1.Volume{memory, memory},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					pod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: tc.volumes}}
					err := guard.check(pod)
					if !tc.refused {
						if err != nil {
							t.Fatalf("volume rejected: %v", err)
						}
						return
					}
					if !errors.Is(err, errInvalidInjectionAnnotation) {
						t.Fatalf("error = %v, want invalid injection annotation", err)
					}
					if want := fmt.Sprintf(guard.wantError, guard.volume); err.Error() != want {
						t.Fatalf("error = %q, want %q", err, want)
					}
				})
			}
		})
	}
}

func TestReservedVolumeRefusalPrecedence(t *testing.T) {
	pod := podWithApp()
	pod.Spec.Volumes = []corev1.Volume{
		{Name: secretsVolumeName},
		{Name: CertVolumeName},
	}
	err := rejectReservedResources(pod, &injection{}, Config{})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("error = %v, want invalid injection annotation", err)
	}
	want := fmt.Sprintf("invalid c8s injection annotation: volume %q is reserved for the injected in-memory cert store; it must be a memory-backed emptyDir (medium: Memory) or omitted", CertVolumeName)
	if err.Error() != want {
		t.Fatalf("error = %q, want certificate volume refusal %q", err, want)
	}
}
