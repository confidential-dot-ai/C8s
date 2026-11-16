//go:build !c8s_node

package main

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

func TestInjectedMountRulesPreservesContainerMounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		volume  corev1.Volume
		mounts  []corev1.VolumeMount
		want    []string
		wantErr bool
	}{
		{
			name: "mountless application",
		},
		{
			name: "memory scratch",
			volume: corev1.Volume{
				Name: "scratch",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
				},
			},
			mounts: []corev1.VolumeMount{
				{Name: "scratch", MountPath: "/scratch"},
			},
			want: []string{"/scratch"},
		},
		{
			name: "expected credential mount",
			mounts: []corev1.VolumeMount{
				{Name: webhook.CertVolumeName, MountPath: webhook.CertDir},
			},
			want: []string{webhook.CertDir},
		},
		{
			name: "host-backed credential volume",
			volume: corev1.Volume{
				Name: webhook.CertVolumeName,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/host/certs"},
				},
			},
			mounts: []corev1.VolumeMount{
				{Name: webhook.CertVolumeName, MountPath: webhook.CertDir},
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := corev1.PodTemplateSpec{}
			if tc.volume.Name != "" {
				template.Spec.Volumes = []corev1.Volume{tc.volume}
			}
			got, err := injectedMountRules(template, corev1.Container{
				Name:         "app",
				VolumeMounts: tc.mounts,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("injectedMountRules() error=%v, want error=%v", err, tc.wantErr)
			}
			if !tc.wantErr && !slices.Equal(got, tc.want) {
				t.Fatalf("injectedMountRules()=%v, want %v", got, tc.want)
			}
		})
	}
}
