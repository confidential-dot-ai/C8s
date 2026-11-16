package webhook

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
)

func TestReleaseContainerDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		endpoint     string
		discovery    discoverySpec
		wantEndpoint string
		wantMounts   []corev1.VolumeMount
	}{
		{
			name:         "HTTP without discovery",
			endpoint:     "http://$(HOST_IP):8400",
			wantEndpoint: "http://$(HOST_IP):8400",
			wantMounts: []corev1.VolumeMount{
				{Name: "c8s-certs", MountPath: "/etc/c8s/certs"},
			},
		},
		{
			name:     "rebased socket with discovery",
			endpoint: "unix:///run/nri-image-policy/attestation-api.sock",
			discovery: discoverySpec{
				Volume:    "discovery",
				MountPath: "/run/c8s/discovery",
			},
			wantEndpoint: "unix:///run/c8s/workload-claims/attestation-api.sock",
			wantMounts: []corev1.VolumeMount{
				{Name: "c8s-certs", MountPath: "/etc/c8s/certs"},
				{Name: "discovery", MountPath: "/run/c8s/discovery"},
			},
		},
		{
			name:         "discovery volume without mount path",
			endpoint:     "http://$(HOST_IP):8400",
			discovery:    discoverySpec{Volume: "discovery"},
			wantEndpoint: "http://$(HOST_IP):8400",
			wantMounts: []corev1.VolumeMount{
				{Name: "c8s-certs", MountPath: "/etc/c8s/certs"},
			},
		},
		{
			name:         "discovery mount path without volume",
			endpoint:     "http://$(HOST_IP):8400",
			discovery:    discoverySpec{MountPath: "/run/c8s/discovery"},
			wantEndpoint: "http://$(HOST_IP):8400",
			wantMounts: []corev1.VolumeMount{
				{Name: "c8s-certs", MountPath: "/etc/c8s/certs"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inj := &injection{
				WorkloadID: "api",
				Discovery:  tc.discovery,
				Secrets: secretsSpec{
					Specs: []string{"DB=/api/db", "TOKEN=/api/token"},
					Dir:   "/run/fixture-secrets",
				},
				Volumes: volumesSpec{
					Specs: []string{"weights=/api/weights", "cache=/api/cache"},
				},
			}
			cfg := Config{
				GetCertImage:          "registry.test/c8s:sidecars",
				AttestationApiURL:     tc.endpoint,
				WorkloadClaimsHostDir: "/run/nri-image-policy",
			}
			wantCommon := corev1.Container{
				VolumeMounts:    tc.wantMounts,
				Image:           "registry.test/c8s:sidecars",
				ImagePullPolicy: corev1.PullIfNotPresent,
				RestartPolicy:   new(corev1.ContainerRestartPolicyAlways),
				Env: []corev1.EnvVar{
					{Name: "C8S_WORKLOAD_ID", Value: "api"},
					{
						Name: "C8S_POD_NAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.name"},
						},
					},
					{
						Name: "C8S_POD_UID",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"},
						},
					},
					{
						Name: "HOST_IP",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "status.hostIP"},
						},
					},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: new(false),
					ReadOnlyRootFilesystem:   new(true),
					RunAsNonRoot:             new(true),
					RunAsUser:                new(int64(1338)),
					RunAsGroup:               new(int64(1338)),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
			}
			wantVolume := *wantCommon.DeepCopy()
			wantVolume.Name = "c8s-volume"
			wantVolume.Args = []string{
				"get-volume",
				"--attestation-api-url=" + tc.wantEndpoint,
				"--cert=/etc/c8s/certs/tls.crt",
				"--key=/etc/c8s/certs/tls.key",
				"--volume=weights=/api/weights",
				"--volume=cache=/api/cache",
			}
			wantSecret := *wantCommon.DeepCopy()
			wantSecret.Name = "c8s-secret"
			wantSecret.Args = []string{
				"get-secret",
				"--attestation-api-url=" + tc.wantEndpoint,
				"--cert=/etc/c8s/certs/tls.crt",
				"--key=/etc/c8s/certs/tls.key",
				"--out-dir=/run/fixture-secrets",
				"--secret=DB=/api/db",
				"--secret=TOKEN=/api/token",
			}
			wantSecret.VolumeMounts = append(wantSecret.VolumeMounts, corev1.VolumeMount{
				Name:      "c8s-secrets",
				MountPath: "/run/fixture-secrets",
			})
			if diff := cmp.Diff(wantVolume, volumeContainer(inj, cfg)); diff != "" {
				t.Errorf("volume container (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(wantSecret, secretContainer(inj, cfg)); diff != "" {
				t.Errorf("secret container (-want +got):\n%s", diff)
			}
		})
	}
}
