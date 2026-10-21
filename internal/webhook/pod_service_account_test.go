package webhook

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestInjectionKeepsServiceAccountTokensOnWorkloadContainers(t *testing.T) {
	for name, automount := range map[string]*bool{
		"default":  nil,
		"enabled":  new(true),
		"disabled": new(false),
	} {
		t.Run(name, func(t *testing.T) {
			pod := podAfterServiceAccountAdmission()
			pod.Spec.AutomountServiceAccountToken = automount
			m, v := meshHandlers(t, meshConfig())
			injected := admit(t, m, pod, "tenant")

			if injected.Spec.AutomountServiceAccountToken == nil || *injected.Spec.AutomountServiceAccountToken {
				t.Error("injection permits ServiceAccount admission to mount tokens into platform containers")
			}
			if !reflect.DeepEqual(injected.Spec.Containers[0].VolumeMounts, pod.Spec.Containers[0].VolumeMounts) {
				t.Error("injection changed the application's service-account token mount")
			}
			if !reflect.DeepEqual(containerNamed(injected, "helper").VolumeMounts, pod.Spec.InitContainers[0].VolumeMounts) {
				t.Error("injection changed the native init container's service-account token mount")
			}
			if !reflect.DeepEqual(findVolume(injected, "kube-api-access-test"), &pod.Spec.Volumes[0]) {
				t.Error("injection changed the projected service-account token volume")
			}
			for _, c := range injected.Spec.InitContainers {
				if !workloadclaims.IsInjectedContainerName(c.Name) {
					continue
				}
				if mountNamed(&c, "kube-api-access-test") != nil {
					t.Errorf("injected container %s mounts the service-account token", c.Name)
				}
			}
			if response := validate(t, v, injected, "tenant"); !response.Allowed {
				t.Fatalf("validator refused the injected pod with workload service-account tokens: %+v", response.Result)
			}
		})
	}
}

func podAfterServiceAccountAdmission() *corev1.Pod {
	pod := podWithApp()
	pod.Spec.ServiceAccountName = "default"
	pod.Spec.Volumes = []corev1.Volume{
		{
			Name: "kube-api-access-test",
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: new(int32(420)),
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Path:              "token",
								ExpirationSeconds: new(int64(3607)),
							},
						},
					},
				},
			},
		},
	}
	mounts := []corev1.VolumeMount{
		{
			Name:      "kube-api-access-test",
			MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
			ReadOnly:  true,
		},
	}
	pod.Spec.Containers[0].VolumeMounts = mounts
	pod.Spec.InitContainers = []corev1.Container{
		{
			Name:          "helper",
			RestartPolicy: new(corev1.ContainerRestartPolicyAlways),
			VolumeMounts:  mounts,
		},
	}
	return pod
}
