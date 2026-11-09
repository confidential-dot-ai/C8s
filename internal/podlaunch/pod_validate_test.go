package podlaunch

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func testParsedPod(t *testing.T, spec string) *corev1.Pod {
	t.Helper()
	pod, err := ParsePodManifest([]byte(testPodManifest(spec)))
	if err != nil {
		t.Fatal(err)
	}
	return pod
}

func TestParsePodManifestRefusesAPodWithoutContainers(t *testing.T) {
	t.Parallel()
	_, err := ParsePodManifest([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app"},"spec":{}}`))
	if err == nil || !strings.Contains(err.Error(), "no containers") {
		t.Fatalf("got %v", err)
	}
	if _, err := (&PodSpec{Manifest: "kind: Pod"}).IngressPorts(); err == nil || !strings.Contains(err.Error(), "v1 Pod") {
		t.Fatalf("ingress ports of an invalid manifest: %v", err)
	}
}

func TestValidatePodSpecRefusesUnresolvableContainers(t *testing.T) {
	t.Parallel()
	if err := ValidatePodSpec(nil); err == nil || !strings.Contains(err.Error(), "must have containers") {
		t.Fatalf("nil pod: %v", err)
	}
	tests := []struct {
		name   string
		change func(*corev1.Container)
		want   string
	}{
		{"unparsable image", func(c *corev1.Container) { c.Image = "Bad Image" }, "image"},
		{"envFrom", func(c *corev1.Container) {
			c.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{}}}
		}, "envFrom"},
		{"secret env", func(c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "K", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}}}
		}, "Secret or ConfigMap"},
		{"configmap env", func(c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "K", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "k"}}}}
		}, "Secret or ConfigMap"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := testParsedPod(t, "")
			tc.change(&pod.Spec.Containers[0])
			if err := ValidatePodSpec(pod); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
