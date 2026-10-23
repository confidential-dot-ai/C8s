package webhook

import (
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// TestAdoptMeInjection: once adopted, the kind harness's workload mounts no
// credential files; the memory-backed cert volume reaches the platform
// containers alone. c8s install writes its allowlist entry from that model
// (test/integration/cluster/testdata).
func TestAdoptMeInjection(t *testing.T) {
	data, err := os.ReadFile("../../test/integration/cluster/manifests/adopt-me.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	for _, doc := range strings.Split(string(data), "\n---\n") {
		if strings.Contains(doc, "kind: Deployment") {
			if err := yaml.Unmarshal([]byte(doc), &deployment); err != nil {
				t.Fatal(err)
			}
		}
	}
	pod := &corev1.Pod{ObjectMeta: deployment.Spec.Template.ObjectMeta, Spec: deployment.Spec.Template.Spec}
	// What install stamps, and what the harness adds once it has.
	pod.Annotations = map[string]string{
		AnnotationWorkload: "web",
	}
	inj, err := parseAnnotations(pod, "default")
	if err != nil || inj == nil {
		t.Fatalf("parseAnnotations(adopt-me) = %+v, %v", inj, err)
	}
	mutatePod(pod, inj, Config{})

	app := pod.Spec.Containers[0]
	if len(app.VolumeMounts) != 0 {
		t.Fatalf("injected app mounts = %+v, want none", app.VolumeMounts)
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == CertVolumeName && (v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory) {
			t.Fatalf("cert volume = %+v, want a memory-backed emptyDir", v)
		}
	}
}
