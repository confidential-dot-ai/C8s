package helmchart

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// Kubelets from 1.35 can run liveness before the startup probe passes after a
// liveness restart (kubernetes/kubernetes#141155), so a liveness window shorter
// than the startup window restarts a container that is still starting.
func TestLivenessWindowCoversStartupWindow(t *testing.T) {
	t.Parallel()
	pods := map[string]corev1.PodSpec{}
	for chart, render := range map[string]func(*testing.T, ...string) (string, error){
		"cloud":  helmTemplate,
		"worker": helmTemplateWorker,
	} {
		out, err := render(t)
		if err != nil {
			t.Fatalf("helm template %s: %v\n%s", chart, err, out)
		}
		for _, w := range renderedPodSpecs(t, out) {
			pods[chart+" "+w.kind+"/"+w.name] = w.spec
		}
	}
	staticPods, err := filepath.Glob(filepath.Join(workerChart, "files", "static-pods", "*.yaml"))
	if err != nil || len(staticPods) == 0 {
		t.Fatalf("static pods: %v, %v", staticPods, err)
	}
	for _, file := range staticPods {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var pod corev1.Pod
		if err := sigsyaml.Unmarshal(data, &pod); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		pods["static pod "+filepath.Base(file)] = pod.Spec
	}

	for name, spec := range pods {
		for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
			if c.StartupProbe == nil || c.LivenessProbe == nil {
				continue
			}
			startup := probeWindow(c.StartupProbe)
			liveness := probeWindow(c.LivenessProbe) + c.LivenessProbe.InitialDelaySeconds
			if liveness < startup {
				t.Errorf("%s container %s: liveness window %ds < startup window %ds", name, c.Name, liveness, startup)
			}
		}
	}
}

// probeWindow is periodSeconds * failureThreshold, with the kubelet defaults.
func probeWindow(p *corev1.Probe) int32 {
	period, failures := p.PeriodSeconds, p.FailureThreshold
	if period == 0 {
		period = 10
	}
	if failures == 0 {
		failures = 3
	}
	return period * failures
}
