package helmchart

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCDSPodPolicyNeverChangesNodeTrust(t *testing.T) {
	t.Parallel()
	policy := writeChartImagePolicy(t, chartTDXPolicy(chartTDXImage("pod", chartDigestA, `[null,"`+chartDigestB+`"]`)))
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"disabled", "", nil},
		{"chart", "/mnt/c8s-data/pod-policy/pods.json", []string{"--set-file", "cds.podImagePolicy=" + policy}},
		{"baked", "/run/c8s-node/pods.json", bakedArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("render: %v\n%s", err, out)
			}
			found := false
			for _, workload := range renderedPodSpecs(t, out) {
				for _, c := range append(workload.spec.Containers, workload.spec.InitContainers...) {
					for _, arg := range c.Args {
						if !strings.HasPrefix(arg, "--pod-image-policy-file=") {
							continue
						}
						if workload.name != "c8s-cds" || tc.want == "" || arg != "--pod-image-policy-file="+tc.want {
							t.Fatalf("unexpected Pod authority for %s/%s: %s", workload.name, c.Name, arg)
						}
						found = true
						if slices.Contains(c.Args, "--image-policy-file="+tc.want) {
							t.Fatal("Pod policy granted node authority")
						}
						if tc.name == "chart" {
							idx := slices.IndexFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
								return m.Name == "pod-image-policy" && m.MountPath == "/mnt/c8s-data/pod-policy" && m.ReadOnly
							})
							if idx < 0 {
								t.Fatal("Pod policy is not mounted read-only")
							}
						}
					}
				}
			}
			if found != (tc.want != "") {
				t.Fatalf("Pod policy flag found=%v", found)
			}
		})
	}
}
