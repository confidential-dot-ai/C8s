package helmchart

import (
	"slices"
	"strings"
	"testing"
)

// The router reads pods under its own ServiceAccount, so the chart renders
// that ServiceAccount beside it: a Deployment naming a missing one creates no
// pod.
func TestRouterServiceAccountRendered(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	keys := renderedObjectKeys(t, out)
	for _, w := range renderedPodSpecs(t, out) {
		if w.kind != "Deployment" || !strings.HasSuffix(w.name, "-router") {
			continue
		}
		sa := w.spec.ServiceAccountName
		if sa == "" {
			t.Fatalf("%s runs under the namespace's default ServiceAccount", w.name)
		}
		for _, want := range []string{"ServiceAccount/c8s-router/" + sa, "ClusterRoleBinding//" + sa} {
			if !slices.Contains(keys, want) {
				t.Errorf("%s names ServiceAccount %s, but the chart renders no %s", w.name, sa, want)
			}
		}
		return
	}
	t.Fatal("chart rendered no router Deployment")
}
