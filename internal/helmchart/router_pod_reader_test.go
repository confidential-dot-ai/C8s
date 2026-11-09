package helmchart

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
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

func TestRouterPodReaderOnlyRuleIsPodsListWatch(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	var role rbacv1.ClusterRole
	if !findDoc(t, out, "ClusterRole", "c8s-router", &role) {
		t.Fatal("chart renders no ClusterRole c8s-router")
	}
	want := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "watch"}}}
	if !reflect.DeepEqual(role.Rules, want) {
		t.Errorf("c8s-router ClusterRole rules = %+v, want %+v", role.Rules, want)
	}
}
