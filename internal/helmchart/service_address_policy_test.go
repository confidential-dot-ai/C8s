package helmchart

import "testing"

const serviceAddressPolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/service-address-policy.yaml"

// Member pods' packet filters let the resolver and the kube-state-metrics
// exit through by address, so no Service outside kube-system may take an
// address of the platform's static band, whoever writes it: a ServiceAccount
// the operator creates is no c8s:* principal.
func TestServiceAddressPolicy(t *testing.T) {
	t.Parallel()
	vap, binding := loadImagePolicy(t, serviceAddressPolicyPath, "confos-service-address")
	checkDenyPolicyShape(t, vap, binding)
	op := []string{"system:authenticated", "c8s:node-operators"}
	sa := []string{"system:serviceaccounts", "system:serviceaccounts:tenant", "system:authenticated"}
	masters := []string{"system:authenticated", "system:masters"}
	svc := func(spec map[string]any) map[string]any { return map[string]any{"spec": spec} }
	exit := svc(map[string]any{"clusterIP": "10.53.0.11", "clusterIPs": []any{"10.53.0.11"}})
	for _, tc := range []struct {
		name      string
		groups    []string
		namespace string
		object    map[string]any
		want      bool
	}{
		{"allocated ClusterIP", sa, "tenant", svc(map[string]any{"clusterIP": "10.53.143.7", "clusterIPs": []any{"10.53.143.7"}}), true},
		{"headless", sa, "tenant", svc(map[string]any{"clusterIP": "None", "clusterIPs": []any{"None"}}), true},
		{"no spec", sa, "tenant", map[string]any{}, true},
		{"server-side dry-run placeholder", sa, "tenant", svc(map[string]any{"clusterIP": "10.53.0.0", "clusterIPs": []any{"10.53.0.0"}}), true},
		{"ServiceAccount takes the exit", sa, "tenant", exit, false},
		{"ServiceAccount takes another band address", sa, "tenant", svc(map[string]any{"clusterIP": "10.53.0.12"}), false},
		{"band address in clusterIPs only", sa, "tenant", svc(map[string]any{"clusterIPs": []any{"10.53.0.12"}}), false},
		{"operator takes the resolver", op, "tenant", svc(map[string]any{"clusterIP": "10.53.0.10"}), false},
		{"operator takes the kubernetes address in default", op, "default", svc(map[string]any{"clusterIP": "10.53.0.1"}), false},
		{"no groups field at all", nil, "tenant", exit, false},
		{"kube-system keeps the band", sa, "kube-system", exit, true},
		{"system:masters keeps the band", masters, "default", svc(map[string]any{"clusterIP": "10.53.0.1"}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scopeRequest{tc.groups, tc.namespace, "", "services", ""}
			if got := evalOperatorScopeObject(t, vap, r, tc.object); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}
