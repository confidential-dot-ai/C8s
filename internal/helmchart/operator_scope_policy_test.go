package helmchart

import (
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// The node image binds cred-release credentials to a bounded ClusterRole and
// bakes this policy so that, whatever RBAC says, no c8s:* principal can write
// where a guard could be disabled or the host reached. Applied by RKE2, not
// the chart, so it is read from the image tree here like psa-level-policy.
const operatorScopePolicyPath = "../../images/node-guest/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/operator-scope-policy.yaml"

func TestOperatorScopePolicyShape(t *testing.T) {
	t.Parallel()
	vap, binding := loadImagePolicy(t, operatorScopePolicyPath, "confos-operator-scope")
	checkDenyPolicyShape(t, vap, binding)
	// The principal test is a match condition, so other callers leave before
	// any validation runs and a validation cannot forget it.
	var selectsCredRelease bool
	for _, mc := range vap.Spec.MatchConditions {
		selectsCredRelease = selectsCredRelease || strings.Contains(mc.Expression, "startsWith('c8s:')")
	}
	if !selectsCredRelease {
		t.Error("matchConditions must select the c8s:* principals")
	}
	for _, v := range vap.Spec.Validations {
		if strings.Contains(v.Expression, "userInfo") {
			t.Errorf("validation %q tests the principal itself; that is the match condition's job", v.Expression)
		}
	}
	// Every group, resource and subresource, on every mutating operation:
	// the validations, not the resource match, decide what a c8s:* principal
	// may do.
	// "*/*" is every resource and subresource; the API rejects it beside
	// any other entry.
	var all bool
	ops := map[admissionregv1.OperationType]bool{}
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		all = all || (len(r.Resources) == 1 && r.Resources[0] == "*/*")
		for _, op := range r.Operations {
			ops[op] = true
		}
	}
	if !all {
		t.Error(`matchConstraints must name exactly "*/*" so every resource and subresource is covered`)
	}
	for _, op := range []admissionregv1.OperationType{admissionregv1.Create, admissionregv1.Update, admissionregv1.Delete, admissionregv1.Connect} {
		if !ops[op] {
			t.Errorf("matchConstraints does not match %s", op)
		}
	}
}

// scopeRequest models the AdmissionRequest fields the policy reads.
type scopeRequest struct {
	groups    []string
	namespace string
	group     string
	resource  string
	sub       string
	operation string
	name      string
	oldObject map[string]any
}

// evalOperatorScope compiles every match condition, variable and validation
// and returns whether the request is admitted: a false match condition
// admits without evaluating anything else, as the apiserver does. Absent
// fields are left out of the map so has() sees exactly what the apiserver
// would present.
func evalOperatorScope(t *testing.T, vap admissionregv1.ValidatingAdmissionPolicy, r scopeRequest) bool {
	t.Helper()
	return evalOperatorScopeObject(t, vap, r, nil)
}

// evalOperatorScopeObject is evalOperatorScope with the admitted object; nil
// is the null object the apiserver presents on DELETE.
func evalOperatorScopeObject(t *testing.T, vap admissionregv1.ValidatingAdmissionPolicy, r scopeRequest, object map[string]any) bool {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("request", cel.DynType), cel.Variable("variables", cel.DynType), cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	userInfo := map[string]any{"username": "x"}
	if r.groups != nil {
		userInfo["groups"] = r.groups
	}
	req := map[string]any{
		"userInfo": userInfo,
		"resource": map[string]any{"group": r.group, "version": "v1", "resource": r.resource},
	}
	if r.operation != "" {
		req["operation"] = r.operation
	}
	req["name"] = r.name
	if r.namespace != "" {
		req["namespace"] = r.namespace
	}
	if r.sub != "" {
		req["subResource"] = r.sub
	}
	for _, mc := range vap.Spec.MatchConditions {
		if evalCEL(t, env, mc.Expression, map[string]any{"request": req}) != true {
			return true
		}
	}
	var obj any
	if object != nil {
		obj = object
	}
	var old any
	if r.oldObject != nil {
		old = r.oldObject
	}
	vars := map[string]any{}
	for _, v := range vap.Spec.Variables {
		vars[v.Name] = evalCEL(t, env, v.Expression, map[string]any{"request": req, "variables": vars, "object": obj, "oldObject": old})
	}
	for _, v := range vap.Spec.Validations {
		if evalCEL(t, env, v.Expression, map[string]any{"request": req, "variables": vars, "object": obj, "oldObject": old}) != true {
			return false
		}
	}
	return true
}

func TestOperatorScopePolicyExpression(t *testing.T) {
	t.Parallel()
	vap, _ := loadImagePolicy(t, operatorScopePolicyPath, "confos-operator-scope")
	op := []string{"system:authenticated", "c8s:node-operators"}
	logs := []string{"system:authenticated", "c8s:log-readers"}
	sys := []string{"system:authenticated", "system:masters"}
	for _, tc := range []struct {
		name string
		req  scopeRequest
		want bool
	}{
		// Other principals are never touched, whatever they write.
		{"system:masters in kube-system", scopeRequest{groups: sys, namespace: "kube-system", resource: "pods", operation: "CREATE"}, true},
		{"system:masters clusterrolebinding", scopeRequest{groups: sys, group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", operation: "CREATE"}, true},
		{"no groups field at all", scopeRequest{namespace: "kube-system", resource: "pods", operation: "CREATE"}, true},
		{"unrelated group in kube-system", scopeRequest{groups: []string{"tenants"}, namespace: "kube-system", resource: "configmaps", operation: "CREATE"}, true},
		// The operator's day-to-day work is admitted.
		{"operator pod in tenant ns", scopeRequest{groups: op, namespace: "tenant", resource: "pods", operation: "CREATE"}, true},
		{"operator deployment in default", scopeRequest{groups: op, namespace: "default", group: "apps", resource: "deployments", operation: "CREATE"}, true},
		{"operator namespace create", scopeRequest{groups: op, namespace: "tenant", resource: "namespaces", operation: "CREATE"}, true},
		{"operator rolebinding in tenant ns", scopeRequest{groups: op, namespace: "tenant", group: "rbac.authorization.k8s.io", resource: "rolebindings", operation: "CREATE"}, true},
		{"operator confidentialworkload", scopeRequest{groups: op, namespace: "tenant", group: "confidential.ai", resource: "confidentialworkloads", operation: "CREATE"}, true},
		{"operator pod log (not proxy)", scopeRequest{groups: op, namespace: "tenant", resource: "pods", sub: "log", operation: "CREATE"}, true},
		// The guards and the host are out of reach.
		{"operator pod in kube-system", scopeRequest{groups: op, namespace: "kube-system", resource: "pods", operation: "CREATE"}, false},
		{"operator configmap in local-path-storage", scopeRequest{groups: op, namespace: "local-path-storage", resource: "configmaps", operation: "CREATE"}, true},
		{"operator pod in c8s-system", scopeRequest{groups: op, namespace: "c8s-system", resource: "pods", operation: "CREATE"}, false},
		{"operator token secret in c8s-system", scopeRequest{groups: op, namespace: "c8s-system", resource: "secrets", operation: "CREATE"}, false},
		{"operator delete c8s-system namespace", scopeRequest{groups: op, namespace: "c8s-system", resource: "namespaces", operation: "DELETE"}, false},
		{"operator pod in c8s-router", scopeRequest{groups: op, namespace: "c8s-router", resource: "pods", operation: "CREATE"}, false},
		{"operator edit the router deployment", scopeRequest{groups: op, namespace: "c8s-router", group: "apps", resource: "deployments", operation: "UPDATE"}, false},
		{"operator crd", scopeRequest{groups: op, group: "apiextensions.k8s.io", resource: "customresourcedefinitions", operation: "CREATE"}, false},
		{"operator secret in kube-system", scopeRequest{groups: op, namespace: "kube-system", resource: "secrets", operation: "CREATE"}, false},
		{"operator token in kube-system", scopeRequest{groups: op, namespace: "kube-system", resource: "serviceaccounts", sub: "token", operation: "CREATE"}, false},
		{"operator delete kube-system namespace", scopeRequest{groups: op, namespace: "kube-system", resource: "namespaces", operation: "DELETE"}, false},
		{"operator clusterrole", scopeRequest{groups: op, group: "rbac.authorization.k8s.io", resource: "clusterroles", operation: "CREATE"}, false},
		{"operator clusterrolebinding", scopeRequest{groups: op, group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", operation: "CREATE"}, false},
		{"operator vap", scopeRequest{groups: op, group: "admissionregistration.k8s.io", resource: "validatingadmissionpolicies", operation: "CREATE"}, false},
		{"operator vap binding", scopeRequest{groups: op, group: "admissionregistration.k8s.io", resource: "validatingadmissionpolicybindings", operation: "CREATE"}, false},
		{"operator mutating webhook", scopeRequest{groups: op, group: "admissionregistration.k8s.io", resource: "mutatingwebhookconfigurations", operation: "CREATE"}, false},
		{"operator helmchart in tenant ns", scopeRequest{groups: op, namespace: "tenant", group: "helm.cattle.io", resource: "helmcharts", operation: "CREATE"}, false},
		{"operator k3s addon", scopeRequest{groups: op, namespace: "kube-system", group: "k3s.cattle.io", resource: "addons", operation: "CREATE"}, false},
		{"operator storageclass", scopeRequest{groups: op, group: "storage.k8s.io", resource: "storageclasses", operation: "CREATE"}, false},
		{"operator persistentvolume", scopeRequest{groups: op, resource: "persistentvolumes", operation: "CREATE"}, false},
		{"operator node", scopeRequest{groups: op, resource: "nodes", operation: "CREATE"}, false},
		{"operator node status", scopeRequest{groups: op, resource: "nodes", sub: "status", operation: "CREATE"}, false},
		{"operator apiservice", scopeRequest{groups: op, group: "apiregistration.k8s.io", resource: "apiservices", operation: "CREATE"}, false},
		{"operator csr approval", scopeRequest{groups: op, group: "certificates.k8s.io", resource: "certificatesigningrequests", sub: "approval", operation: "CREATE"}, false},
		{"operator nodes/proxy", scopeRequest{groups: op, resource: "nodes", sub: "proxy", operation: "CREATE"}, false},
		{"operator pods/proxy", scopeRequest{groups: op, namespace: "tenant", resource: "pods", sub: "proxy", operation: "CREATE"}, false},
		{"operator services/proxy", scopeRequest{groups: op, namespace: "tenant", resource: "services", sub: "proxy", operation: "CREATE"}, false},
		// The log-reader is a c8s:* group too.
		{"log-reader configmap in kube-system", scopeRequest{groups: logs, namespace: "kube-system", resource: "configmaps", operation: "CREATE"}, false},
		{"log-reader clusterrolebinding", scopeRequest{groups: logs, group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", operation: "CREATE"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOperatorScope(t, vap, tc.req); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}

// A Service is the one object the operator may write whose content, not its
// place, matters: member pods' packet filters let the resolver and the
// kube-state-metrics exit through by address, so no c8s:* Service may route
// those addresses elsewhere.
func TestOperatorScopePolicyServiceAddresses(t *testing.T) {
	t.Parallel()
	vap, _ := loadImagePolicy(t, operatorScopePolicyPath, "confos-operator-scope")
	op := []string{"system:authenticated", "c8s:node-operators"}
	sys := []string{"system:authenticated", "system:masters"}
	svc := func(spec map[string]any) map[string]any { return map[string]any{"spec": spec} }
	for _, tc := range []struct {
		name   string
		groups []string
		object map[string]any
		want   bool
	}{
		{"allocated ClusterIP", op, svc(map[string]any{"clusterIP": "10.53.143.7", "clusterIPs": []any{"10.53.143.7"}}), true},
		{"headless", op, svc(map[string]any{"clusterIP": "None", "clusterIPs": []any{"None"}}), true},
		{"empty externalIPs", op, svc(map[string]any{"externalIPs": []any{}}), true},
		{"no spec", op, map[string]any{}, true},
		{"delete (null object)", op, nil, true},
		{"server-side dry-run placeholder", op, svc(map[string]any{"clusterIP": "10.53.0.0", "clusterIPs": []any{"10.53.0.0"}}), true},
		{"externalIPs on the exit", op, svc(map[string]any{"externalIPs": []any{"10.53.0.11"}}), false},
		{"externalIPs anywhere", op, svc(map[string]any{"externalIPs": []any{"192.0.2.1"}}), false},
		{"ClusterIP of the exit", op, svc(map[string]any{"clusterIP": "10.53.0.11"}), false},
		{"other static-band ClusterIP", op, svc(map[string]any{"clusterIP": "10.53.0.200"}), false},
		{"first static-band ClusterIP", op, svc(map[string]any{"clusterIP": "10.53.0.1"}), false},
		{"static band in clusterIPs only", op, svc(map[string]any{"clusterIPs": []any{"10.53.0.12"}}), false},
		{"system:masters keeps the band", sys, svc(map[string]any{"clusterIP": "10.53.0.11", "externalIPs": []any{"10.53.0.11"}}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scopeRequest{groups: tc.groups, namespace: "tenant", resource: "services", operation: "CREATE"}
			if tc.object == nil {
				r.operation = "DELETE"
			}
			if got := evalOperatorScopeObject(t, vap, r, tc.object); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOperatorScopeRouterRecovery(t *testing.T) {
	t.Parallel()
	vap, _ := loadImagePolicy(t, operatorScopePolicyPath, "confos-operator-scope")
	pod := func(namespace, name string, labels map[string]any) map[string]any {
		return map[string]any{"metadata": map[string]any{"namespace": namespace, "name": name, "labels": labels}}
	}
	base := scopeRequest{groups: []string{"system:authenticated", "c8s:node-operators"}, namespace: "c8s-router", resource: "pods", operation: "DELETE", name: "router-1", oldObject: pod("c8s-router", "router-1", nil)}
	for _, tc := range []struct {
		name   string
		change func(*scopeRequest)
		want   bool
	}{
		{"named deletion without labels", func(r *scopeRequest) {}, true},
		{"collection deletion with stored pod", func(r *scopeRequest) { r.name = "" }, true},
		{"labels irrelevant", func(r *scopeRequest) { r.oldObject = pod("c8s-router", "router-1", map[string]any{"app": "unrelated"}) }, true},
		{"log reader", func(r *scopeRequest) { r.groups = []string{"c8s:log-readers"} }, false},
		{"other released group", func(r *scopeRequest) { r.groups = []string{"c8s:other"} }, false},
		{"operator-looking group", func(r *scopeRequest) { r.groups = []string{"c8s:node-operators-extra"} }, false},
		{"create", func(r *scopeRequest) { r.operation = "CREATE" }, false},
		{"patch admits as update", func(r *scopeRequest) { r.operation = "UPDATE" }, false},
		{"connect", func(r *scopeRequest) { r.operation = "CONNECT" }, false},
		{"missing operation", func(r *scopeRequest) { r.operation = "" }, false},
		{"eviction", func(r *scopeRequest) { r.operation = "CREATE"; r.sub = "eviction" }, false},
		{"exec", func(r *scopeRequest) { r.operation = "CONNECT"; r.sub = "exec" }, false},
		{"proxy", func(r *scopeRequest) { r.sub = "proxy" }, false},
		{"status", func(r *scopeRequest) { r.sub = "status" }, false},
		{"custom pods", func(r *scopeRequest) { r.group = "example.com" }, false},
		{"deployment delete", func(r *scopeRequest) { r.group = "apps"; r.resource = "deployments" }, false},
		{"deployment patch", func(r *scopeRequest) { r.group = "apps"; r.resource = "deployments"; r.operation = "UPDATE" }, false},
		{"replicaset delete", func(r *scopeRequest) { r.group = "apps"; r.resource = "replicasets" }, false},
		{"configmap delete", func(r *scopeRequest) { r.resource = "configmaps" }, false},
		{"secret delete", func(r *scopeRequest) { r.resource = "secrets" }, false},
		{"service delete", func(r *scopeRequest) { r.resource = "services" }, false},
		{"namespace delete", func(r *scopeRequest) { r.resource = "namespaces" }, false},
		{"kube-system with router labels", func(r *scopeRequest) {
			r.namespace = "kube-system"
			r.oldObject = pod(r.namespace, "router-1", map[string]any{"app": "c8s-router"})
		}, false},
		{"c8s-system", func(r *scopeRequest) { r.namespace = "c8s-system" }, false},
		{"wrong stored namespace", func(r *scopeRequest) { r.oldObject = pod("tenant", "router-1", nil) }, false},
		{"empty stored name", func(r *scopeRequest) { r.oldObject = pod("c8s-router", "", nil) }, false},
		{"missing old object", func(r *scopeRequest) { r.oldObject = nil }, false},
		{"missing metadata", func(r *scopeRequest) { r.oldObject = map[string]any{} }, false},
		{"null metadata", func(r *scopeRequest) { r.oldObject = map[string]any{"metadata": nil} }, false},
		{"null stored name", func(r *scopeRequest) {
			r.oldObject = map[string]any{"metadata": map[string]any{"namespace": "c8s-router", "name": nil}}
		}, false},
		{"missing stored fields", func(r *scopeRequest) { r.oldObject = map[string]any{"metadata": map[string]any{}} }, false},
		{"tenant delete", func(r *scopeRequest) { r.namespace = "tenant" }, true},
		{"system principal", func(r *scopeRequest) { r.groups = []string{"system:masters"}; r.operation = "CREATE" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			if got := evalOperatorScope(t, vap, r); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}
