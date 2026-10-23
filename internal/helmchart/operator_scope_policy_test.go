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
const operatorScopePolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/operator-scope-policy.yaml"

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
	env, err := cel.NewEnv(cel.Variable("request", cel.DynType), cel.Variable("variables", cel.DynType), cel.Variable("object", cel.DynType))
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
	vars := map[string]any{}
	for _, v := range vap.Spec.Variables {
		vars[v.Name] = evalCEL(t, env, v.Expression, map[string]any{"request": req, "variables": vars, "object": obj})
	}
	for _, v := range vap.Spec.Validations {
		if evalCEL(t, env, v.Expression, map[string]any{"request": req, "variables": vars, "object": obj}) != true {
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
		{"system:masters in kube-system", scopeRequest{sys, "kube-system", "", "pods", ""}, true},
		{"system:masters clusterrolebinding", scopeRequest{sys, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, true},
		{"no groups field at all", scopeRequest{nil, "kube-system", "", "pods", ""}, true},
		{"unrelated group in kube-system", scopeRequest{[]string{"tenants"}, "kube-system", "", "configmaps", ""}, true},
		// The operator's day-to-day work is admitted.
		{"operator pod in tenant ns", scopeRequest{op, "tenant", "", "pods", ""}, true},
		{"operator deployment in default", scopeRequest{op, "default", "apps", "deployments", ""}, true},
		{"operator namespace create", scopeRequest{op, "tenant", "", "namespaces", ""}, true},
		{"operator rolebinding in tenant ns", scopeRequest{op, "tenant", "rbac.authorization.k8s.io", "rolebindings", ""}, true},
		{"operator confidentialworkload", scopeRequest{op, "tenant", "confidential.ai", "confidentialworkloads", ""}, true},
		{"operator pod log (not proxy)", scopeRequest{op, "tenant", "", "pods", "log"}, true},
		// The guards and the host are out of reach.
		{"operator pod in kube-system", scopeRequest{op, "kube-system", "", "pods", ""}, false},
		{"operator configmap in local-path-storage", scopeRequest{op, "local-path-storage", "", "configmaps", ""}, false},
		{"operator pod in c8s-system", scopeRequest{op, "c8s-system", "", "pods", ""}, false},
		{"operator token secret in c8s-system", scopeRequest{op, "c8s-system", "", "secrets", ""}, false},
		{"operator delete c8s-system namespace", scopeRequest{op, "c8s-system", "", "namespaces", ""}, false},
		{"operator pod in c8s-router", scopeRequest{op, "c8s-router", "", "pods", ""}, false},
		{"operator edit the router deployment", scopeRequest{op, "c8s-router", "apps", "deployments", ""}, false},
		{"operator crd", scopeRequest{op, "", "apiextensions.k8s.io", "customresourcedefinitions", ""}, false},
		{"operator secret in kube-system", scopeRequest{op, "kube-system", "", "secrets", ""}, false},
		{"operator token in kube-system", scopeRequest{op, "kube-system", "", "serviceaccounts", "token"}, false},
		{"operator delete kube-system namespace", scopeRequest{op, "kube-system", "", "namespaces", ""}, false},
		{"operator clusterrole", scopeRequest{op, "", "rbac.authorization.k8s.io", "clusterroles", ""}, false},
		{"operator clusterrolebinding", scopeRequest{op, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, false},
		{"operator vap", scopeRequest{op, "", "admissionregistration.k8s.io", "validatingadmissionpolicies", ""}, false},
		{"operator vap binding", scopeRequest{op, "", "admissionregistration.k8s.io", "validatingadmissionpolicybindings", ""}, false},
		{"operator mutating webhook", scopeRequest{op, "", "admissionregistration.k8s.io", "mutatingwebhookconfigurations", ""}, false},
		{"operator helmchart in tenant ns", scopeRequest{op, "tenant", "helm.cattle.io", "helmcharts", ""}, false},
		{"operator k3s addon", scopeRequest{op, "kube-system", "k3s.cattle.io", "addons", ""}, false},
		{"operator storageclass", scopeRequest{op, "", "storage.k8s.io", "storageclasses", ""}, false},
		{"operator persistentvolume", scopeRequest{op, "", "", "persistentvolumes", ""}, false},
		{"operator node", scopeRequest{op, "", "", "nodes", ""}, false},
		{"operator node status", scopeRequest{op, "", "", "nodes", "status"}, false},
		{"operator apiservice", scopeRequest{op, "", "apiregistration.k8s.io", "apiservices", ""}, false},
		{"operator csr approval", scopeRequest{op, "", "certificates.k8s.io", "certificatesigningrequests", "approval"}, false},
		{"operator nodes/proxy", scopeRequest{op, "", "", "nodes", "proxy"}, false},
		{"operator pods/proxy", scopeRequest{op, "tenant", "", "pods", "proxy"}, false},
		{"operator services/proxy", scopeRequest{op, "tenant", "", "services", "proxy"}, false},
		// The log-reader is a c8s:* group too.
		{"log-reader configmap in kube-system", scopeRequest{logs, "kube-system", "", "configmaps", ""}, false},
		{"log-reader clusterrolebinding", scopeRequest{logs, "", "rbac.authorization.k8s.io", "clusterrolebindings", ""}, false},
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
			r := scopeRequest{tc.groups, "tenant", "", "services", ""}
			if got := evalOperatorScopeObject(t, vap, r, tc.object); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}
