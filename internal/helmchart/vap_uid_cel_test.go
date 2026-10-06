// Behaviorally evaluates the rendered deny-armtls-mesh-uid and
// deny-armtls-mesh-uid-ephemeral ValidatingAdmissionPolicies with cel-go over
// the same expressions the apiserver compiles, so UID-0 / reserved-proxy-UID
// admission is tested, not just rendered.
//
// The expressions are compiled over `object: dyn`: the apiserver type-checks
// VAP expressions against the matched resource schema, which cel-go cannot
// reproduce here; evaluating over dyn still exercises the guards (runAsUser 0
// and the reserved proxy UID) that the policies must enforce. A live
// `kubectl apply` of the policy remains the schema-level proof (see the PR
// body's live-e2e list).
package helmchart

import (
	"testing"

	"cel.dev/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// renderedUIDPolicies renders the chart and pulls both UID admission policies'
// validation expressions, keyed by policy name.
func renderedUIDPolicies(t *testing.T) map[string][]admissionregv1.Validation {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	policies := map[string][]admissionregv1.Validation{}
	iterateManifests(t, out, func(doc []byte) bool {
		var p admissionregv1.ValidatingAdmissionPolicy
		if err := sigsyaml.Unmarshal(doc, &p); err != nil {
			return false
		}
		if p.Kind != "ValidatingAdmissionPolicy" {
			return false
		}
		policies[p.Name] = p.Spec.Validations
		return false
	})
	for _, name := range []string{"deny-armtls-mesh-uid", "deny-armtls-mesh-uid-ephemeral"} {
		if _, ok := policies[name]; !ok {
			t.Fatalf("%s policy not rendered", name)
		}
	}
	return policies
}

// evalPolicy compiles one validation expression against an admission `object`
// and reports whether it evaluates to true (allowed) without error.
func evalPolicy(t *testing.T, expr string, object map[string]any) bool {
	t.Helper()
	return evalAdmissionPolicy(t, expr, object, nil, "CREATE")
}

// evalAdmissionPolicy supplies the prior persisted object and admission operation.
// CREATE has a null oldObject, matching the API server rather than an empty map.
func evalAdmissionPolicy(t *testing.T, expr string, object, oldObject map[string]any, operation string) bool {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	var prior any
	if oldObject != nil {
		prior = oldObject
	}
	return evalCEL(t, env, expr, map[string]any{
		"object":    object,
		"oldObject": prior,
		"request":   map[string]any{"operation": operation},
	}) == true
}

// evalCEL compiles expr in env and evaluates it against activation, failing
// the test on a compile or evaluation error.
func evalCEL(t *testing.T, env *cel.Env, expr string, activation map[string]any) any {
	t.Helper()
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("cel compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("cel program: %v", err)
	}
	out, _, err := prg.Eval(activation)
	if err != nil {
		t.Fatalf("cel eval %q: %v", expr, err)
	}
	return out.Value()
}

// allTrue asserts every validation of a policy allows the object.
func allTrue(t *testing.T, validations []admissionregv1.Validation, o map[string]any) {
	t.Helper()
	allTrueAdmission(t, validations, o, nil, "CREATE")
}

func allTrueAdmission(t *testing.T, validations []admissionregv1.Validation, o, old map[string]any, operation string) {
	t.Helper()
	for _, v := range validations {
		if !evalAdmissionPolicy(t, v.Expression, o, old, operation) {
			t.Errorf("expression %q denied an object that should be allowed", v.Expression)
		}
	}
}

// anyFalse asserts at least one validation denies the object.
func anyFalse(t *testing.T, validations []admissionregv1.Validation, o map[string]any) {
	t.Helper()
	anyFalseAdmission(t, validations, o, nil, "CREATE")
}

func anyFalseAdmission(t *testing.T, validations []admissionregv1.Validation, o, old map[string]any, operation string) {
	t.Helper()
	for _, v := range validations {
		if !evalAdmissionPolicy(t, v.Expression, o, old, operation) {
			return
		}
	}
	t.Errorf("policy admitted an object that every expression allowed")
}

// container shapes a container map with an optional runAsUser (int64 so CEL
// sees an int, never a double).
func container(name, image string, runAsUser *int64) map[string]any {
	c := map[string]any{"name": name, "image": image}
	if runAsUser != nil {
		c["securityContext"] = map[string]any{"runAsUser": *runAsUser}
	}
	return c
}

func TestDenyARMTLSMeshUidPodPolicyBehaviors(t *testing.T) {
	policies := renderedUIDPolicies(t)
	validations := policies["deny-armtls-mesh-uid"]

	u1000 := int64(1000)
	u0 := int64(0)
	u1337 := int64(1337)

	// A pod with no securityContext is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"containers": []any{container("app", "busybox", nil)}},
	})

	// Pod-level runAsUser 0 is not in any exemption cgroup -> denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u0}},
	})

	// Pod-level runAsUser 1337 is the proxy's reserved UID -> denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u1337}},
	})

	// A non-reserved, non-0 user is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"securityContext": map[string]any{"runAsUser": u1000}},
	})

	// A container requesting runAsUser 0 is denied even with no pod context.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"containers": []any{container("app", "busybox", &u0)}},
	})

	// An init container at UID 0 is denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{
			"initContainers": []any{container("init", "busybox", &u0)},
			"containers":     []any{container("app", "busybox", nil)},
		},
	})
}

func TestDenyARMTLSMeshUidEphemeralPolicyBehaviors(t *testing.T) {
	policies := renderedUIDPolicies(t)
	validations := policies["deny-armtls-mesh-uid-ephemeral"]

	u1000 := int64(1000)
	u0 := int64(0)

	// The pods/ephemeralcontainers subresource with no shape is allowed.
	allTrue(t, validations, map[string]any{"spec": map[string]any{}})

	// An ephemeral container at UID 0 is denied.
	anyFalse(t, validations, map[string]any{
		"spec": map[string]any{"ephemeralContainers": []any{container("debugger", "busybox", &u0)}},
	})

	// An ephemeral container at a non-reserved user is allowed.
	allTrue(t, validations, map[string]any{
		"spec": map[string]any{"ephemeralContainers": []any{container("debugger", "busybox", &u1000)}},
	})
}
