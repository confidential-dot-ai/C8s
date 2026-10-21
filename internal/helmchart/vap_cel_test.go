// Shared CEL evaluation for the rendered ValidatingAdmissionPolicies: the
// expressions are compiled over `object: dyn`, because the apiserver
// type-checks them against the matched resource schema and cel-go cannot
// reproduce that here. Evaluating over dyn still exercises the guards.
package helmchart

import (
	"testing"

	"cel.dev/cel-go/cel"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

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
	t.Errorf("policy admitted the object: want at least one expression to deny it")
}
