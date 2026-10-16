package helmchart

import (
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
)

// The node image keeps the kubelet debugging handlers on so `kubectl logs`
// works for the log-reader credential, and bakes this policy so the other
// handlers (exec, attach, port-forward) and ephemeral containers stay closed
// at the apiserver for every principal. Applied by RKE2, not the chart, so it
// is read from the image tree here like psa-level-policy.
const podExecPolicyPath = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/pod-exec-policy.yaml"

func TestPodExecPolicyShape(t *testing.T) {
	t.Parallel()
	vap, binding := loadImagePolicy(t, podExecPolicyPath, "confos-pod-exec")
	checkDenyPolicyShape(t, vap, binding)
	// exec/attach/port-forward are CONNECT on their subresources; ephemeral
	// containers are an UPDATE on theirs (kubectl debug). Each subresource
	// must be matched under the operation the apiserver actually reports.
	want := map[string]admissionregv1.OperationType{
		"pods/exec":                admissionregv1.Connect,
		"pods/attach":              admissionregv1.Connect,
		"pods/portforward":         admissionregv1.Connect,
		"pods/ephemeralcontainers": admissionregv1.Update,
	}
	for _, r := range vap.Spec.MatchConstraints.ResourceRules {
		for _, res := range r.Resources {
			op, ok := want[res]
			if !ok {
				t.Errorf("matchConstraints names unexpected resource %q", res)
				continue
			}
			for _, have := range r.Operations {
				if have == op || have == admissionregv1.OperationAll {
					delete(want, res)
				}
			}
		}
	}
	for res, op := range want {
		t.Errorf("matchConstraints does not match %s on %s", op, res)
	}
	if len(vap.Spec.Validations) != 1 {
		t.Fatalf("expected one validation, got %d", len(vap.Spec.Validations))
	}
	// The expression is a constant deny: it must compile and evaluate false
	// against any object, so it cannot error into the failurePolicy path.
	if evalPolicy(t, vap.Spec.Validations[0].Expression, map[string]any{}) {
		t.Error("validation admits the request, want a constant deny")
	}
	if binding.Spec.MatchResources != nil {
		t.Error("binding must not narrow the policy: every principal, cluster-admin included, is denied")
	}
}
