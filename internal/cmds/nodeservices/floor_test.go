package nodeservices

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// floorValues are the placeholder values a staging gives a floor: this node's
// name, and no advertise address, which passes no flag.
func floorValues() map[string]string {
	return map[string]string{NodeNamePlaceholder: "n1", nodeAdvertiseAddressPlaceholder: DropFlag}
}

func TestFillingRefusesAPlaceholderTheFloorDoesNotDefine(t *testing.T) {
	for _, element := range []string{"${NODE_NAME}", "--hostname-override=n-${NODE_NAME}", "--hostname-override=${NODE}"} {
		base := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"w": {Containers: []allowlist.Container{{
			Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{element}},
		}}}}}
		if err := bindPlaceholderFlags(base, floorValues()); err == nil {
			t.Errorf("filled %q", element)
		}
	}
}

// A floor placeholder the preparation has no value for is refused wherever it
// stands, and so is a value for a placeholder no floor names.
func TestFillingRefusesAPlaceholderWithoutAValue(t *testing.T) {
	for _, element := range []string{"--hostname-override=${NODE_NAME}", "n-${NODE_NAME}"} {
		base := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"w": {Containers: []allowlist.Container{{
			Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{element}},
		}}}}}
		if err := bindPlaceholderFlags(base, nil); err == nil {
			t.Errorf("left %q unfilled", element)
		}
	}
	if err := bindPlaceholderFlags(&allowlist.Allowlist{}, map[string]string{"${API_SERVER}": "a"}); err == nil {
		t.Error("accepted a value for a placeholder no floor names")
	}
}

// A pinned script's own shell variables are not floor placeholders.
func TestFillingKeepsAScriptsOwnVariables(t *testing.T) {
	script := `nsenter --mount=/hostproc/1/ns/mnt "${BIN_PATH}/cilium-mount" $CGROUP_ROOT`
	base := &allowlist.Allowlist{Workloads: map[string]allowlist.Workload{"w": {Containers: []allowlist.Container{{
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"bash", "-ec", script}},
	}}}}}
	if err := bindPlaceholderFlags(base, floorValues()); err != nil {
		t.Fatal(err)
	}
	if got := base.Workloads["w"].Containers[0].Command.Argv[2]; got != script {
		t.Errorf("script = %q, want it unchanged", got)
	}
}
