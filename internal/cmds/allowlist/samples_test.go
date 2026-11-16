package allowlist

import (
	"os"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The entry docs/DEMO.md step 1 writes for the sample workload must pass the
// lint apply runs before signing: nginx's entrypoint is a component
// invocation, so its environment has to be named variable by variable.
func TestSampleWorkloadEntryLints(t *testing.T) {
	manifest, err := os.ReadFile(testutil.RepoPath("samples", "nginx-confidential-pod.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	podJSON, err := yaml.YAMLToJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := podSpecOf(podJSON)
	if err != nil {
		t.Fatal(err)
	}
	policyFile, err := os.ReadFile(testutil.RepoPath("samples", "nginx-env-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policies, err := pkgallowlist.ParseEnvPoliciesJSON(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	var nginxArgv imageArgv = func(string) ([]string, []string, error) {
		return []string{"/docker-entrypoint.sh"}, []string{"nginx", "-g", "daemon off;"}, nil
	}
	var containers []pkgallowlist.Container
	for _, c := range spec.Containers {
		derived, err := deriveContainers([]templateContainer{c}, nginxArgv)
		if err != nil {
			t.Fatal(err)
		}
		policy, ok := policies[c.Name]
		if !ok {
			t.Fatalf("the sample env policy names no policy for container %q", c.Name)
		}
		entry := derived[0]
		entry.Env = policy
		entry.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}
		containers = append(containers, entry)
	}
	al := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"demo-nginx": {Containers: containers}},
	}
	if findings := lintOffline(al); countErrors(findings) > 0 {
		t.Fatalf("lint refuses the documented sample entry: %v", findings)
	}
}
