package allowlist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDeriveRequiresExplicitEnvironment(t *testing.T) {
	if _, err := runDerive(t, deployJSON(), "w", "-"); err == nil {
		t.Fatal("implicit env accepted")
	}
	for _, mode := range []string{"any", "deny"} {
		got, err := runDerive(t, deployJSON(), "w", "-", "--env="+mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range allContainers(got["w"]) {
			if c.Env.Policy != mode {
				t.Fatal("policy not applied to every container")
			}
		}
	}
	file := filepath.Join(t.TempDir(), "env.json")
	data := `{"seed":{"policy":"deny"},"frontend":{"policy":"exact","values":{"MODE":"production"}},"worker":{"policy":"any"}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := runDerive(t, deployJSON(), "w", "-", "--env-file", file)
	if err != nil {
		t.Fatal(err)
	}
	if got["w"].Containers[0].Env.Values["MODE"] != "production" {
		t.Fatal("exact values not derived")
	}
	if _, err := runDerive(t, deployJSON(), "w", "-", "--env-file", file, "--env=any"); err == nil {
		t.Fatal("conflicting policies accepted")
	}
}

func TestEnvironmentEditsAndCollisionShapes(t *testing.T) {
	for _, policy := range []string{"exact", "match"} {
		t.Run(policy, func(t *testing.T) {
			testEnvironmentEditsAndCollisionShapes(t, policy)
		})
	}
}

func testEnvironmentEditsAndCollisionShapes(t *testing.T, policy string) {
	t.Helper()
	parse := func(value string) pkgallowlist.Workload {
		env := `{"policy":"exact","values":{"MODE":"` + value + `"}}`
		if policy == "match" {
			env = `{"policy":"match","variables":{"MODE":{"exact":"` + value + `"},"GPU_SERIAL":{"present":true}}}`
		}
		w, err := pkgallowlist.ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"env":` + env + `}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return *w
	}
	a, b := parse("a"), parse("b")
	if diffEntry(a, b).empty() {
		t.Fatal("env-only edit invisible")
	}
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{"a": a, "b": b}}
	if len(indistinguishableEntries(al)) != 0 {
		t.Fatal("env-distinct workloads treated as identical")
	}
	al.Workloads["b"] = a
	if len(indistinguishableEntries(al)) != 1 {
		t.Fatal("identical workloads not flagged")
	}
}

func TestDeriveMixedEnvironmentMatchers(t *testing.T) {
	file := filepath.Join(t.TempDir(), "env.json")
	data := `{"seed":{"policy":"deny"},"frontend":{"policy":"match","variables":{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}},"worker":{"policy":"any"}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := runDerive(t, deployJSON(), "w", "-", "--env-file", file)
	if err != nil {
		t.Fatal(err)
	}
	env := got["w"].Containers[0].Env
	value, exact := env.ExactValues()["MODE"]
	present, err := json.Marshal(env.Variables["GPU_SERIAL"])
	if env.Policy != pkgallowlist.PolicyMatch || !exact || value != "production" || err != nil || string(present) != `{"present":true}` {
		t.Fatalf("mixed environment matchers not derived: %#v", env)
	}
}
