package yamlutil

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func parseTree(t *testing.T, data string) *yaml.Node {
	t.Helper()
	var tree yaml.Node
	if err := yaml.Unmarshal([]byte(data), &tree); err != nil {
		t.Fatal(err)
	}
	return &tree
}

// A key a document does not write and a key written as something else are
// both absent: a caller reading presence must not see a zero value as one.
func TestPathPresent(t *testing.T) {
	tree := parseTree(t, "rke2:\n  agentToken: a\nrole: server\n")
	if !PathPresent(tree, "rke2", "agentToken") {
		t.Error("present nested key not found")
	}
	if PathPresent(tree, "rke2", "serverToken") {
		t.Error("absent nested key reported present")
	}
	if PathPresent(tree, "role", "nested") {
		t.Error("descended into a scalar")
	}
}

func TestMappingPathRefusesWhatItCannotPatch(t *testing.T) {
	tree := parseTree(t, "allowlist:\n  pull:\n    url: https://cds:8443\n  base: a\n")
	if _, err := MappingPath(tree.Content[0], "allowlist", "pull"); err != nil {
		t.Fatalf("MappingPath: %v", err)
	}
	if _, err := MappingPath(tree.Content[0], "allowlist", "push"); err == nil {
		t.Error("walked to a section the document does not carry")
	}
	if _, err := MappingPath(tree.Content[0], "allowlist", "base"); err == nil {
		t.Error("walked into a scalar")
	}
}

// Patching a value keeps the comments the node image ships around it.
func TestSetMappingValueKeepsComments(t *testing.T) {
	tree := parseTree(t, "pull:\n  measure_policies: false # the switch this release runs with\n")
	pull, err := MappingPath(tree.Content[0], "pull")
	if err != nil {
		t.Fatal(err)
	}
	SetMappingValue(pull, "measure_policies", &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!bool",
		Value: "true",
	})
	SetMappingValue(pull, "url", &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "https://cds:8443",
	})
	patched := MappingValue(pull, "measure_policies")
	if patched.Value != "true" || patched.LineComment != "# the switch this release runs with" {
		t.Errorf("patched value = %q with comment %q", patched.Value, patched.LineComment)
	}
	if added := MappingValue(pull, "url"); added == nil || added.Value != "https://cds:8443" {
		t.Errorf("appended value = %v", added)
	}
}
