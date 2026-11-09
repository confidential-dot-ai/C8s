package workflows

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflowStep struct {
	Name, ID, Uses, Run, If string
	With                    map[string]string
}

type workflowDocument struct {
	Jobs map[string]struct {
		Steps []workflowStep
	}
}

func readYAML(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func readWorkflow(t *testing.T, name string) workflowDocument {
	t.Helper()
	var doc workflowDocument
	readYAML(t, filepath.Join("../../.github/workflows", name), &doc)
	return doc
}

// names reads a workflow field that takes one value, a list of values or a
// mapping keyed by them — as `needs` and `on` do. An absent field has none.
func names(t *testing.T, node yaml.Node) []string {
	t.Helper()
	var result []string
	switch {
	case node.IsZero():
	case node.Kind == yaml.ScalarNode:
		result = append(result, node.Value)
	case node.Kind == yaml.SequenceNode:
		for _, value := range node.Content {
			result = append(result, value.Value)
		}
	case node.Kind == yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			result = append(result, node.Content[i].Value)
		}
	default:
		t.Fatalf("unsupported shape for a list of names: %v", node.Kind)
	}
	slices.Sort(result)
	return result
}
