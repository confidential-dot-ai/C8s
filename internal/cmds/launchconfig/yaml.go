package launchconfig

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

// Parse strictly validates the offline launch document. Guest callers must
// use Verify first; Parse alone provides no authentication.
func Parse(data []byte) (*Document, error) {
	tree, err := yamlutil.DecodeTree(data)
	if err != nil {
		return nil, fmt.Errorf("launch configuration: %w", err)
	}
	var doc Document
	if err := yamlutil.Decode(data, &doc); err != nil {
		return nil, fmt.Errorf("launch configuration: %w", err)
	}
	doc.serverTokenPresent = yamlPathPresent(tree, "rke2", "serverToken")
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func yamlPathPresent(n *yaml.Node, path ...string) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return yamlPathPresent(n.Content[0], path...)
	}
	if len(path) == 0 {
		return true
	}
	if n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == path[0] {
			return yamlPathPresent(n.Content[i+1], path[1:]...)
		}
	}
	return false
}
