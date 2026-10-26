package launchconfig

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Parse strictly validates the offline launch document. Guest callers must
// use Verify first; Parse alone provides no authentication.
func Parse(data []byte) (*Document, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("launch configuration must contain 1..%d bytes", MaxDocumentSize)
	}
	var tree yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("parse launch YAML: %w", err)
	}
	if err := singleDocument(dec); err != nil {
		return nil, err
	}
	if err := checkYAML(&tree, 0); err != nil {
		return nil, err
	}
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode launch configuration: %w", err)
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func singleDocument(dec *yaml.Decoder) error {
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("launch configuration must contain exactly one YAML document")
	}
	return nil
}

func checkYAML(n *yaml.Node, depth int) error {
	if depth > 32 {
		return fmt.Errorf("launch YAML nesting exceeds 32 levels")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("launch YAML anchors and aliases are forbidden")
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Value == "<<" {
				return fmt.Errorf("invalid launch YAML mapping key")
			}
			// Integer keys occur only in the RTMR map. Alternative spellings
			// such as 01 and 1 must not collapse to one int after review.
			if k.Tag != "!!str" && (k.Tag != "!!int" || (k.Value != "1" && k.Value != "2")) {
				return fmt.Errorf("noncanonical launch YAML mapping key")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate launch YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := checkYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}
