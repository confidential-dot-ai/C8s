// Package yamlutil decodes a configuration document that must mean exactly
// what it says: one bounded document, no anchors or aliases, no ambiguous or
// duplicate keys, and no field the target type does not declare.
package yamlutil

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"gopkg.in/yaml.v3"
)

// maxDocumentSize bounds a document supplied by the host.
const maxDocumentSize = 1024 * 1024

// maxDepth bounds nesting before the recursive walk reaches the stack.
const maxDepth = 32

// Decode checks data against the document rules and decodes it into out,
// which must declare every field the document writes.
func Decode(data []byte, out any) error {
	if _, err := DecodeTree(data); err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	return nil
}

// DecodeTree checks data against the document rules and returns its node
// tree, which tells a caller whether a key was written at all; a decoded zero
// value does not.
func DecodeTree(data []byte) (*yaml.Node, error) {
	if len(data) == 0 || len(data) > maxDocumentSize {
		return nil, fmt.Errorf("configuration must contain 1..%d bytes", maxDocumentSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var tree yaml.Node
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if err := singleDocument(dec); err != nil {
		return nil, err
	}
	if err := checkNode(&tree, 0); err != nil {
		return nil, err
	}
	return &tree, nil
}

func singleDocument(dec *yaml.Decoder) error {
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("configuration must contain exactly one YAML document")
	}
	return nil
}

func checkNode(n *yaml.Node, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("YAML nesting exceeds %d levels", maxDepth)
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("YAML anchors and aliases are forbidden")
	}
	if n.Kind == yaml.MappingNode {
		if err := checkKeys(n); err != nil {
			return err
		}
	}
	for _, child := range n.Content {
		if err := checkNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func checkKeys(n *yaml.Node) error {
	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if err := checkKey(key); err != nil {
			return err
		}
		if seen[key.Value] {
			return fmt.Errorf("duplicate YAML key %q", key.Value)
		}
		seen[key.Value] = true
	}
	return nil
}

func checkKey(key *yaml.Node) error {
	if key.Kind != yaml.ScalarNode || key.Value == "<<" {
		return fmt.Errorf("invalid YAML mapping key")
	}
	switch key.Tag {
	case "!!str":
		return nil
	case "!!int":
		if !canonicalIntKey(key.Value) {
			return fmt.Errorf("noncanonical YAML mapping key")
		}
		return nil
	default:
		return fmt.Errorf("invalid YAML mapping key")
	}
}

// canonicalIntKey holds an integer key to the one spelling the duplicate
// check compares: 01 and 1 are two strings and one integer key.
func canonicalIntKey(value string) bool {
	index, err := strconv.ParseUint(value, 10, 64)
	return err == nil && strconv.FormatUint(index, 10) == value
}
