package yamlutil

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MappingValue is key's value in a mapping node, nil when the node is not a
// mapping or does not carry the key.
func MappingValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// MappingPath walks nested mappings. A missing key is an error rather than a
// created one: a caller patches a section the document already carries.
func MappingPath(n *yaml.Node, keys ...string) (*yaml.Node, error) {
	for i, key := range keys {
		value := MappingValue(n, key)
		if value == nil {
			return nil, fmt.Errorf("no %s section", strings.Join(keys[:i+1], "."))
		}
		if value.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a mapping", strings.Join(keys[:i+1], "."))
		}
		n = value
	}
	return n, nil
}

// SetMappingValue replaces key's value in place, keeping the comments written
// around it, or appends the pair when the mapping does not carry it yet.
func SetMappingValue(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			value.HeadComment = n.Content[i+1].HeadComment
			value.LineComment = n.Content[i+1].LineComment
			value.FootComment = n.Content[i+1].FootComment
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content,
		&yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: key,
		},
		value)
}

// PathPresent reports whether a document writes the key at path at all; a
// decoded zero value does not.
func PathPresent(n *yaml.Node, path ...string) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return PathPresent(n.Content[0], path...)
	}
	if len(path) == 0 {
		return true
	}
	value := MappingValue(n, path[0])
	if value == nil {
		return false
	}
	return PathPresent(value, path[1:]...)
}
