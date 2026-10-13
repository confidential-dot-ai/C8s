package allowlist

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// EnvMatcher holds one exact-value or presence matcher.
type EnvMatcher struct {
	matcher envMatcherBehavior
}

type envMatcherBehavior interface {
	valid() bool
	matches(name, digest string) bool
	exactValue() (string, bool)
}

func (m EnvMatcher) behavior() (envMatcherBehavior, error) {
	if m.matcher == nil || !m.matcher.valid() {
		return nil, fmt.Errorf("environment matcher requires exactly one of exact or present: true")
	}
	return m.matcher, nil
}

func (m EnvMatcher) MarshalJSON() ([]byte, error) {
	matcher, err := m.behavior()
	if err != nil {
		return nil, err
	}
	return json.Marshal(matcher)
}

func (m EnvMatcher) MarshalYAML() (any, error) {
	return m.behavior()
}

// Unknown matcher fields fail closed even when parsing a served allowlist.
func (m *EnvMatcher) UnmarshalJSON(data []byte) error {
	if err := validateJSON(data); err != nil {
		return fmt.Errorf("invalid environment matcher")
	}
	var exact exactEnvMatcher
	var present presentEnvMatcher
	switch {
	case decodeEnvMatcher(data, &exact):
		m.matcher = exact
	case decodeEnvMatcher(data, &present):
		m.matcher = present
	default:
		return fmt.Errorf("environment matcher requires exactly one of exact or present: true")
	}
	return nil
}

func decodeEnvMatcher(data []byte, matcher envMatcherBehavior) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(matcher) == nil && matcher.valid()
}

// UnmarshalYAML takes an unquoted numeric exact value by its literal text, so
// `exact: 8080` pins "8080" rather than failing as a non-string.
func (m *EnvMatcher) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
		return fmt.Errorf("environment matcher requires exactly one of exact or present: true")
	}
	key, value := node.Content[0], node.Content[1]
	if key.Value == "exact" && value.Kind == yaml.ScalarNode {
		switch value.Tag {
		case "!!str", "!!int", "!!float":
			exact := exactEnvMatcher{Exact: &value.Value}
			if !exact.valid() {
				return fmt.Errorf("invalid environment matcher")
			}
			m.matcher = exact
			return nil
		}
		return fmt.Errorf("environment matcher exact value must be a string, got %s; quote it", value.Tag)
	}
	var present presentEnvMatcher
	if key.Value != "present" || value.Kind != yaml.ScalarNode || value.Tag != "!!bool" || value.Decode(&present.Present) != nil || !present.valid() {
		return fmt.Errorf("environment matcher requires exactly one of exact or present: true")
	}
	m.matcher = present
	return nil
}

type exactEnvMatcher struct {
	Exact *string `json:"exact" yaml:"exact"`
}

func (m exactEnvMatcher) valid() bool {
	return m.Exact != nil && validEnvValue(*m.Exact)
}
func (m exactEnvMatcher) matches(name, digest string) bool {
	return fingerprintEnvVariable(name, *m.Exact) == digest
}
func (m exactEnvMatcher) exactValue() (string, bool) {
	return *m.Exact, true
}

type presentEnvMatcher struct {
	Present bool `json:"present" yaml:"present"`
}

func (m presentEnvMatcher) valid() bool {
	return m.Present
}
func (presentEnvMatcher) matches(string, string) bool {
	return true
}
func (presentEnvMatcher) exactValue() (string, bool) {
	return "", false
}
