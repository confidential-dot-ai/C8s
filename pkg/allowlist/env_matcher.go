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

func (m *EnvMatcher) UnmarshalYAML(node *yaml.Node) error {
	var fields map[string]any
	if err := node.Decode(&fields); err != nil {
		return fmt.Errorf("invalid environment matcher")
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("invalid environment matcher")
	}
	return m.UnmarshalJSON(data)
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
