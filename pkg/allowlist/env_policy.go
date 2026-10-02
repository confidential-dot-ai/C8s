package allowlist

import (
	"fmt"
	"maps"
)

func (p EnvPolicy) MarshalYAML() (any, error) {
	type wirePolicy struct {
		Policy    string                 `yaml:"policy"`
		Values    map[string]string      `yaml:"values,omitempty"`
		Variables *map[string]EnvMatcher `yaml:"variables,omitempty"`
	}
	wire := wirePolicy{Policy: p.Policy, Values: p.Values}
	if p.Variables != nil {
		wire.Variables = &p.Variables
	}
	return wire, nil
}

type envPolicyBehavior interface {
	admits(*EnvObservation) bool
	exactValues() map[string]string
	hostIndependent() bool
	isUnconstrained() bool
}

func (p EnvPolicy) behavior() (envPolicyBehavior, error) {
	switch p.Policy {
	case PolicyAny, "", PolicyDeny:
		if p.Values != nil || p.Variables != nil {
			return nil, fmt.Errorf("%s env policy takes no values or variables", p.Policy)
		}
		if p.Policy == PolicyDeny {
			return denyEnvPolicy{}, nil
		}
		return anyEnvPolicy{}, nil
	case PolicyExact:
		if p.Values == nil || p.Variables != nil {
			return nil, fmt.Errorf("exact env requires values and takes no variables")
		}
		for name, value := range p.Values {
			if !validEnvPair(name, value) {
				return nil, fmt.Errorf("invalid environment name or value")
			}
		}
		return exactEnvPolicy{values: p.Values}, nil
	case PolicyMatch:
		if p.Variables == nil || p.Values != nil {
			return nil, fmt.Errorf("match env requires variables and takes no values")
		}
		return newMatchEnvPolicy(p.Variables)
	default:
		return nil, fmt.Errorf("unknown env policy %q (want deny, any, exact, or match)", p.Policy)
	}
}

func normalizeEnv(p *EnvPolicy) error {
	_, err := newEnvConstraint(p).normalize()
	return err
}

// ExactValues returns the pinned values for operator-side lint checks.
func (p EnvPolicy) ExactValues() map[string]string {
	behavior, err := p.behavior()
	if err != nil {
		return nil
	}
	return behavior.exactValues()
}

type anyEnvPolicy struct{}

func (anyEnvPolicy) admits(*EnvObservation) bool {
	return true
}
func (anyEnvPolicy) exactValues() map[string]string {
	return nil
}
func (anyEnvPolicy) hostIndependent() bool {
	return false
}
func (anyEnvPolicy) isUnconstrained() bool {
	return true
}

type denyEnvPolicy struct{}

func (denyEnvPolicy) admits(o *EnvObservation) bool {
	return o.WellFormed() && o.Digest == fingerprintEnv(nil).Digest
}
func (denyEnvPolicy) exactValues() map[string]string {
	return nil
}
func (denyEnvPolicy) hostIndependent() bool {
	return true
}
func (denyEnvPolicy) isUnconstrained() bool {
	return false
}

type exactEnvPolicy struct{ values map[string]string }

func (p exactEnvPolicy) admits(o *EnvObservation) bool {
	return o.WellFormed() && o.Digest == fingerprintEnv(p.values).Digest
}
func (p exactEnvPolicy) exactValues() map[string]string {
	return maps.Clone(p.values)
}
func (exactEnvPolicy) hostIndependent() bool {
	return true
}
func (exactEnvPolicy) isUnconstrained() bool {
	return false
}

type matchEnvPolicy struct{ variables map[string]envMatcherBehavior }

func newMatchEnvPolicy(variables map[string]EnvMatcher) (matchEnvPolicy, error) {
	p := matchEnvPolicy{variables: make(map[string]envMatcherBehavior, len(variables))}
	for name, matcher := range variables {
		if !validEnvName(name) {
			return p, fmt.Errorf("invalid environment name")
		}
		behavior, err := matcher.behavior()
		if err != nil {
			return p, err
		}
		p.variables[name] = behavior
	}
	return p, nil
}

func (p matchEnvPolicy) admits(o *EnvObservation) bool {
	if !o.WellFormed() || o.VariableDigests == nil || len(o.VariableDigests) != len(p.variables) {
		return false
	}
	for name, matcher := range p.variables {
		digest, present := o.VariableDigests[name]
		if !present || !matcher.matches(name, digest) {
			return false
		}
	}
	return true
}
func (p matchEnvPolicy) exactValues() map[string]string {
	values := make(map[string]string)
	for name, matcher := range p.variables {
		if value, pinned := matcher.exactValue(); pinned {
			values[name] = value
		}
	}
	return values
}
func (p matchEnvPolicy) hostIndependent() bool {
	for _, matcher := range p.variables {
		if _, exact := matcher.exactValue(); !exact {
			return false
		}
	}
	return true
}
func (matchEnvPolicy) isUnconstrained() bool {
	return false
}
