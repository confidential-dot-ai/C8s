package allowlist

import (
	"fmt"
	"maps"
	"reflect"
	"regexp"
)

func (p EnvPolicy) MarshalYAML() (any, error) {
	type wirePolicy struct {
		Policy       string                 `yaml:"policy"`
		Values       map[string]string      `yaml:"values,omitempty"`
		Variables    *map[string]EnvMatcher `yaml:"variables,omitempty"`
		ServiceLinks bool                   `yaml:"serviceLinks,omitempty"`
	}
	wire := wirePolicy{Policy: p.Policy, Values: p.Values, ServiceLinks: p.ServiceLinks}
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
	if p.ServiceLinks && p.Policy != PolicyMatch {
		return nil, fmt.Errorf("serviceLinks needs a match env policy")
	}
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
		policy, err := newMatchEnvPolicy(p.Variables)
		policy.serviceLinks = p.ServiceLinks
		return policy, err
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

// Covers reports whether p admits every environment narrow admits: p is any,
// both are equal, or both constrain the same names and each of p's matchers
// accepts every value narrow's does. A match p never covers an exact or deny
// narrow, which also admits aggregate-only evidence that match refuses.
func (p EnvPolicy) Covers(narrow EnvPolicy) bool {
	if reflect.DeepEqual(p, narrow) {
		return true
	}
	wide, err := p.behavior()
	if err != nil {
		return false
	}
	if wide.isUnconstrained() {
		return true
	}
	narrowBehavior, err := narrow.behavior()
	if err != nil {
		return false
	}
	if _, perVariable := wide.(matchEnvPolicy); perVariable {
		if _, narrowPerVariable := narrowBehavior.(matchEnvPolicy); !narrowPerVariable {
			return false
		}
	}
	wideVariables, narrowVariables := variableMatchers(wide), variableMatchers(narrowBehavior)
	if wideVariables == nil || narrowVariables == nil || len(wideVariables) != len(narrowVariables) {
		return false
	}
	for name, matcher := range wideVariables {
		n, listed := narrowVariables[name]
		if !listed || !matcher.covers(n) {
			return false
		}
	}
	return true
}

// variableMatchers views a constrained policy as one matcher per variable, or
// nil for any.
func variableMatchers(b envPolicyBehavior) map[string]envMatcherBehavior {
	switch p := b.(type) {
	case matchEnvPolicy:
		return p.variables
	case exactEnvPolicy:
		out := make(map[string]envMatcherBehavior, len(p.values))
		for name, value := range p.values {
			out[name] = exactEnvMatcher{Exact: &value}
		}
		return out
	case denyEnvPolicy:
		return map[string]envMatcherBehavior{}
	}
	return nil
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
	return o.Valid() && o.Digest == fingerprintEnv(nil).Digest
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
	return o.Valid() && o.Digest == fingerprintEnv(p.values).Digest
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

type matchEnvPolicy struct {
	variables    map[string]envMatcherBehavior
	serviceLinks bool
}

func newMatchEnvPolicy(variables map[string]EnvMatcher) (matchEnvPolicy, error) {
	p := matchEnvPolicy{variables: make(map[string]envMatcherBehavior, len(variables))}
	if err := checkVariableEvidenceLimits(maps.Keys(variables)); err != nil {
		return p, err
	}
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
	if !o.Valid() || o.VariableDigests == nil {
		return false
	}
	for name := range o.VariableDigests {
		if _, listed := p.variables[name]; !listed && !(p.serviceLinks && ServiceLinkName(name)) {
			return false
		}
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

// serviceLinkPattern is the shape of the variables the kubelet derives from a
// Service (k8s.io/kubernetes pkg/kubelet/envvars): <NAME>_SERVICE_HOST,
// <NAME>_SERVICE_PORT[_<PORT NAME>], <NAME>_PORT and
// <NAME>_PORT_<port>_<PROTOCOL>[_PROTO|_PORT|_ADDR].
var serviceLinkPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*_(SERVICE_HOST|SERVICE_PORT(_[A-Z0-9_]+)?|PORT(_[0-9]+_(TCP|UDP|SCTP)(_(PROTO|PORT|ADDR))?)?)$`)

// ServiceLinkName reports whether name has the shape of a kubelet service
// link variable.
func ServiceLinkName(name string) bool {
	return serviceLinkPattern.MatchString(name)
}
