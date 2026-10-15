package allowlist

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseMatchEnv(t *testing.T, variables string) EnvPolicy {
	t.Helper()
	policies, err := ParseEnvPoliciesJSON([]byte(`{"app":{"policy":"match","variables":` + variables + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	return policies["app"]
}

func TestEnvMatcherRoundTripAndReplacement(t *testing.T) {
	var matcher EnvMatcher
	for _, input := range []string{`{"exact":"production"}`, `{"present":true}`, `{"exact":""}`} {
		if err := json.Unmarshal([]byte(input), &matcher); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(matcher)
		if err != nil || string(encoded) != input {
			t.Fatalf("JSON roundtrip = %s, %v", encoded, err)
		}
		yamlData, err := yaml.Marshal(matcher)
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip EnvMatcher
		if err := yaml.Unmarshal(yamlData, &roundTrip); err != nil {
			t.Fatal(err)
		}
		encoded, err = json.Marshal(roundTrip)
		if err != nil || string(encoded) != input {
			t.Fatalf("YAML roundtrip = %s, %v", encoded, err)
		}
		if err := json.Unmarshal([]byte(`{"exact":"changed","present":true}`), &matcher); err == nil {
			t.Fatal("accepted mixed variants")
		}
		encoded, err = json.Marshal(matcher)
		if err != nil || string(encoded) != input {
			t.Fatal("failed decode changed the matcher")
		}
	}
	if _, err := json.Marshal(EnvMatcher{}); err == nil {
		t.Fatal("serialized an uninitialized matcher to JSON")
	}
	if _, err := yaml.Marshal(EnvMatcher{}); err == nil {
		t.Fatal("serialized an uninitialized matcher to YAML")
	}
}

func TestEnvMatcherRejectsMalformedPolicies(t *testing.T) {
	for _, matcher := range []string{
		`{}`, `null`, `[]`, `"exact"`, `{"regex":".*"}`, `{"exact":"x","present":true}`,
		`{"present":false}`, `{"present":null}`, `{"exact":null}`, `{"exact":1}`,
		`{"present":"true"}`, `{"exact":"x","unknown":true}`, `{"exact":"x","present":null}`,
		`{"exact":"x","exact":"y"}`, `{"exact":"\u0000"}`, `{"exact":"\ud800"}`,
	} {
		t.Run(matcher, func(t *testing.T) {
			env := `{"policy":"match","variables":{"A":` + matcher + `}}`
			var policy EnvPolicy
			// YAML takes an unquoted number by its literal text; JSON does not.
			if err := yaml.Unmarshal([]byte(env), &policy); err == nil && normalizeEnv(&policy) == nil && matcher != `{"exact":1}` {
				t.Fatal("YAML accepted malformed matcher")
			}
			if _, err := ParseEnvPoliciesJSON([]byte(`{"app":` + env + `}`)); err == nil {
				t.Fatal("accepted malformed matcher")
			}
			doc := []byte(`{"schema":"` + Schema + `","workloads":{"w":{"containers":[{"digest":"` + digestA + `","env":` + env + `}]}}}`)
			for _, parse := range []func([]byte) (*Allowlist, error){ParseJSON, ParseServedJSON} {
				if _, err := parse(doc); err == nil {
					t.Fatal("allowlist accepted malformed matcher")
				}
			}
		})
	}
	for _, env := range []string{
		`{"policy":"match"}`, `{"policy":"match","variables":null}`, `{"policy":"match","variables":{},"values":{}}`,
		`{"policy":"any","variables":{}}`, `{"policy":"deny","variables":{}}`, `{"policy":"exact","values":{},"variables":{}}`,
		`{"policy":"match","variables":{"":{"present":true}}}`, `{"policy":"match","variables":{"A=B":{"present":true}}}`,
	} {
		if _, err := ParseEnvPoliciesJSON([]byte(`{"app":` + env + `}`)); err == nil {
			t.Fatalf("accepted %s", env)
		}
	}
}

func TestEnvMatcherYAMLScalars(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"exact: 8080", `{"exact":"8080"}`},
		{"exact: 1.0", `{"exact":"1.0"}`},
		{"exact: 0x1F", `{"exact":"0x1F"}`},
		{`exact: "007"`, `{"exact":"007"}`},
		{"present: true", `{"present":true}`},
	} {
		var m EnvMatcher
		if err := yaml.Unmarshal([]byte(tc.input), &m); err != nil {
			t.Fatalf("yaml.Unmarshal(%q) error = %v", tc.input, err)
		}
		if got, err := json.Marshal(m); err != nil || string(got) != tc.want {
			t.Fatalf("yaml.Unmarshal(%q) = %s, %v, want %s", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{"exact: true", "exact: ~", "exact: [a]", "present: false", "present: yes", "other: x"} {
		var m EnvMatcher
		err := yaml.Unmarshal([]byte(input), &m)
		if err == nil {
			t.Fatalf("yaml.Unmarshal(%q) accepted", input)
		}
		if strings.HasPrefix(input, "exact: t") && !strings.Contains(err.Error(), "must be a string") {
			t.Fatalf("yaml.Unmarshal(%q) error = %v, want a type error", input, err)
		}
	}
}

func TestEnvMatcherYAMLAliases(t *testing.T) {
	var variables map[string]EnvMatcher
	input := "A: {exact: &mode production}\nB: {exact: *mode}\nC: {exact: &port 8080}\nD: {exact: *port}\nE: &matcher {present: true}\nF: *matcher\n"
	if err := yaml.Unmarshal([]byte(input), &variables); err != nil {
		t.Fatalf("yaml.Unmarshal(%q) error = %v", input, err)
	}
	p := EnvPolicy{Policy: PolicyMatch, Variables: variables}
	want := map[string]string{"A": "production", "B": "production", "C": "8080", "D": "8080"}
	if got := p.ExactValues(); !maps.Equal(got, want) {
		t.Fatalf("ExactValues() = %v, want %v", got, want)
	}
	matching, _ := ObserveEnv([]string{"A=production", "B=production", "C=8080", "D=8080", "E=x", "F=y"})
	if !p.admitsObservation(matching) {
		t.Fatal("aliased matchers rejected their resolved values")
	}
	changed, _ := ObserveEnv([]string{"A=production", "B=debug", "C=8080", "D=8080", "E=x", "F=y"})
	if p.admitsObservation(changed) {
		t.Fatal("aliased exact matcher admitted another value")
	}
}

func TestMixedEnvMatching(t *testing.T) {
	p := parseMatchEnv(t, `{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}`)
	for _, tc := range []struct {
		name    string
		entries []string
		want    bool
	}{
		{"match", []string{"MODE=production", "GPU_SERIAL=123"}, true},
		{"empty present", []string{"GPU_SERIAL=", "MODE=production"}, true},
		{"missing", []string{"MODE=production"}, false},
		{"extra", []string{"MODE=production", "GPU_SERIAL=123", "DEBUG=1"}, false},
		{"changed", []string{"MODE=debug", "GPU_SERIAL=123"}, false},
		{"wrong name", []string{"MODE=production", "OTHER=123"}, false},
		{"duplicate", []string{"MODE=production", "GPU_SERIAL=1", "GPU_SERIAL=2"}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := ObserveEnv(tc.entries)
			if got := p.admitsObservation(o); got != tc.want {
				t.Fatalf("admitted=%v, want %v", got, tc.want)
			}
		})
	}
	if p.admitsObservation(nil) {
		t.Fatal("admitted unavailable evidence")
	}
	emptyExact := parseMatchEnv(t, `{"MODE":{"exact":""}}`)
	o, _ := ObserveEnv([]string{"MODE="})
	if !emptyExact.admitsObservation(o) {
		t.Fatal("rejected exact empty value")
	}
}

func TestMatchEnvEvidenceValidation(t *testing.T) {
	p := parseMatchEnv(t, `{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}`)
	original, _ := ObserveEnv([]string{"MODE=production", "GPU_SERIAL=123"})
	mutations := map[string]func(*EnvObservation){
		"legacy": func(o *EnvObservation) {
			o.VariableDigests = nil
		},
		"format": func(o *EnvObservation) {
			o.Format = "future"
		},
		"aggregate": func(o *EnvObservation) {
			o.Digest = "bad"
		},
		"present digest": func(o *EnvObservation) {
			o.VariableDigests["GPU_SERIAL"] = "bad"
		},
		"uppercase": func(o *EnvObservation) {
			o.VariableDigests["MODE"] = strings.ToUpper(o.VariableDigests["MODE"])
		},
		"invalid name": func(o *EnvObservation) {
			delete(o.VariableDigests, "GPU_SERIAL")
			o.VariableDigests["A=B"] = original.VariableDigests["GPU_SERIAL"]
		},
		"substituted digest": func(o *EnvObservation) {
			o.VariableDigests["MODE"] = fingerprintEnvVariable("OTHER", "production")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			o := original.Clone()
			mutate(o)
			if p.admitsObservation(o) {
				t.Fatal("admitted invalid evidence")
			}
		})
	}
	if !p.admitsObservation(original) {
		t.Fatal("clone mutation changed source")
	}
	if got := original.VariableDigests["MODE"]; got != "506cbcdc2fff57ef78354d8e15175ad978197e41c3bb14f73bd75e9aa36697d0" {
		t.Fatalf("variable digest=%s", got)
	}
	for _, p := range []EnvPolicy{{Policy: PolicyExact, Values: map[string]string{"MODE": "production", "GPU_SERIAL": "123"}}, {Policy: PolicyDeny}} {
		o := original.Clone()
		if p.Policy == PolicyDeny {
			o, _ = ObserveEnv(nil)
		}
		if !p.admitsObservation(o) {
			t.Fatal("new observation rejected by existing policy")
		}
		o.VariableDigests = nil
		if !p.admitsObservation(o) {
			t.Fatal("legacy observation rejected by existing policy")
		}
	}
}

func TestEmptyMatchEnvRoundTrip(t *testing.T) {
	p := parseMatchEnv(t, `{}`)
	yamlData, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var yamlPolicy EnvPolicy
	if err := yaml.Unmarshal(yamlData, &yamlPolicy); err != nil {
		t.Fatal(err)
	}
	if err := normalizeEnv(&yamlPolicy); err != nil {
		t.Fatalf("YAML roundtrip: %v", err)
	}
	data, err := json.Marshal(map[string]EnvPolicy{"app": p})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := ParseEnvPoliciesJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	observation, _ := ObserveEnv(nil)
	data, err = json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EnvObservation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !policies["app"].admitsObservation(&decoded) {
		t.Fatal("known empty evidence lost in roundtrip")
	}
	decoded.VariableDigests = nil
	if policies["app"].admitsObservation(&decoded) {
		t.Fatal("missing variable evidence treated as empty")
	}
}

func TestMatchEnvHostIndependenceAndPinnedValues(t *testing.T) {
	for _, tc := range []struct {
		variables   string
		independent bool
	}{
		{`{}`, true}, {`{"MODE":{"exact":"production"}}`, true},
		{`{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}`, false},
	} {
		p := parseMatchEnv(t, tc.variables)
		constraint := newEnvConstraint(&p)
		if constraint.hostIndependent() != tc.independent {
			t.Fatalf("host independence: %s", tc.variables)
		}
		if constraint.isUnconstrained() {
			t.Fatal("match classified as unrestricted")
		}
		if _, pinned := p.ExactValues()["GPU_SERIAL"]; pinned {
			t.Fatal("present classified as pinned")
		}
		if strings.Contains(tc.variables, "MODE") {
			if value, pinned := p.ExactValues()["MODE"]; !pinned || value != "production" {
				t.Fatal("exact value not pinned")
			}
		}
	}
}

func TestMatchEnvCanonicalOrder(t *testing.T) {
	container := func(value string) string {
		return `{"digest":"` + digestA + `","env":{"policy":"match","variables":{"MODE":{"exact":"` + value + `"},"GPU_SERIAL":{"present":true}}}}`
	}
	canonical := func(containers string) []byte {
		al := mustParse(t, `{"schema":"`+Schema+`","workloads":{"w":{"containers":[`+containers+`]}}}`)
		data, err := al.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	a, b := container("a"), container("b")
	if !bytes.Equal(canonical(a+","+b), canonical(b+","+a)) {
		t.Fatal("container order changed canonical policy")
	}
	if bytes.Equal(canonical(a), canonical(b)) {
		t.Fatal("different matchers have same canonical policy")
	}
}

func TestEnvPolicyCovers(t *testing.T) {
	present := parseMatchEnv(t, `{"MODE":{"present":true}}`)
	exactMatch := parseMatchEnv(t, `{"MODE":{"exact":"production"}}`)
	exact := EnvPolicy{Policy: PolicyExact, Values: map[string]string{"MODE": "production"}}
	empty := parseMatchEnv(t, `{}`)
	for _, tc := range []struct {
		name         string
		wide, narrow EnvPolicy
		want         bool
	}{
		{"any covers exact", EnvPolicy{Policy: PolicyAny}, exact, true},
		{"present covers exact matcher", present, exactMatch, true},
		{"match does not cover exact policy", present, exact, false},
		{"exact matcher does not cover present", exactMatch, present, false},
		{"exact policy covers equal matcher", exact, exactMatch, true},
		{"empty match does not cover deny", empty, EnvPolicy{Policy: PolicyDeny}, false},
		{"other names", present, parseMatchEnv(t, `{"OTHER":{"present":true}}`), false},
		{"constrained does not cover any", present, EnvPolicy{Policy: PolicyAny}, false},
	} {
		if got := tc.wide.Covers(tc.narrow); got != tc.want {
			t.Errorf("%s: Covers = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Exact and deny admit aggregate-only evidence from pre-upgrade enforcers; match
// refuses it, so a match policy cannot cover them.
func TestMatchEnvDoesNotCoverAggregateOnlyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wide, narrow EnvPolicy
		values       map[string]string
	}{
		{"exact", parseMatchEnv(t, `{"MODE":{"present":true}}`), EnvPolicy{Policy: PolicyExact, Values: map[string]string{"MODE": "production"}}, map[string]string{"MODE": "production"}},
		{"deny", parseMatchEnv(t, `{}`), EnvPolicy{Policy: PolicyDeny}, nil},
	} {
		aggregateOnly := fingerprintEnv(tc.values)
		if !tc.narrow.admitsObservation(aggregateOnly) || tc.wide.admitsObservation(aggregateOnly) {
			t.Fatalf("%s: aggregate-only evidence must be admitted only by the narrow policy", tc.name)
		}
		if tc.wide.Covers(tc.narrow) {
			t.Errorf("%s: match Covers a policy admitting evidence it refuses", tc.name)
		}
	}
}

// The documented env examples are what readers pass to derive --env-file.
func TestDocumentedEnvExamplesParse(t *testing.T) {
	doc, err := os.ReadFile("../../docs/allowlist-and-capabilities.md")
	if err != nil {
		t.Fatal(err)
	}
	examples := regexp.MustCompile("(?m)^```json\n\"env\":(.*)\n```").FindAllSubmatch(doc, -1)
	if len(examples) < 2 {
		t.Fatalf("found %d env examples, want at least 2", len(examples))
	}
	for _, example := range examples {
		if _, err := ParseEnvPoliciesJSON([]byte(`{"app":` + string(example[1]) + `}`)); err != nil {
			t.Errorf("ParseEnvPoliciesJSON(%s) error = %v", example[1], err)
		}
	}
}

func TestObserveEnvBoundsVariableEvidence(t *testing.T) {
	numbered := func(n int, prefix string) []string {
		env := make([]string, n)
		for i := range env {
			env[i] = prefix + strconv.Itoa(i) + "=v"
		}
		return env
	}
	for _, tc := range []struct {
		name string
		env  []string
		want bool
	}{
		{"at variable cap", numbered(maxVariableEvidence, "V"), true},
		{"over variable cap", numbered(maxVariableEvidence+1, "V"), false},
		{"at name bytes cap", []string{strings.Repeat("N", maxVariableEvidenceNameBytes) + "=v"}, true},
		{"over name bytes cap", numbered(2, strings.Repeat("N", maxVariableEvidenceNameBytes/2)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ObserveEnv(tc.env)
			if err != nil {
				t.Fatal(err)
			}
			if got := o.VariableDigests != nil; got != tc.want {
				t.Fatalf("ObserveEnv(%d variables) has variable digests = %t, want %t", len(tc.env), got, tc.want)
			}
			if !o.Valid() {
				t.Fatal("observation invalid")
			}
			values := make(map[string]string, len(tc.env))
			for _, entry := range tc.env {
				name, value, _ := strings.Cut(entry, "=")
				values[name] = value
			}
			if !(EnvPolicy{Policy: PolicyExact, Values: values}).admitsObservation(o) {
				t.Fatal("exact policy rejected the observation")
			}
			variables := make(map[string]map[string]string, len(values))
			for name, value := range values {
				variables[name] = map[string]string{"exact": value}
			}
			encoded, _ := json.Marshal(map[string]any{"app": map[string]any{"policy": PolicyMatch, "variables": variables}})
			policies, err := ParseEnvPoliciesJSON(encoded)
			if !tc.want {
				if err == nil || !strings.Contains(err.Error(), "at most") {
					t.Fatalf("ParseEnvPoliciesJSON(oversized match) error = %v, want the evidence limit", err)
				}
				return
			}
			if err != nil || !policies["app"].admitsObservation(o) {
				t.Fatalf("match policy at the limit: error %v, admitted false", err)
			}
		})
	}
}
