package allowlist

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEnvironmentValueMatching(t *testing.T) {
	exact := EnvPolicy{Policy: PolicyExact, Values: map[string]string{"A": "one=two", "B": ""}}
	for _, tc := range []struct {
		name string
		env  []string
		want bool
	}{
		{"exact", []string{"A=one=two", "B="}, true},
		{"reordered", []string{"B=", "A=one=two"}, true},
		{"missing", []string{"A=one=two"}, false},
		{"changed", []string{"A=bad", "B="}, false},
		{"extra", []string{"A=one=two", "B=", "C=x"}, false},
		{"duplicate", []string{"A=bad", "A=one=two", "B="}, false},
		{"malformed", []string{"A=one=two", "B=", "bad"}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := ObserveEnv(tc.env)
			if got := exact.admitsObservation(o); got != tc.want {
				t.Fatalf("match=%v want %v", got, tc.want)
			}
		})
	}
	empty, _ := ObserveEnv(nil)
	for _, p := range []EnvPolicy{{Policy: PolicyDeny}, exact} {
		if p.admitsObservation(nil) {
			t.Fatal("unknown evidence admitted")
		}
	}
	if !(EnvPolicy{Policy: PolicyDeny}).admitsObservation(empty) {
		t.Fatal("observed empty denied")
	}
	if !(EnvPolicy{Policy: PolicyAny}).admitsObservation(nil) {
		t.Fatal("any requires evidence")
	}
	invalid := *empty
	invalid.Format = "future"
	if (EnvPolicy{Policy: PolicyDeny}).admitsObservation(&invalid) {
		t.Fatal("unknown format admitted")
	}
	for _, e := range []string{"=value", "A\x00=x", "A=x\x00", "A=\xff"} {
		if _, err := ObserveEnv([]string{e}); err == nil {
			t.Fatal("malformed env accepted")
		}
	}
}

func TestEnvEncodingAndPrivacy(t *testing.T) {
	o, _ := ObserveEnv([]string{"B=", "A=one=two"})
	// Independent fixed vector pins domain, encoding, and hash across producers.
	if o.Digest != "2ca95b966d05cb4c862d7900e3a342caf052531fe89ba5f1a8e4c806d770eb73" {
		t.Fatalf("fingerprint %s", o.Digest)
	}
	b, _ := json.Marshal(o)
	if bytes.Contains(b, []byte("one=two")) {
		t.Fatal("raw value disclosed")
	}
}

func TestEnvPolicyParsing(t *testing.T) {
	doc := func(schema, env string) []byte {
		return []byte(`{"schema":"` + schema + `","workloads":{"w":{"containers":[{"digest":"` + digestA + `","env":` + env + `}]}}}`)
	}
	for _, tc := range []struct {
		schema, env string
		want        bool
	}{
		{Schema, `{"policy":"exact","names":["A"]}`, false},
		{Schema, `{"policy":"exact","values":{"A":"x"}}`, true},
		{Schema, `{"policy":"exact","values":{}}`, true},
		{Schema, `{"policy":"deny"}`, true},
		{Schema, `{}`, true},
		{Schema, `{"policy":"exact","values":{"A":"x","A":"y"}}`, false},
		{Schema, `{"policy":"any","values":{"A":"x"}}`, false},
	} {
		for _, parse := range []func([]byte) (*Allowlist, error){ParseJSON, ParseServedJSON} {
			al, err := parse(doc(tc.schema, tc.env))
			if (err == nil) != tc.want {
				t.Fatalf("%s %s: %v", tc.schema, tc.env, err)
			}
			if err == nil && al.Schema != tc.schema {
				t.Fatal("schema changed")
			}
		}
	}
	if _, err := ParseJSON(append(doc(Schema, `{"policy":"any"}`), []byte(`{}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestEnvDistinguishesWorkloadsAndHistory(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
 "a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},"env":{"policy":"exact","values":{"MODE":"a"}}}]},
 "b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"},"env":{"policy":"exact","values":{"MODE":"b"}}}]}}}`)
	a, _ := ObserveEnv([]string{"MODE=a"})
	b, _ := ObserveEnv([]string{"MODE=b"})
	running := []RunningContainer{{Digest: digestA, Env: a, Mounts: []ObservedMount{}}}
	if name, _, err := al.MatchWorkload(running); err != nil || name != "a" {
		t.Fatalf("match %q %v", name, err)
	}
	running = append(running, RunningContainer{Digest: digestA, Env: b, Mounts: []ObservedMount{}})
	if _, _, err := al.MatchWorkload(running); err == nil {
		t.Fatal("foreign historical env ignored")
	}
	running = running[:1]
	running[0].Env = nil
	if _, _, err := al.MatchWorkload(running); err == nil {
		t.Fatal("old inventory matched")
	}
}

func TestEnvCanonicalOrder(t *testing.T) {
	c := `{"digest":"` + digestA + `","env":{"policy":"exact","values":{"A":"VALUE"}}}`
	a, b := strings.ReplaceAll(c, "VALUE", "a"), strings.ReplaceAll(c, "VALUE", "b")
	parse := func(cs string) []byte {
		al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[`+cs+`]}}}`)
		out, _ := al.Canonical()
		return out
	}
	if !bytes.Equal(parse(a+","+b), parse(b+","+a)) {
		t.Fatal("env policy order changes canonical bytes")
	}
}

func TestEnvUnicodeAndDuplicatePolicyKeys(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{`"\ud800"`, false}, {`"\udfff"`, false}, {`"\ud800x"`, false},
		{`"\ud83d\ude00"`, true}, {`"\\ud800"`, true}, {`"�"`, true},
	} {
		_, err := ParseEnvPoliciesJSON([]byte(`{"app":{"policy":"exact","values":{"A":` + tc.value + `}}}`))
		if (err == nil) != tc.want {
			t.Fatalf("%s: %v", tc.value, err)
		}
	}
	for _, data := range []string{
		`{"app":{"policy":"deny"},"app":{"policy":"any"}}`,
		`{"app":{"policy":"deny","policy":"any"}}`,
		`{"app":{"policy":"exact","values":{"A":"one","A":"two"}}}`,
	} {
		if _, err := ParseEnvPoliciesJSON([]byte(data)); err == nil {
			t.Fatal("duplicate policy key accepted")
		}
	}
}

func TestObserveLaunchEnvResolvesDuplicatesLikeTheRuntime(t *testing.T) {
	// runc keeps the last value for a repeated name (libcontainer, prepareEnv),
	// which is how a CDI edit that sets a name the image already set resolves.
	obs, err := ObserveLaunchEnv([]string{"PATH=/usr/bin", "NVIDIA_VISIBLE_DEVICES=all", "NVIDIA_VISIBLE_DEVICES=void"})
	if err != nil {
		t.Fatalf("duplicate name: %v", err)
	}
	want, err := ObserveEnv([]string{"PATH=/usr/bin", "NVIDIA_VISIBLE_DEVICES=void"})
	if err != nil {
		t.Fatal(err)
	}
	if *obs != *want {
		t.Error("observation does not describe the environment the runtime execs")
	}
}

func TestObserveLaunchEnvKeepsRejectingMalformedEntries(t *testing.T) {
	for _, bad := range [][]string{
		{"PATH=/usr/bin", "NOEQUALS"},
		{"PATH=/usr/bin", "=novalue"},
		{"PATH=/usr/bin", "NUL\x00NAME=x"},
	} {
		if _, err := ObserveLaunchEnv(bad); err == nil {
			t.Errorf("malformed entry %q was accepted", bad)
		}
	}
}

func TestObserveLaunchEnvMatchesObserveEnvWithoutDuplicates(t *testing.T) {
	entries := []string{"PATH=/usr/bin", "MODE=production"}
	a, err := ObserveLaunchEnv(entries)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ObserveEnv(entries)
	if err != nil {
		t.Fatal(err)
	}
	if *a != *b {
		t.Error("duplicate-free environments must observe identically")
	}
}
