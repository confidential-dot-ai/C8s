package cdsconfig

import (
	"strings"
	"testing"
)

func TestObjectWALMeasuredConfigRoundTrip(t *testing.T) {
	_, op := testKey(t)
	_, anchor := testKey(t)
	d := testDocumentFor(t, op, anchor)
	d.HA = HA{Replicas: []string{"10.0.0.8"}, Voters: 3, ObjectWALPilot: &ObjectWALPilot{
		Bucket: "isolated-pilot", Region: "us-west-2", Prefix: "cds/trial-1", KeySHA256: strings.Repeat("ab", 32)}}
	data, err := Format(d)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HA.ObjectWALPilot == nil || *parsed.HA.ObjectWALPilot != *d.HA.ObjectWALPilot {
		t.Fatal("pilot selection was lost")
	}
	cluster, err := ReadCluster(data)
	if err != nil || !cluster.Replicated {
		t.Fatalf("client cluster parsing: %+v %v", cluster, err)
	}
}

func TestObjectWALConfigRejectsUnsafeOrSecretFields(t *testing.T) {
	good := ObjectWALPilot{Bucket: "pilot", Region: "us-west-2", Prefix: "cds/pilot", KeySHA256: strings.Repeat("ab", 32)}
	for name, change := range map[string]func(*ObjectWALPilot){
		"HTTP":         func(p *ObjectWALPilot) { p.Endpoint = "http://storage.example" },
		"userinfo":     func(p *ObjectWALPilot) { p.Endpoint = "https://key:secret@storage.example" },
		"query":        func(p *ObjectWALPilot) { p.Endpoint = "https://storage.example?credential=x" },
		"key":          func(p *ObjectWALPilot) { p.KeySHA256 = "plaintext-key" },
		"empty prefix": func(p *ObjectWALPilot) { p.Prefix = "" },
		"traversal":    func(p *ObjectWALPilot) { p.Prefix = "cds/../head" },
	} {
		t.Run(name, func(t *testing.T) {
			p := good
			change(&p)
			if p.Check() == nil {
				t.Fatal("accepted invalid pilot config")
			}
		})
	}
	_, op := testKey(t)
	_, anchor := testKey(t)
	d := testHADocument(t, op, anchor)
	d.HA.ObjectWALPilot = &good
	raw := string(render(t, d))
	raw = strings.Replace(raw, "objectWALPilot:", "objectWALPilot:\n        secretAccessKey: must-not-be-measured", 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("accepted credential in launch file")
	}
}
