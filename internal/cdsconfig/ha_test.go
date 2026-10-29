package cdsconfig

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testHAWire() haWire {
	return haWire{
		Replicas: []string{
			"cds.acme.example",
			"10.0.0.7",
		},
		Voters: 3,
	}
}

func testHADocument(t *testing.T, operatorPEM, anchorPEM string) wire {
	t.Helper()
	document := testDocument(t, operatorPEM, anchorPEM)
	block := testHAWire()
	document.HA = &block
	return document
}

func TestParseReturnsTheReplicaSet(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	cfg, err := Parse(render(t, testHADocument(t, operatorPEM, anchorPEM)))
	if err != nil {
		t.Fatal(err)
	}
	ha := cfg.HA
	if ha == nil {
		t.Fatal("the document's ha block is not parsed")
	}
	if len(ha.Replicas) != 2 || ha.Replicas[0] != "cds.acme.example" || ha.Replicas[1] != "10.0.0.7" {
		t.Fatalf("replicas = %v", ha.Replicas)
	}
	if ha.Voters != 3 {
		t.Fatalf("voters = %d", ha.Voters)
	}
}

// Without an ha block a cluster's CDS runs as the singleton.
func TestParseLeavesTheSingletonWithoutAnHABlock(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	cfg, err := Parse(render(t, testDocument(t, operatorPEM, anchorPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HA != nil {
		t.Fatalf("ha = %+v, want the singleton", cfg.HA)
	}
}

func TestParseRefusesEachMalformedHAField(t *testing.T) {
	tests := []struct {
		name   string
		change func(*haWire)
		want   string
	}{
		{"no replica", func(h *haWire) { h.Replicas = nil }, "ha.replicas"},
		{"the same replica twice", func(h *haWire) { h.Replicas = []string{"cds.acme.example", "cds.acme.example"} }, "twice"},
		{"a replica port", func(h *haWire) { h.Replicas = []string{"cds.acme.example:8444"} }, "port"},
		{"a replica URL", func(h *haWire) { h.Replicas = []string{"https://cds.acme.example"} }, "ha.replicas"},
		{"a replica wildcard", func(h *haWire) { h.Replicas = []string{"*.acme.example"} }, "ha.replicas"},
		{"an IPv6 replica", func(h *haWire) { h.Replicas = []string{"fd00::7"} }, "ha.replicas"},
		{"an empty replica", func(h *haWire) { h.Replicas = []string{""} }, "ha.replicas"},
		{"no voter", func(h *haWire) { h.Voters = 0 }, "ha.voters"},
		{"an even voter count", func(h *haWire) { h.Voters = 4 }, "ha.voters"},
		{"more voters than seats", func(h *haWire) { h.Voters = maxVoters + 2 }, "ha.voters"},
	}
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := testHADocument(t, operatorPEM, anchorPEM)
			tc.change(document.HA)
			_, err := Parse(render(t, document))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// An unknown field inside the block is a setting CDS does not define.
func TestParseRefusesAnUndeclaredHAField(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	var document map[string]any
	if err := yaml.Unmarshal(render(t, testHADocument(t, operatorPEM, anchorPEM)), &document); err != nil {
		t.Fatal(err)
	}
	block, ok := document["ha"].(map[string]any)
	if !ok {
		t.Fatalf("the rendered ha block is %T", document["ha"])
	}
	block["seats"] = 5
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted a setting the ha block does not define")
	}
}

func TestFormatWritesAnHABlockParseAccepts(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	document.HA = &HA{
		Replicas: []string{"cds.acme.example"},
		Voters:   1,
	}
	data, err := Format(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Format wrote an ha block Parse refuses: %v", err)
	}
	if cfg.HA == nil || cfg.HA.Voters != 1 {
		t.Fatalf("ha = %+v, want the document's block", cfg.HA)
	}
}

// Format writes only what Parse accepts back, the ha block included.
func TestFormatRefusesAReplicaSetParseWouldRefuse(t *testing.T) {
	for name, change := range map[string]func(*HA){
		"an even voter count":   func(h *HA) { h.Voters = 4 },
		"no replica":            func(h *HA) { h.Replicas = nil },
		"a replica with a port": func(h *HA) { h.Replicas = []string{"cds.acme.example:8444"} },
	} {
		t.Run(name, func(t *testing.T) {
			_, operatorPEM := testKey(t)
			_, anchorPEM := testKey(t)
			document := testDocumentFor(t, operatorPEM, anchorPEM)
			document.HA = &HA{
				Replicas: []string{"cds.acme.example"},
				Voters:   1,
			}
			change(document.HA)
			if _, err := Format(document); err == nil {
				t.Fatal("Format wrote an ha block Parse refuses")
			}
		})
	}
}
