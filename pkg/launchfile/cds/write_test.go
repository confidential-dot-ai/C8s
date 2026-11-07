package cds

import (
	"bytes"
	"testing"
)

func testDocumentFor(
	t *testing.T,
	operatorPEM string,
	anchorPEM string,
) Document {
	t.Helper()
	return Document{
		ClusterID:          "acme-prod",
		OperatorPublicKeys: []byte(operatorPEM),
		Workloads:          []byte(testWorkloads),
		Nodes:              []byte(testNodePins(t, anchorPEM)),
		NodeCIDRs:          []string{"10.0.0.0/24"},
		LeafDNSNames:       []string{"cds.acme.example"},
		LeafDNSPatterns:    []string{testServicePattern},
	}
}

func TestFormatWritesWhatParseReads(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	data, err := Format(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Format wrote a config Parse refuses: %v", err)
	}
	if cfg.ClusterID != document.ClusterID {
		t.Fatalf("clusterID = %q", cfg.ClusterID)
	}
	if !bytes.Equal(cfg.OperatorPublicKeys, document.OperatorPublicKeys) {
		t.Fatal("operator key bundle is not the bytes written")
	}
	if !bytes.Equal(cfg.Workloads, document.Workloads) {
		t.Fatal("workloads are not the bytes written")
	}
	if len(cfg.Nodes.Images) != 1 || !bytes.Equal(cfg.Nodes.Images[0].Anchor, []byte(anchorPEM)) {
		t.Fatalf("node pins = %+v", cfg.Nodes)
	}
	if len(cfg.NodeCIDRs) != 1 || cfg.NodeCIDRs[0].String() != "10.0.0.0/24" {
		t.Fatalf("node subnets = %v", cfg.NodeCIDRs)
	}
	if len(cfg.DNSSANPatterns) != 2 || !cfg.DNSSANPatterns[0].MatchString("mesh.c8s.svc") {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}

// The writer states the schema version, so a caller cannot write a document
// under a version CDS does not parse.
func TestFormatRefusesADocumentParseWouldRefuse(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	document.NodeCIDRs = []string{"0.0.0.0/0"}
	if _, err := Format(document); err == nil {
		t.Fatal("Format wrote a default route as a node subnet")
	}
}

func TestCheckNodeSubnetsRefusesClusterRanges(t *testing.T) {
	tests := []struct {
		name    string
		nodes   []string
		cluster []string
		refused bool
	}{
		{name: "disjoint", nodes: []string{"10.0.0.0/24"}, cluster: []string{"10.42.0.0/16", "10.43.0.0/16"}},
		{name: "node subnet holds the pod range", nodes: []string{"10.0.0.0/8"}, cluster: []string{"10.42.0.0/16"}, refused: true},
		{name: "node subnet inside the pod range", nodes: []string{"10.42.1.0/24"}, cluster: []string{"10.42.0.0/16"}, refused: true},
		{name: "node subnet is the service range", nodes: []string{"10.43.0.0/16"}, cluster: []string{"10.43.0.0/16"}, refused: true},
		{name: "malformed range", nodes: []string{"10.0.0.0/24"}, cluster: []string{"10.42.0.0"}, refused: true},
		{name: "no cluster range to check against", nodes: []string{"10.0.0.0/24"}, refused: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckNodeSubnets(tc.nodes, tc.cluster)
			if (err != nil) != tc.refused {
				t.Fatalf("got %v, want refused=%v", err, tc.refused)
			}
		})
	}
}

// The leaf DNS lists are optional: a CDS that issues no literal name writes
// none.
func TestFormatWritesAnAbsentLeafNameList(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	document.LeafDNSNames = nil
	data, err := Format(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNSSANPatterns) != 1 {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}
