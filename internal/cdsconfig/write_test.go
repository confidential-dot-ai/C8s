package cdsconfig

import (
	"bytes"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func testDocumentFor(t *testing.T, operatorPEM string, anchorPEM string) Document {
	t.Helper()
	workloads, err := allowlist.ParseJSON([]byte(testWorkloads))
	if err != nil {
		t.Fatal(err)
	}
	operatorKeys, err := operatorauth.ParseKeyBundle([]byte(operatorPEM))
	if err != nil {
		t.Fatal(err)
	}
	return Document{
		ClusterID:       "acme-prod",
		OperatorKeys:    operatorKeys,
		Workloads:       workloads,
		Nodes:           []byte(testNodePins(t, anchorPEM)),
		NodeCIDRs:       []string{"10.0.0.0/24"},
		LeafDNSNames:    []string{"cds.acme.example"},
		LeafDNSPatterns: []string{testServicePattern},
	}
}

func TestFormatWritesWhatCDSParses(t *testing.T) {
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
	if !bytes.Equal(cfg.OperatorKeys.PEM(), document.OperatorKeys.PEM()) {
		t.Fatal("operator key bundle is not the bytes written")
	}
	if _, ok := cfg.Workloads.Workloads["c8s-router"]; !ok {
		t.Fatalf("workloads = %v", cfg.Workloads.Workloads)
	}
	if len(cfg.Nodes.Images) != 1 || !bytes.Equal(cfg.Nodes.Images[0].Anchor, []byte(anchorPEM)) {
		t.Fatalf("node pins = %+v", cfg.Nodes)
	}
	if !cfg.NodeCIDRs.Contains("10.0.0.5") {
		t.Fatalf("node subnets = %v", cfg.NodeCIDRs)
	}
	if len(cfg.DNSSANPatterns) != 2 || !cfg.DNSSANPatterns[0].MatchString("mesh.c8s.svc") {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}

// The writer states the schema version, so a caller cannot write a document
// under a version CDS does not parse.
func TestFormatRefusesADocumentCDSWouldRefuse(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	document.NodeCIDRs = []string{"0.0.0.0/0"}
	if _, err := Format(document); err == nil {
		t.Fatal("Format wrote a default route as a node subnet")
	}
}

func TestMergeWorkloadsKeepsComponentEntries(t *testing.T) {
	const tenant = `{"schema":"c8s.allowlist/v1","workloads":{"tenant-app":{"containers":[{"digest":"sha256:` +
		"2222222222222222222222222222222222222222222222222222222222222222" + `"}]}}}`
	merged, err := MergeWorkloads([]byte(testWorkloads), []byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := merged.Workloads["c8s-router"]; !ok {
		t.Fatalf("merged lost the component entries: %v", merged.Workloads)
	}
	if _, ok := merged.Workloads["tenant-app"]; !ok {
		t.Fatalf("merged lost the tenant entries: %v", merged.Workloads)
	}
	if _, err := MergeWorkloads([]byte(testWorkloads), []byte(testWorkloads)); err == nil {
		t.Fatal("a tenant document replaced a component entry")
	}
	if _, err := MergeWorkloads([]byte(testWorkloads), []byte{}); err == nil {
		t.Fatal("an empty tenant document parsed as no tenant workloads")
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
