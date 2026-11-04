package cdsconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

const testWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"c8s-router":{"containers":[{"digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `"}]}}}`

const testServicePattern = cmdsutil.ServiceDNSSANPattern

func testKey(t *testing.T) (*ecdsa.PublicKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return &key.PublicKey, string(pem.EncodeToMemory(block))
}

// testNodePins anchors the node pins to a launch key of their own: the
// operator key authorizes writes, a launch key says which node booted.
func testNodePins(t *testing.T, anchor string) string {
	t.Helper()
	pins, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:   "server",
			Digest: bytes.Repeat([]byte{0x11}, refvalues.DigestSize),
			Anchor: []byte(anchor),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(pins)
}

func testDocument(t *testing.T, operatorPEM, anchorPEM string) wire {
	t.Helper()
	return wire{
		SchemaVersion:      SchemaVersion,
		ClusterID:          "acme-prod",
		OperatorPublicKeys: operatorPEM,
		Workloads:          testWorkloads,
		Nodes:              testNodePins(t, anchorPEM),
		NodeCIDRs:          []string{"10.0.0.0/24"},
		LeafDNSNames:       []string{"cds.acme.example"},
		LeafDNSPatterns:    []string{testServicePattern},
	}
}

func render(t *testing.T, document wire) []byte {
	t.Helper()
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseReturnsEverySettingParsed(t *testing.T) {
	operator, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	cfg, err := Parse(render(t, testDocument(t, operatorPEM, anchorPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClusterID != "acme-prod" {
		t.Fatalf("clusterID = %q", cfg.ClusterID)
	}
	if keys := cfg.OperatorKeys.Keys(); len(keys) != 1 || !keys[0].Equal(operator) {
		t.Fatalf("operator keys = %v", keys)
	}
	if string(cfg.OperatorKeys.PEM()) != operatorPEM {
		t.Fatal("operator key bundle is not the document's bytes")
	}
	if _, ok := cfg.Workloads.Workloads["c8s-router"]; !ok {
		t.Fatalf("workloads = %v", cfg.Workloads.Workloads)
	}
	if cfg.Nodes.Family != teetypes.FamilySNP || len(cfg.Nodes.Images) != 1 {
		t.Fatalf("node pins = %+v", cfg.Nodes)
	}
	if !bytes.Equal(cfg.Nodes.Images[0].Anchor, []byte(anchorPEM)) {
		t.Fatal("node pin lost its launch-key anchor")
	}
	if !cfg.NodeCIDRs.Contains("10.0.0.5") || cfg.NodeCIDRs.Contains("10.1.0.5") {
		t.Fatalf("node subnets = %v", cfg.NodeCIDRs)
	}
	if len(cfg.DNSSANPatterns) != 2 {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
	if !cfg.DNSSANPatterns[0].MatchString("mesh.c8s.svc") {
		t.Fatal("lost the document's service DNS pattern")
	}
	// A leaf name is a literal identity: it matches whole, or not at all.
	if !cfg.DNSSANPatterns[1].MatchString("cds.acme.example") || cfg.DNSSANPatterns[1].MatchString("evil.cds.acme.example") {
		t.Fatal("leaf name is not matched as a whole name")
	}
}

func TestParseRefusesEachMalformedField(t *testing.T) {
	tests := []struct {
		name   string
		change func(*wire)
		want   string
	}{
		{"schema", func(w *wire) { w.SchemaVersion = "c8s-cds/v2" }, "schemaVersion"},
		{"cluster label", func(w *wire) { w.ClusterID = "Acme_Prod" }, "clusterID"},
		{"no operator keys", func(w *wire) { w.OperatorPublicKeys = "" }, "operatorPublicKeys"},
		{"operator key is not a key", func(w *wire) { w.OperatorPublicKeys = "not a key" }, "operatorPublicKeys"},
		{"no workloads", func(w *wire) { w.Workloads = "" }, "workloads"},
		{"no node pins", func(w *wire) { w.Nodes = "" }, "nodes"},
		{"node pins pin nothing", func(w *wire) {
			w.Nodes = `{"schema_version":"1","tee":"sev-snp","measurements":[]}`
		}, "nodes"},
		{"no node subnet", func(w *wire) { w.NodeCIDRs = nil }, "nodeCIDRs"},
		{"default route", func(w *wire) { w.NodeCIDRs = []string{"0.0.0.0/0"} }, "nodeCIDRs"},
		{"subnet host bits", func(w *wire) { w.NodeCIDRs = []string{"10.0.0.5/24"} }, "nodeCIDRs"},
		{"bare node address", func(w *wire) { w.NodeCIDRs = []string{"10.0.0.5"} }, "nodeCIDRs"},
		{"leaf address", func(w *wire) { w.LeafDNSNames = []string{"10.0.0.5"} }, "leafDNSNames"},
		{"leaf wildcard", func(w *wire) { w.LeafDNSNames = []string{"*.acme.example"} }, "leafDNSNames"},
		{"uncompilable pattern", func(w *wire) { w.LeafDNSPatterns = []string{"^[a-"} }, "leafDNSPatterns"},
	}
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := testDocument(t, operatorPEM, anchorPEM)
			tc.change(&document)
			_, err := Parse(render(t, document))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A measured document carries only the settings this schema defines.
func TestParseRefusesAnUndeclaredField(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	data := append(render(t, testDocument(t, operatorPEM, anchorPEM)), []byte("cdsAddress: 10.0.0.1:8443\n")...)
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted a setting CDS does not define")
	}
}
