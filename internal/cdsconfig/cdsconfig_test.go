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
	"unicode/utf8"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

const testWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"c8s-router":{"containers":[{"digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `"}]}}}`

const testServicePattern = cmdsutil.ServiceDNSSANPattern

func testKey(t testing.TB) (*ecdsa.PublicKey, string) {
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
func testNodePins(
	t testing.TB,
	anchor string,
) string {
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

// testDocument is a launch file as a map, so a test can write a field the
// writer would refuse.
func testDocument(
	t testing.TB,
	operatorPEM string,
	anchorPEM string,
) map[string]any {
	t.Helper()
	return map[string]any{
		"schemaVersion":      SchemaVersion,
		"clusterID":          "acme-prod",
		"operatorPublicKeys": operatorPEM,
		"workloads":          testWorkloads,
		"nodes":              testNodePins(t, anchorPEM),
		"nodeCIDRs":          []string{"10.0.0.0/24"},
		"leafDNSNames":       []string{"cds.acme.example"},
		"leafDNSPatterns":    []string{testServicePattern},
	}
}

func render(
	t testing.TB,
	document map[string]any,
) []byte {
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
	if !cfg.NodeCIDRs.Contains("10.0.0.5") || cfg.NodeCIDRs.Contains("10.1.0.5") {
		t.Fatalf("node subnets = %v", cfg.NodeCIDRs)
	}
	if len(cfg.DNSSANPatterns) != 2 {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}

// The launch file module leaves these two policies to C8s's own parsers.
func TestParseRefusesEachMalformedEmbeddedPolicy(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{
			name:  "no operator keys",
			field: "operatorPublicKeys",
			value: "",
		},
		{
			name:  "operator key is not a key",
			field: "operatorPublicKeys",
			value: "not a key",
		},
		{
			name:  "no workloads",
			field: "workloads",
			value: "",
		},
	}
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := testDocument(t, operatorPEM, anchorPEM)
			document[tc.field] = tc.value
			_, err := Parse(render(t, document))
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("got %v, want %q", err, tc.field)
			}
		})
	}
}

// The launch file module carries its own RFC 1123 label check so that it
// needs no Kubernetes module; this holds it to apimachinery's.
func FuzzClusterIDRuleIsApimachinerys(f *testing.F) {
	for _, seed := range []string{
		"",
		"a",
		"0",
		"acme-prod",
		"a--b",
		"-a",
		"a-",
		"A",
		"acme_prod",
		"acme.prod",
		"a\n",
		"\na",
		"é",
		strings.Repeat("a", 63),
		strings.Repeat("a", 64),
		strings.Repeat("a", 62) + "-",
	} {
		f.Add(seed)
	}
	_, operatorPEM := testKey(f)
	_, anchorPEM := testKey(f)
	document := testDocument(f, operatorPEM, anchorPEM)
	f.Fuzz(func(t *testing.T, id string) {
		if !utf8.ValidString(id) {
			t.Skip("YAML carries only UTF-8")
		}
		document["clusterID"] = id
		data := render(t, document)
		var written struct {
			ClusterID string `yaml:"clusterID"`
		}
		if err := yaml.Unmarshal(data, &written); err != nil || written.ClusterID != id {
			t.Skip("YAML does not carry this string unchanged")
		}
		_, err := Parse(data)
		if err != nil && !strings.Contains(err.Error(), "clusterID") {
			t.Fatalf("clusterID %q: %v", id, err)
		}
		apimachinery := len(validation.IsDNS1123Label(id)) == 0
		if (err == nil) != apimachinery {
			t.Fatalf("clusterID %q: accepted=%v, apimachinery accepts=%v", id, err == nil, apimachinery)
		}
	})
}
