package cdsconfig

import (
	"bytes"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func testPodPolicy(t *testing.T, anchor string) []byte {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{
			Name: "pod", Digest: bytes.Repeat([]byte{0x21}, refvalues.DigestSize),
			Registers: map[int][]byte{1: bytes.Repeat([]byte{0x22}, refvalues.DigestSize), 2: bytes.Repeat([]byte{0x23}, refvalues.DigestSize)},
			Anchor:    []byte(anchor),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestPodPolicyIsSeparateAndBoundByTheCDSLaunch(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	_, pod := testKey(t)
	doc := testDocumentFor(t, operator, node)
	podPolicy := testPodPolicy(t, pod)
	input := Inputs{
		ClusterID: doc.ClusterID, OperatorKeys: doc.OperatorKeys,
		ComponentSeed: []byte(testWorkloads), Nodes: doc.Nodes, PodImagePolicy: podPolicy,
		NodeCIDRs: doc.NodeCIDRs, ClusterCIDRs: []string{"10.42.0.0/16", "10.43.0.0/16"},
		ManifestPath: tdxManifest(t), Family: teetypes.FamilyTDX,
	}
	configuration, pin, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.PodImages) != 1 || !bytes.Equal(parsed.PodImages[0].Anchor, []byte(pod)) {
		t.Fatal("measured configuration lost the separate Pod launch authority")
	}
	if len(parsed.Nodes.Images) != 1 || !bytes.Equal(parsed.Nodes.Images[0].Anchor, []byte(node)) {
		t.Fatal("Pod authority leaked into node image pins")
	}
	bound := parsePin(t, pin)
	if len(bound.Images) != 1 || !bytes.Equal(bound.Images[0].LaunchFile, configuration) {
		t.Fatal("CDS pin does not bind the complete configuration including Pod policy")
	}
	input.PodImagePolicy = nil
	disabled, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bound.Images[0].LaunchFile, disabled) {
		t.Fatal("removing Pod authority did not change the bound launch file")
	}
	parsed, err = Parse(disabled)
	if err != nil || len(parsed.PodImages) != 0 {
		t.Fatalf("absent Pod policy did not disable issuance: %v", err)
	}
}

func TestMeasuredPodPolicyRejectsMalformedAndSharedAuthorities(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	_, pod := testKey(t)
	for _, tc := range []struct {
		name    string
		policy  []byte
		allowed bool
	}{
		{"disabled", nil, true},
		{"separate launch key", testPodPolicy(t, pod), true},
		{"node key", testPodPolicy(t, node), false},
		{"equivalent node key", testPodPolicy(t, " \n"+node+"\n\t"), false},
		{"operator key", testPodPolicy(t, operator), false},
		{"equivalent operator key", testPodPolicy(t, "\n"+operator+"\n"), false},
		{"whitespace", []byte(" "), false},
		{"null", []byte("null"), false},
		{"empty pins", []byte(`{"schema_version":"1","tee":"tdx","measurements":[]}`), false},
		{"node policy", []byte(testNodePins(t, node)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := testDocument(t, operator, node)
			doc.PodImagePolicy = string(tc.policy)
			_, err := Parse(render(t, doc))
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
			if err != nil && !strings.Contains(err.Error(), "podImagePolicy") {
				t.Fatalf("unexpected refusal: %v", err)
			}
			generated := testDocumentFor(t, operator, node)
			generated.PodImagePolicy = tc.policy
			if _, err := Format(generated); (err == nil) != tc.allowed {
				t.Fatalf("generator allowed=%v, error=%v", tc.allowed, err)
			}
		})
	}
}
