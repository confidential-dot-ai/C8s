package workloadclaims

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func TestPodPolicyRequiresWholeAnchoredTDXIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	anchor := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for _, tc := range []struct {
		name   string
		change func(*refvalues.ReferenceValues)
		valid  bool
	}{
		{"valid", func(v *refvalues.ReferenceValues) {}, true},
		{"missing key", func(v *refvalues.ReferenceValues) { v.Images[0].Anchor = nil }, false},
		{"missing kernel", func(v *refvalues.ReferenceValues) { delete(v.Images[0].Registers, 1) }, false},
		{"missing command line", func(v *refvalues.ReferenceValues) { delete(v.Images[0].Registers, 2) }, false},
		{"SNP", func(v *refvalues.ReferenceValues) { v.Family = teetypes.FamilySNP; v.Images[0].Registers = nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{{Name: "pod", Digest: bytes.Repeat([]byte{1}, 48), Registers: map[int][]byte{1: bytes.Repeat([]byte{2}, 48), 2: bytes.Repeat([]byte{3}, 48)}, Anchor: anchor}}}
			tc.change(&v)
			raw, err := refvalues.Format(v)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParsePodImagePolicy(raw)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
			if tc.valid && !bytes.Equal(parsed.Images[0].Anchor, anchor) {
				t.Fatal("anchor bytes changed")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte(`{"schema_version":"1","tee":"tdx","measurements":[]}`)} {
		if _, err := ParsePodImagePolicy(raw); err == nil {
			t.Fatal("empty policy accepted")
		}
	}
	// Format validates anchors itself; construct malformed input directly so
	// this negative reaches the parser rather than failing in the fixture.
	bad, err := json.Marshal(map[string]any{"schema_version": "1", "tee": "tdx", "measurements": []any{map[string]any{
		"name": "pod", "mrtd": strings.Repeat("01", 48), "rtmr": []any{nil, strings.Repeat("02", 48), strings.Repeat("03", 48), nil}, "approver_key": "arbitrary",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePodImagePolicy(bad); err == nil {
		t.Fatal("arbitrary anchor accepted")
	}
}
