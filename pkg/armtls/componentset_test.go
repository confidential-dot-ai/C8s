package armtls

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

func testComponentSet() *ComponentSet {
	return &ComponentSet{Version: "0.43.0", Digest: bytes.Repeat([]byte{0x22}, 32)}
}

// goldenComponentSetDER is the one canonical encoding of {"0.43.0", 0x22*32},
// shared with any other parser of this extension.
const goldenComponentSetDER = "302a0c06302e34332e30" +
	"04202222222222222222222222222222222222222222222222222222222222222222"

func TestComponentSet_GoldenVector(t *testing.T) {
	ext, err := MarshalComponentSetExtension(testComponentSet())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ext.Value); got != goldenComponentSetDER {
		t.Fatalf("DER = %s, want %s", got, goldenComponentSetDER)
	}
	if ext.Critical {
		t.Fatal("component-set extension must be non-critical")
	}
	if !ext.Id.Equal(OIDComponentSet) {
		t.Fatalf("OID = %v", ext.Id)
	}
	der, err := hex.DecodeString(goldenComponentSetDER)
	if err != nil {
		t.Fatal(err)
	}
	set, err := UnmarshalComponentSet(der)
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != "0.43.0" || !bytes.Equal(set.Digest, testComponentSet().Digest) {
		t.Fatalf("round trip = %+v", set)
	}
}

// The version grammar and the digest length are the stamp's whole shape, and
// both are checked on the way out and on the way in.
func TestComponentSet_RejectsInvalid(t *testing.T) {
	for name, mutate := range map[string]func(*ComponentSet){
		"no version":         func(c *ComponentSet) { c.Version = "" },
		"a v prefix":         func(c *ComponentSet) { c.Version = "v0.43.0" },
		"two numbers":        func(c *ComponentSet) { c.Version = "0.43" },
		"a leading zero":     func(c *ComponentSet) { c.Version = "0.043.0" },
		"a pre-release":      func(c *ComponentSet) { c.Version = "0.43.0-rc1" },
		"a short digest":     func(c *ComponentSet) { c.Digest = c.Digest[:31] },
		"no digest":          func(c *ComponentSet) { c.Digest = nil },
		"an oversize digest": func(c *ComponentSet) { c.Digest = append(c.Digest, 0x22) },
	} {
		t.Run(name, func(t *testing.T) {
			set := testComponentSet()
			mutate(set)
			if _, err := MarshalComponentSetExtension(set); err == nil {
				t.Fatal("marshal accepted a stamp outside the extension's shape")
			}
		})
	}

	golden, err := hex.DecodeString(goldenComponentSetDER)
	if err != nil {
		t.Fatal(err)
	}
	extraField, err := asn1.Marshal(struct {
		Version string `asn1:"utf8"`
		Digest  []byte
		Extra   int
	}{"0.43.0", bytes.Repeat([]byte{0x22}, 32), 5})
	if err != nil {
		t.Fatal(err)
	}
	ia5Version := append([]byte(nil), golden...)
	ia5Version[2] = 0x16
	for name, der := range map[string][]byte{
		"empty":                {},
		"truncated":            golden[:len(golden)-1],
		"trailing bytes":       append(append([]byte(nil), golden...), 0x00),
		"extra sequence field": extraField,
		"non-minimal length":   append([]byte{0x30, 0x81, golden[1]}, golden[2:]...),
		"wrong string tag":     ia5Version,
		"not a sequence":       {0x02, 0x01, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalComponentSet(der); err == nil {
				t.Fatal("unmarshal accepted a rejected boundary")
			}
		})
	}
}

// A leaf carries at most one stamp: absence is nil, damage and duplication are
// errors a verifier must not read as absence.
func TestComponentSetFromCert(t *testing.T) {
	ext, err := MarshalComponentSetExtension(testComponentSet())
	if err != nil {
		t.Fatal(err)
	}
	set, err := ComponentSetFromCert(selfSignedWithExts(t))
	if err != nil || set != nil {
		t.Fatalf("absent stamp = %v, err = %v", set, err)
	}
	set, err = ComponentSetFromCert(selfSignedWithExts(t, ext))
	if err != nil || set == nil || set.Version != "0.43.0" {
		t.Fatalf("present stamp = %v, err = %v", set, err)
	}
	damaged := ext
	damaged.Value = ext.Value[:len(ext.Value)-1]
	if _, err := ComponentSetFromCert(selfSignedWithExts(t, damaged)); err == nil || !strings.Contains(err.Error(), "component set") {
		t.Fatalf("a damaged stamp read as %v", err)
	}
}
