package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"strings"
	"testing"
)

const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

func TestSandboxIDRoundtrip(t *testing.T) {
	ext := mustSandboxExt(t, testSandboxID)
	if !ext.Id.Equal(OIDSandboxID) || ext.Critical {
		t.Fatalf("extension = %+v, want non-critical OIDSandboxID", ext)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
		t.Fatal(err)
	}
	if !isUTF8String(raw) {
		t.Fatalf("extension is class %d tag %#x (compound %v), want a primitive UTF8String", raw.Class, raw.Tag, raw.IsCompound)
	}
	got, err := SandboxIDFromCert(&x509.Certificate{Extensions: []pkix.Extension{ext}})
	if err != nil {
		t.Fatal(err)
	}
	if got != testSandboxID {
		t.Fatalf("sandbox = %q, want %q", got, testSandboxID)
	}
}

func TestSandboxIDAbsent(t *testing.T) {
	got, err := SandboxIDFromCert(&x509.Certificate{})
	if err != nil || got != "" {
		t.Fatalf("absent extension: %q, %v; want empty, nil", got, err)
	}
}

// A present but malformed extension must be an error, never silently absent.
func TestSandboxIDMalformedFailsClosed(t *testing.T) {
	for name, value := range map[string][]byte{
		"garbage":            {0xff, 0x01, 0x02},
		"trailing bytes":     withTrailingBytes(mustSandboxExt(t, testSandboxID).Value),
		"non-minimal length": nonMinimalLength(testSandboxID),
		"constructed":        constructedUTF8(testSandboxID),
		"ia5string":          mustMarshalString(t, testSandboxID, "ia5"),
		"printablestring":    mustMarshalString(t, testSandboxID, "printable"),
		"129 characters":     mustMarshalString(t, strings.Repeat("a", 129), "utf8"),
		"out of pattern":     mustMarshalString(t, "sandbox id", "utf8"),
	} {
		t.Run(name, func(t *testing.T) {
			cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDSandboxID, Value: value}}}
			if _, err := SandboxIDFromCert(cert); err == nil {
				t.Fatal("malformed sandbox extension accepted")
			}
		})
	}
}

// An empty UTF8String decodes cleanly, so only the pattern stands between it
// and a leaf whose sandbox ID reads as absent.
func TestSandboxIDEmptyStringRejected(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDSandboxID, Value: []byte{0x0c, 0x00}}}}
	_, err := SandboxIDFromCert(cert)
	if err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("err = %v, want a pattern rejection", err)
	}
}

// Two extensions are two claims; neither may win.
func TestSandboxIDDuplicateFailsClosed(t *testing.T) {
	ext := mustSandboxExt(t, testSandboxID)
	cert := &x509.Certificate{Extensions: []pkix.Extension{ext, ext}}
	if _, err := SandboxIDFromCert(cert); err == nil {
		t.Fatal("duplicate sandbox-ID extension accepted")
	}
}

func TestValidateSandboxID(t *testing.T) {
	for _, ok := range []string{testSandboxID, "a", "pod-1.sandbox_2"} {
		if err := ValidateSandboxID(ok); err != nil {
			t.Errorf("ValidateSandboxID(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "with space", "slash/id", "semi;colon", strings.Repeat("a", 129), "sandbox-\U0001f642"} {
		if err := ValidateSandboxID(bad); err == nil {
			t.Errorf("ValidateSandboxID(%q) accepted", bad)
		}
		if _, err := MarshalSandboxIDExtension(bad); err == nil {
			t.Errorf("MarshalSandboxIDExtension(%q) accepted", bad)
		}
	}
}

func mustSandboxExt(t *testing.T, id string) pkix.Extension {
	t.Helper()
	ext, err := MarshalSandboxIDExtension(id)
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

// mustMarshalString builds extension values MarshalSandboxIDExtension refuses
// to emit.
func mustMarshalString(t *testing.T, value, params string) []byte {
	t.Helper()
	der, err := asn1.MarshalWithParams(value, params)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func withTrailingBytes(der []byte) []byte {
	return append(slices.Clone(der), 0x00)
}

// nonMinimalLength encodes id's length in the long form DER reserves for
// lengths above 127.
func nonMinimalLength(id string) []byte {
	return append([]byte{0x0c, 0x81, byte(len(id))}, id...)
}

// constructedUTF8 wraps id's primitive UTF8String in a constructed one, the
// BER segmentation DER forbids.
func constructedUTF8(id string) []byte {
	inner := append([]byte{0x0c, byte(len(id))}, id...)
	return append([]byte{0x2c, byte(len(inner))}, inner...)
}
