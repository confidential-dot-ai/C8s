package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

func TestSandboxIDRoundtrip(t *testing.T) {
	ext, err := MarshalSandboxIDExtension(testSandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if !ext.Id.Equal(OIDSandboxID) || ext.Critical {
		t.Fatalf("extension = %+v, want non-critical OIDSandboxID", ext)
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
		"garbage":        {0xff, 0x01, 0x02},
		"trailing bytes": append(mustSandboxExt(t, testSandboxID).Value, 0x00),
		"empty string":   {0x16, 0x00}, // IA5String of length 0
	} {
		t.Run(name, func(t *testing.T) {
			cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDSandboxID, Value: value}}}
			if _, err := SandboxIDFromCert(cert); err == nil {
				t.Fatal("malformed sandbox extension accepted")
			}
		})
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

func TestValidateSandboxID(t *testing.T) {
	for _, ok := range []string{testSandboxID, "a", "pod-1.sandbox_2"} {
		if err := ValidateSandboxID(ok); err != nil {
			t.Errorf("ValidateSandboxID(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "with space", "slash/id", "semi;colon", strings.Repeat("a", 129), "sandbox-🙂"} {
		if err := ValidateSandboxID(bad); err == nil {
			t.Errorf("ValidateSandboxID(%q) accepted", bad)
		}
		if _, err := MarshalSandboxIDExtension(bad); err == nil {
			t.Errorf("MarshalSandboxIDExtension(%q) accepted", bad)
		}
	}
}
