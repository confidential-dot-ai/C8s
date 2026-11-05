package armtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

const testWorkloadID = "tenant-a.web"

func mustAssignedWorkloadExt(t *testing.T, id string) pkix.Extension {
	t.Helper()
	ext, err := MarshalAssignedWorkloadIDExtension(id)
	if err != nil {
		t.Fatalf("MarshalAssignedWorkloadIDExtension(%q): %v", id, err)
	}
	return ext
}

func TestAssignedWorkloadIDRoundtrip(t *testing.T) {
	ext := mustAssignedWorkloadExt(t, testWorkloadID)
	if !ext.Id.Equal(OIDAssignedWorkloadID) || ext.Critical {
		t.Fatalf("extension = %+v, want non-critical OIDAssignedWorkloadID", ext)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(ext.Value, &raw); err != nil {
		t.Fatal(err)
	}
	if !isUTF8String(raw) {
		t.Fatalf("extension is class %d tag %#x (compound %v), want a primitive UTF8String", raw.Class, raw.Tag, raw.IsCompound)
	}
	got, err := AssignedWorkloadIDFromCert(&x509.Certificate{Extensions: []pkix.Extension{ext}})
	if err != nil {
		t.Fatal(err)
	}
	if got != testWorkloadID {
		t.Fatalf("workload ID = %q, want %q", got, testWorkloadID)
	}
}

// The sandbox-ID and workload-ID extensions share a grammar and an encoding
// but never an OID: one is not read as the other.
func TestAssignedWorkloadIDIsNotTheSandboxID(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{mustSandboxExt(t, testSandboxID)}}
	got, err := AssignedWorkloadIDFromCert(cert)
	if err != nil || got != "" {
		t.Fatalf("sandbox extension read as workload ID: %q, %v", got, err)
	}
	cert = &x509.Certificate{Extensions: []pkix.Extension{mustAssignedWorkloadExt(t, testWorkloadID)}}
	got, err = SandboxIDFromCert(cert)
	if err != nil || got != "" {
		t.Fatalf("workload extension read as sandbox ID: %q, %v", got, err)
	}
}

func TestAssignedWorkloadIDAbsent(t *testing.T) {
	got, err := AssignedWorkloadIDFromCert(&x509.Certificate{})
	if err != nil || got != "" {
		t.Fatalf("absent extension: %q, %v; want empty, nil", got, err)
	}
}

// A present but malformed extension must be an error, never silently absent.
func TestAssignedWorkloadIDMalformedFailsClosed(t *testing.T) {
	for name, value := range map[string][]byte{
		"garbage":            {0xff, 0x01, 0x02},
		"trailing bytes":     withTrailingBytes(mustAssignedWorkloadExt(t, testWorkloadID).Value),
		"non-minimal length": nonMinimalLength(testWorkloadID),
		"constructed":        constructedUTF8(testWorkloadID),
		"ia5string":          mustMarshalString(t, testWorkloadID, "ia5"),
		"64 bytes":           mustMarshalString(t, strings.Repeat("a", 64), "utf8"),
		"leading hyphen":     mustMarshalString(t, "-tenant", "utf8"),
		"out of pattern":     mustMarshalString(t, "tenant a", "utf8"),
		"empty":              mustMarshalString(t, "", "utf8"),
	} {
		t.Run(name, func(t *testing.T) {
			cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: OIDAssignedWorkloadID, Value: value}}}
			if _, err := AssignedWorkloadIDFromCert(cert); err == nil {
				t.Fatal("malformed workload ID extension accepted")
			}
		})
	}
}

func TestAssignedWorkloadIDDuplicateFailsClosed(t *testing.T) {
	ext := mustAssignedWorkloadExt(t, testWorkloadID)
	cert := &x509.Certificate{Extensions: []pkix.Extension{ext, ext}}
	if _, err := AssignedWorkloadIDFromCert(cert); err == nil {
		t.Fatal("duplicate workload ID extension accepted")
	}
}

func TestValidateWorkloadIDRefusesWhatTheExtensionCannotCarry(t *testing.T) {
	for _, id := range []string{"", "tenant a", "a/b", "-tenant", ".tenant", strings.Repeat("a", 64), "ünïcode"} {
		if err := ValidateWorkloadID(id); err == nil {
			t.Errorf("ValidateWorkloadID(%q) accepted", id)
		}
	}
	for _, id := range []string{"a", "tenant-a.web_1", "9lives", strings.Repeat("a", 63)} {
		if err := ValidateWorkloadID(id); err != nil {
			t.Errorf("ValidateWorkloadID(%q): %v", id, err)
		}
	}
}
