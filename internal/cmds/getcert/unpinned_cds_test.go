package getcert

import (
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// testCDSMeasurement is the CDS launch measurement these tests pin, which
// armTLS requires of every verifying client.
var testCDSMeasurement = strings.Repeat("ab", 48)

// Without a pin armTLS accepts any attested CDS, so the client is not built.
func TestUnpinnedCDSRefused(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); !errors.Is(err, armtls.ErrUnpinned) {
		t.Fatalf("err = %v, want errors.Is armtls.ErrUnpinned", err)
	}
}

// A pinned measurement is what the flag is for; it must still work.
func TestPinnedCDSAccepted(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		CDSMeasurements:   testCDSMeasurement,
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
