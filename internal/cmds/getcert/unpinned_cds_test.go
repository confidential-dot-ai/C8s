package getcert

import (
	"strings"
	"testing"
)

// An unpinned CDS would hand this pod its identity — and its sandbox token —
// on the strength of being some TEE, so get-cert refuses to dial one.
func TestUnpinnedCDSRefused(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); err == nil {
		t.Fatal("client built against an unpinned CDS")
	}
}

// A pinned measurement is what the flag is for; it must still work.
func TestPinnedCDSAccepted(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		CDSMeasurements:   strings.Repeat("ab", 48),
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
