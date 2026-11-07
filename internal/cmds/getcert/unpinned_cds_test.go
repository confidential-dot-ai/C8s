package getcert

import (
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// testCDSPin is the identity these tests hold CDS to: one image bound to the
// exact launch file that CDS runs on, the only pin a client accepts.
var testCDSPin = testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)

// Without a pin armTLS accepts any attested CDS, so the client is not built.
func TestUnpinnedCDSRefused(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); !errors.Is(err, cmdsutil.ErrCDSPinUnbound) {
		t.Fatalf("err = %v, want errors.Is cmdsutil.ErrCDSPinUnbound", err)
	}
}

// A pin document is what --image-policy-file is for; it must still work.
func TestPinnedCDSAccepted(t *testing.T) {
	cfg := config{
		CDSURL:                 "https://cds:8443",
		AttestationApiURL:      "http://attestation-api:8400",
		SAN:                    "host.example.com",
		MeasurementsConfigJSON: testCDSPin,
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
