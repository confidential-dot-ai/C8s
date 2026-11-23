package getcert

import (
	"errors"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

// testTAPin is the identity these tests hold Trust Authority to: one image bound to the
// exact launch file that Trust Authority runs on, the only pin a client accepts.
var testTAPin = testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)

// Without a pin armTLS accepts any attested Trust Authority, so the client is not built.
func TestUnpinnedCDSRefused(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := taHTTPClient(t.Context(), cfg); !errors.Is(err, cmdsutil.ErrCDSPinUnbound) {
		t.Fatalf("err = %v, want errors.Is cmdsutil.ErrCDSPinUnbound", err)
	}
}

// A pin document is what --image-policy-file is for; it must still work.
func TestPinnedCDSAccepted(t *testing.T) {
	cfg := config{
		CDSURL:                 "https://cds:8443",
		AttestationApiURL:      "http://attestation-api:8400",
		SAN:                    "host.example.com",
		MeasurementsConfigJSON: testTAPin,
	}
	if _, err := taHTTPClient(t.Context(), cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
