package getcert

import (
	"errors"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

// testTAPin is the identity these tests hold Trust Authority to: one image bound to the
// exact launch file that Trust Authority runs on, the only pin a client accepts.
var testTAPin = testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile)

// Without a pin armTLS accepts any attested Trust Authority, so the client is not built.
func TestUnpinnedTARefused(t *testing.T) {
	cfg := config{
		TAURL:             "https://ta:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := taHTTPClient(cfg); !errors.Is(err, cmdsutil.ErrTAPinUnbound) {
		t.Fatalf("err = %v, want errors.Is cmdsutil.ErrTAPinUnbound", err)
	}
}

// A pin document is what --image-policy-file is for; it must still work.
func TestPinnedTAAccepted(t *testing.T) {
	cfg := config{
		TAURL:                  "https://ta:8443",
		AttestationApiURL:      "http://attestation-api:8400",
		SAN:                    "host.example.com",
		MeasurementsConfigJSON: testTAPin,
	}
	if _, err := taHTTPClient(cfg); err != nil {
		t.Fatalf("taHTTPClient: %v", err)
	}
}
