package cdsconn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

func TestHTTPClientRouterFrontDoor(t *testing.T) {
	router := testutil.NewRouterServer(t)
	reject := testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		return nil, localverify.ErrMeasurementNotAllowed
	})
	for _, tc := range []struct {
		name      string
		directCDS bool
		verifier  PinVerifier
		wantErr   string
	}{
		{name: "allowlist", verifier: testutil.ApproveAll()},
		{name: "direct CDS", directCDS: true, verifier: testutil.ApproveAll(), wantErr: "https://<node>:30808"},
		{name: "direct CDS pinned to CDS", directCDS: true, verifier: reject, wantErr: "https://<node>:30808"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{
				URL:          router.URL,
				Measurements: []string{testutil.TestMeasurement},
				Timeout:      5 * time.Second,
				Verifier:     tc.verifier,
				DirectCDS:    tc.directCDS,
			}
			hc, err := o.HTTPClient(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("HTTPClient(%s) = %v, want a client", router.URL, err)
				}
				hc.CloseIdleConnections()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("HTTPClient(%s) = %v, want an error containing %q", router.URL, err, tc.wantErr)
			}
		})
	}
}
