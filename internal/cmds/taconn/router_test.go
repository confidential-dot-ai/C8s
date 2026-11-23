package taconn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

func TestHTTPClientRouterFrontDoor(t *testing.T) {
	router := testutil.NewRouterServer(t)
	reject := testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		return nil, localverify.ErrMeasurementNotAllowed
	})
	for _, tc := range []struct {
		name     string
		directTA bool
		verifier PinVerifier
		wantErr  string
	}{
		{name: "allowlist", verifier: testutil.ApproveAll()},
		{name: "direct Trust Authority", directTA: true, verifier: testutil.ApproveAll(), wantErr: "--ta-address"},
		{name: "direct Trust Authority pinned to the Trust Authority", directTA: true, verifier: reject, wantErr: "--ta-address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{
				URL:      router.URL,
				Timeout:  5 * time.Second,
				Verifier: tc.verifier,
				DirectTA: tc.directTA,
			}
			if tc.directTA {
				o.MeasurementsConfig = testutil.TAPinFile(t)
			} else {
				o.Measurements = []string{testutil.TestMeasurement}
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
