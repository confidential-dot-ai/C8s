package allowlistproxy

import "testing"

func TestProxyAcceptsCompleteServerPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.cdsMeasurements = nil // the policy file carries the pin, and the two are exclusive
	cfg.measurementsConfig = "../../../internal/testdata/node-identities.json"
	if _, err := newHandler(cfg, nil); err != nil {
		t.Fatalf("node operator policy refused at startup: %v", err)
	}
}
