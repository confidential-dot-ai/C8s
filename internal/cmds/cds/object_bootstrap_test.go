package cds

import "testing"

func TestObjectConfigurationCannotFallBackToLegacyState(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	h.cfg.allowlistDB = ""
	if err := validateConfig(h.cfg); err != nil {
		t.Fatalf(
			"object mode required a local database: %v",
			err,
		)
	}
	if _, err := newBackend(
		t.Context(),
		h.cfg,
		stores{},
	); err == nil {
		t.Fatal("object mode silently selected a legacy backend")
	}
	h.cfg.measured.ObjectState = nil
	if err := validateConfig(h.cfg); err == nil {
		t.Fatal("legacy mode accepted a missing database path")
	}
}
