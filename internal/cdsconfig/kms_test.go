package cdsconfig

import (
	"strings"
	"testing"
)

// The KMS setting round-trips through Format and needs Pod issuance, since
// only a pod CVM leaf can ask for a brokered secret.
func TestKMSRidesTheMeasuredConfiguration(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	_, pod := testKey(t)
	pin := strings.Repeat("ab", 32)
	document := testDocument(t, operator, node)
	document.PodImagePolicy = string(testPodPolicy(t, pod))
	document.KMS = &kmsWire{URL: "https://kms.example/v1/release", TLSKeySHA256: pin}
	cfg, err := Parse(render(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KMS == nil || cfg.KMS.URL != "https://kms.example/v1/release" || cfg.KMS.wire().TLSKeySHA256 != pin {
		t.Fatalf("KMS = %+v", cfg.KMS)
	}

	for name, change := range map[string]func(*wire){
		"no pod policy": func(w *wire) { w.PodImagePolicy = "" },
		"plain http":    func(w *wire) { w.KMS.URL = "http://kms.example/release" },
		"credentials":   func(w *wire) { w.KMS.URL = "https://user:pw@kms.example/release" },
		"short pin":     func(w *wire) { w.KMS.TLSKeySHA256 = "abab" },
		"uppercase pin": func(w *wire) { w.KMS.TLSKeySHA256 = strings.ToUpper(pin) },
		"no pin":        func(w *wire) { w.KMS.TLSKeySHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := document
			kms := *document.KMS
			bad.KMS = &kms
			change(&bad)
			if _, err := Parse(render(t, bad)); err == nil || !strings.Contains(err.Error(), "kms") {
				t.Fatalf("got %v", err)
			}
		})
	}
}
