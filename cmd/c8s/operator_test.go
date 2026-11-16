//go:build !c8s_node

package main

import "testing"

// A worker control plane runs the operator with nothing but --webhook-host,
// --get-cert-image and --mesh-image; everything else must already match the
// worker image and the document c8s worker control-plane render writes.
func TestOperatorFlagDefaults(t *testing.T) {
	flagDefaults := map[string]string{
		"workload-claims-host-dir": "/run/nri-image-policy",
		"webhook-config-name":      "c8s-pod-injector",
		"webhook-host":             "",
		"kubeconfig":               "",
		"get-cert-image":           "",
		"mesh-image":               "",
		"attestation-api-url":      "",
	}
	for name, want := range flagDefaults {
		flag := operatorCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("no --%s flag registered", name)
		}
		if flag.DefValue != want {
			t.Errorf("--%s default = %q, want %q", name, flag.DefValue, want)
		}
	}
}
