package workloadclaims

import "testing"

func TestAttestationSidecarSocketConsumer(t *testing.T) {
	if !IsSocketConsumer("cds-attest") {
		t.Fatal("attestation sidecar has no socket access")
	}
	if IsInjectedContainerName("cds-attest") {
		t.Fatal("application sidecar marked as webhook injected")
	}
	if IsSocketConsumer("gateway") {
		t.Fatal("ordinary workload receives node sockets")
	}
}
