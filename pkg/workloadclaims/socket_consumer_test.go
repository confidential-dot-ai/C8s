package workloadclaims

import "testing"

func TestSocketConsumers(t *testing.T) {
	for name, want := range map[string]bool{
		CertContainerName:     true,
		SecretContainerName:   true,
		VolumeContainerName:   true,
		AttestContainerName:   true,
		CertWaitContainerName: false,
		"gateway":             false,
	} {
		if got := IsSocketConsumer(name); got != want {
			t.Errorf("IsSocketConsumer(%q) = %v, want %v", name, got, want)
		}
	}
	if IsInjectedContainerName(AttestContainerName) {
		t.Error("an application's cds-attest must not count as a webhook-injected container")
	}
}
