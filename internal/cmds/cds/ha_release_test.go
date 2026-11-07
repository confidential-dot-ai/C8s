//go:build !c8s_dev

package cds

import "testing"

// A release verifies every replica in-process, so no command takes an
// attestation-api's verdict instead.
func TestReleaseVerifiesReplicasOnlyInProcess(t *testing.T) {
	for _, cmd := range replicaDialers(t) {
		if cmd.Flags().Lookup("attestation-api-url") != nil {
			t.Errorf("%s defines --attestation-api-url in a build without c8s_dev", cmd.CommandPath())
		}
	}
}
