package secrets

import (
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Waiting recovers only a node that has not applied the policy yet, so every
// other case without per-variable digests must name pod recreation.
func TestEnvEvidenceReasonNamesRecreation(t *testing.T) {
	for _, diagnosis := range []string{pkgallowlist.EnvEvidenceUnavailable, pkgallowlist.EnvEvidenceMissing, pkgallowlist.EnvEvidenceEvicted} {
		if got := envEvidenceReason(diagnosis); !strings.Contains(got, "recreate the pod") {
			t.Errorf("envEvidenceReason(%q) = %q, want it to name pod recreation", diagnosis, got)
		}
	}
}
