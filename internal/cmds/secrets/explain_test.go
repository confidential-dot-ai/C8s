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

// An oversized environment persists across restarts, so the missing case must
// name how to shrink it.
func TestEnvEvidenceMissingNamesShrinking(t *testing.T) {
	if got := envEvidenceReason(pkgallowlist.EnvEvidenceMissing); !strings.Contains(got, "enableServiceLinks: false") {
		t.Errorf("envEvidenceReason(%q) = %q, want it to name how to shrink the environment", pkgallowlist.EnvEvidenceMissing, got)
	}
}
