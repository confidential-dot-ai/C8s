//go:build linux

package armtlsmesh

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// TestCWLabelMatchesWebhook pins labelConfidentialWorkload to the label the
// injection webhook actually stamps, without a runtime dependency on the
// webhook package. Drift would silently empty the cw ipsets and disable the
// inbound guard.
func TestCWLabelMatchesWebhook(t *testing.T) {
	if labelConfidentialWorkload != webhook.LabelWorkload {
		t.Fatalf("labelConfidentialWorkload = %q, webhook.LabelWorkload = %q; the cw guard keys off the webhook-stamped label and must match", labelConfidentialWorkload, webhook.LabelWorkload)
	}
}
