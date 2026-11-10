package nriimagepolicy

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// newPodPolicyPlugin is a Pod-role plugin applyPodPolicy installs onto.
func newPodPolicyPlugin(t *testing.T, registered bool) *plugin {
	t.Helper()
	p := newTestPlugin(&config{Pod: &podConfig{}, Policy: policyConfig{Mode: ModeAudit}})
	p.inventory = newAdmissionInventory(t.TempDir())
	p.podBroker = &podCredentialBroker{changes: make(chan struct{}, 1)}
	p.podRegistered.Store(registered)
	return p
}

func TestApplyPodPolicy(t *testing.T) {
	doc := &allowlist.Allowlist{}

	for _, tc := range []struct {
		name       string
		registered bool
		pulled     *allowlist.Allowlist
		want       string
	}{
		{"missing document", true, nil, "missing its document"},
		{"unregistered runtime", false, doc, "verified runtime registration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPodPolicyPlugin(t, tc.registered)
			if err := p.applyPodPolicy(t.Context(), tc.pulled, 1); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if p.policy.current().pulled != nil || len(p.podBroker.changes) != 0 {
				t.Fatal("a refused policy was applied")
			}
		})
	}

	t.Run("apply, repeat and rollback", func(t *testing.T) {
		p := newPodPolicyPlugin(t, true)
		if err := p.applyPodPolicy(t.Context(), doc, 2); err != nil {
			t.Fatal(err)
		}
		if cur := p.policy.current(); cur.pulled != doc || cur.version != 2 {
			t.Fatalf("applied snapshot: version %d", cur.version)
		}
		if p.inventory.revision != 1 || len(p.podBroker.changes) != 1 {
			t.Fatalf("revision %d, wake-ups %d", p.inventory.revision, len(p.podBroker.changes))
		}
		<-p.podBroker.changes
		if err := p.applyPodPolicy(t.Context(), &allowlist.Allowlist{}, 2); err != nil {
			t.Fatal(err)
		}
		if p.policy.current().pulled != doc || p.inventory.revision != 1 || len(p.podBroker.changes) != 0 {
			t.Fatal("a repeated version replaced the applied policy")
		}
		if err := p.applyPodPolicy(t.Context(), doc, 1); err == nil || !strings.Contains(err.Error(), "rolls back") {
			t.Fatalf("rollback: %v", err)
		}
	})
}
