package nriimagepolicy

import (
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
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

// A set ending on a Pod guest goes through the lock a new document goes
// through: it waits for admission, stales the issuance in flight and wakes the
// broker, and a set still in force changes nothing.
func TestEndPodSetsUnderAdmissionLock(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	argv := []string{"/usr/local/bin/c8s", "armtls-mesh"}
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}

	p := newPodPolicyPlugin(t, true)
	p.policy = newPolicyStore(anyAllowlist(map[string]string{}), newTAClock(func() time.Time { return taTime }))
	document := componentDocument(t, retiring, componentContainer(t, pushDigestB, allowlist.RoleMesh, argv))
	if err := p.applyPodPolicy(t.Context(), document, 7); err != nil {
		t.Fatal(err)
	}
	<-p.podBroker.changes

	p.endPodSets(t.Context())
	if !admitsDigest(p.policy, pushDigestB) || p.inventory.revision != 1 || len(p.podBroker.changes) != 0 {
		t.Fatalf("a set in force ended: revision %d, wake-ups %d", p.inventory.revision, len(p.podBroker.changes))
	}

	taTime = deadline
	p.podMu.Lock()
	ended := make(chan struct{})
	go func() {
		p.endPodSets(t.Context())
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("a set ended on a Pod guest without admission's lock")
	case <-time.After(20 * time.Millisecond):
	}
	p.podMu.Unlock()
	<-ended

	if admitsDigest(p.policy, pushDigestB) {
		t.Fatal("the retired set still admits its entry")
	}
	if p.inventory.revision != 2 || len(p.podBroker.changes) != 1 {
		t.Fatalf("revision %d, wake-ups %d after the set ended", p.inventory.revision, len(p.podBroker.changes))
	}
	if version := p.policy.current().version; version != 7 {
		t.Fatalf("version = %d, want 7: ending a set rewrites no policy", version)
	}
}
