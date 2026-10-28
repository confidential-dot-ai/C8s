package nriimagepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func checkpointTestPolicy(t *testing.T, populated bool) *allowlist.Allowlist {
	t.Helper()
	raw := `{"schema":"c8s.allowlist/v1","workloads":{}}`
	if populated {
		raw = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
	}
	policy, err := allowlist.ParseJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPodPolicyRecoveryRetainsVersionAndDecisions(t *testing.T) {
	for _, populated := range []bool{false, true} {
		store := newPolicyStore(nil)
		store.apply(checkpointTestPolicy(t, populated), 17)
		saved, err := checkpointPodPolicy(store.current())
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the surrounding checkpoint's JSON boundary too.
		raw, _ := json.Marshal(saved)
		var decoded podPolicyCheckpoint
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		restored, err := restorePodPolicy(decoded)
		if err != nil || restored.version != 17 || restored.index.AdmitsDigest("sha256:"+strings.Repeat("a", 64)) != populated {
			t.Fatalf("policy recovery lost version or decision: %v", err)
		}
		if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, !populated), 16); err == nil {
			t.Fatal("restart accepted policy rollback")
		}
		if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, !populated), 17); err == nil {
			t.Fatal("same version changed policy after restart")
		}
		if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, populated), 17); err != nil {
			t.Fatalf("same policy confirmation refused: %v", err)
		}
		if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, !populated), 18); err != nil {
			t.Fatalf("next authenticated version refused: %v", err)
		}
	}
}

func TestPodPolicyRecoveryDistinguishesNoPullFromEmptyPolicy(t *testing.T) {
	store := newPolicyStore(nil)
	saved, err := checkpointPodPolicy(store.current())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restorePodPolicy(saved)
	if err != nil || restored.pulled != nil || restored.version != 0 || restored.index.Size() != 0 {
		t.Fatalf("fresh state changed: %v", err)
	}
	if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, true), 0); err != nil {
		t.Fatalf("first pull was refused: %v", err)
	}
	store.apply(checkpointTestPolicy(t, false), 0)
	saved, _ = checkpointPodPolicy(store.current())
	restored, err = restorePodPolicy(saved)
	if err != nil || restored.pulled == nil {
		t.Fatalf("applied empty policy became missing: %v", err)
	}
	if err := validatePodPolicyUpdate(restored, checkpointTestPolicy(t, true), 0); err == nil {
		t.Fatal("changed version zero replaced applied policy")
	}
}

func TestPodPolicyRecoveryRefusesLostOrChangedDocument(t *testing.T) {
	store := newPolicyStore(nil)
	store.apply(checkpointTestPolicy(t, true), 17)
	valid, _ := checkpointPodPolicy(store.current())
	for _, mutate := range []func(*podPolicyCheckpoint){
		func(s *podPolicyCheckpoint) { s.Document = nil },
		func(s *podPolicyCheckpoint) { s.Document = []byte("null") },
		func(s *podPolicyCheckpoint) { s.Digest = "" },
		func(s *podPolicyCheckpoint) { s.Document = append(bytes.Clone(s.Document), '\n') },
		func(s *podPolicyCheckpoint) {
			s.Document = []byte(`{"schema":"unknown","workloads":{}}`)
			sum := sha256.Sum256(s.Document)
			s.Digest = hex.EncodeToString(sum[:])
		},
		func(s *podPolicyCheckpoint) {
			s.Document = append(bytes.Clone(s.Document), '\n')
			sum := sha256.Sum256(s.Document)
			s.Digest = hex.EncodeToString(sum[:])
		},
	} {
		saved := valid
		mutate(&saved)
		if _, err := restorePodPolicy(saved); err == nil {
			t.Fatal("restored incomplete or changed policy checkpoint")
		}
	}
}

// Restoring a consumer snapshot must not apply newer authoring restrictions.
func TestPodPolicyRecoveryPreservesServedPolicySemantics(t *testing.T) {
	policy := checkpointTestPolicy(t, true)
	entry := policy.Workloads["app"]
	entry.Egress = allowlist.EgressList{{CIDR: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}}
	policy.Workloads["app"] = entry
	raw, _ := policy.Canonical()
	if _, err := allowlist.ParseJSON(raw); err == nil {
		t.Fatal("fixture must violate strict authoring constraints")
	}
	served, err := allowlist.ParseServedJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	store := newPolicyStore(nil)
	store.apply(served, 3)
	saved, err := checkpointPodPolicy(store.current())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restorePodPolicy(saved)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := restored.pulled.Canonical()
	if !bytes.Equal(after, raw) || !restored.index.AdmitsDigest("sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("restart changed an authenticated consumer policy")
	}
}
