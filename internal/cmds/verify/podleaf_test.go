package verify

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const podInstance = "pcvm-5ac26a2af8d068221a3001879b991e7d95b620edc116e93c4ff7f92312c1eb9d"

// A Pod CVM leaf carries no hardware evidence: it is accepted by its chain to
// --mesh-ca alone, and refused without one or under another CA.
func TestPodLeafEvidence(t *testing.T) {
	leaf, caPath := caSignedLeaf(t, podInstance, serverAuthOnly)
	pool, err := meshCAPool(caPath)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceFromCert(leaf, "pod", leafTrust{meshCA: pool})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.podLeaf || !ev.leafChainVerified || ev.sandboxID != podInstance || ev.rawEvidence != nil {
		t.Fatalf("evidence = %+v", ev)
	}

	if _, err := evidenceFromCert(leaf, "pod", leafTrust{}); !errors.Is(err, armtls.ErrNoAttestation) || !strings.Contains(err.Error(), "--mesh-ca") {
		t.Fatalf("without --mesh-ca: %v", err)
	}
	_, otherCA := caSignedLeaf(t, podInstance, serverAuthOnly)
	other, err := meshCAPool(otherCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromCert(leaf, "pod", leafTrust{meshCA: other}); !isSecurityError(err) {
		t.Fatalf("under another CA: %v", err)
	}

	// Only a Pod CVM leaf may stand without evidence.
	node, nodeCA := caSignedLeaf(t, "8d9f6c2b1a0e", serverAuthOnly)
	nodePool, err := meshCAPool(nodeCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromCert(node, "node", leafTrust{meshCA: nodePool}); !errors.Is(err, armtls.ErrNoAttestation) {
		t.Fatalf("a non-pod leaf without evidence: %v", err)
	}
}

// The verdict on a Pod CVM leaf rests on the chain and the stamps; a pin on
// hardware evidence fails it.
func TestVerifyPodLeaf(t *testing.T) {
	leaf, caPath := caSignedLeaf(t, podInstance, serverAuthOnly)
	pool, err := meshCAPool(caPath)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceFromCert(leaf, "pod", leafTrust{meshCA: pool})
	if err != nil {
		t.Fatal(err)
	}
	run := func(cfg config) (int, string) {
		t.Helper()
		plan, err := buildPolicy(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		return verifyPodLeaf(cfg, plan, ev, nil, &out), out.String()
	}
	code, out := run(config{kind: "workload", meshCA: caPath, sandboxID: podInstance})
	if code != exitVerified || !strings.Contains(out, backendMeshChain) || strings.Contains(out, "measurement:") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if code, out := run(config{kind: "workload", meshCA: caPath, sandboxID: "pcvm-other"}); code != exitFailed {
		t.Fatalf("mismatched --sandbox-id: exit %d:\n%s", code, out)
	}
	if code, out := run(config{kind: "workload", meshCA: caPath, measurements: []string{strings.Repeat("ab", 48)}}); code != exitFailed || !strings.Contains(out, "no hardware evidence") {
		t.Fatalf("measurement pin: exit %d:\n%s", code, out)
	}
}
