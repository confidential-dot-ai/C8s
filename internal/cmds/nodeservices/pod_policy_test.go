package nodeservices

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func TestPrepareKeepsPodTrustSeparateAndClearsItForAgents(t *testing.T) {
	root := prepareRoot(t)
	doc := document(t, launchconfig.Server)
	pins := testPins(t)
	pins.Images = pins.Images[1:]
	policy, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	doc.PodImagePolicy = string(policy)
	peerPath := filepath.Join(root, PublicDir, "peers.json")
	wantPeers, err := os.ReadFile(filepath.Join(root, launchDir, "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Prepare(root, doc); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, PublicDir, "pods.json"))
	if err != nil || !bytes.Equal(got, policy) {
		t.Fatalf("Pod policy publication: %v", err)
	}
	got, err = os.ReadFile(peerPath)
	if err != nil || !bytes.Equal(got, wantPeers) {
		t.Fatalf("Pod policy changed node trust: %v", err)
	}
	if err := Prepare(root, document(t, launchconfig.Agent)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, PublicDir, "pods.json")); !os.IsNotExist(err) {
		t.Fatalf("agent retained Pod trust: %v", err)
	}
	if err := Prepare(root, document(t, launchconfig.Server)); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(root, PublicDir, "pods.json"))
	if err != nil || len(got) != 0 {
		t.Fatalf("server without Pod policy did not disable issuance: %v", err)
	}
}
