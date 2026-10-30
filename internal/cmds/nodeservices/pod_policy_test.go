package nodeservices

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func TestPrepareKeepsExternalCDSTrustSeparateAndDropsLegacyPolicies(t *testing.T) {
	root := prepareRoot(t)
	wantPeers, err := os.ReadFile(filepath.Join(root, launchDir, "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		t.Run(string(role), func(t *testing.T) {
			for _, name := range []string{"pods.json", "allowlist-seed.json"} {
				writeInput(t, root, PublicDir+"/"+name, []byte("obsolete in-cluster CDS input"))
			}
			doc := document(t, role)
			wantCDS, err := doc.CDSPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if err := Prepare(root, doc); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"pods.json", "allowlist-seed.json"} {
				if _, err := os.Stat(filepath.Join(root, PublicDir, name)); !os.IsNotExist(err) {
					t.Fatalf("retained legacy %s: %v", name, err)
				}
			}
			for name, want := range map[string][]byte{"peers.json": wantPeers, "cds.json": wantCDS} {
				got, err := os.ReadFile(filepath.Join(root, PublicDir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s trust changed: %v", name, err)
				}
			}
		})
	}
}
