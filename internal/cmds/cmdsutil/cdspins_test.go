package cmdsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCDSPinsFlags(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cds-pins.json")
	if _, on, err := (CDSPinsFlags{File: file}).Info(); on || err != nil {
		t.Fatalf("missing file (cluster without HA CDS): %v %v", on, err)
	}
	if err := os.WriteFile(file, []byte(`{"cluster_id":"c1","decree_key":"-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	info, on, err := (CDSPinsFlags{File: file}).Info()
	if !on || err != nil || info.ClusterID != "c1" {
		t.Fatalf("file: %+v %v %v", info, on, err)
	}
	args := info.Args()
	back, on, err := (CDSPinsFlags{ClusterID: args[0][len("--cds-cluster-id="):], DecreeKey: args[1][len("--cds-decree-key="):]}).Info()
	if !on || err != nil || back.ClusterID != "c1" {
		t.Fatalf("flags round trip: %+v %v %v", back, on, err)
	}
	for name, f := range map[string]CDSPinsFlags{
		"file and flags": {File: file, ClusterID: "c1"},
		"id only":        {ClusterID: "c1"},
		"key only":       {DecreeKey: "k"},
	} {
		if _, _, err := f.Info(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := decreeKeyDER("not pem"); err == nil {
		t.Fatal("a non-PEM decree key was accepted")
	}
}
