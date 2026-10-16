package cds

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestYieldIfHA(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "cds-mode")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := yieldIfHA(write("singleton\n")); err != nil {
		t.Fatalf("singleton cluster: %v", err)
	}
	if err := yieldIfHA(write("ha\n")); !errors.Is(err, errYield) {
		t.Fatalf("HA cluster: %v", err)
	}
	for _, bad := range []string{"", "maybe"} {
		if err := yieldIfHA(write(bad)); err == nil || errors.Is(err, errYield) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if err := yieldIfHA(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
