package policymeasure

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, JournalName)
	if got, err := Read(path); err != nil || got != nil {
		t.Fatalf("Read(missing) = %v, %v; want none", got, err)
	}
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	if err := os.WriteFile(path, []byte(p+"\n"+q+"\n"+p+"\npartial-line"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(path); err != nil || !slices.Equal(got, []string{p, q}) {
		t.Fatalf("Read = %v, %v; want [%s %s]", got, err, p, q)
	}
}
