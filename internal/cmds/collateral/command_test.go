package collateral

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/sitecollateral"
)

func TestCheckRejectsExtraOrCorruptObjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := sitecollateral.Manifest{
		Target: "inventory", Generation: 1, ExpiresAt: time.Now().Add(time.Hour),
		Objects: map[string]sitecollateral.Object{"unexpected": {}},
	}
	run := func(want string) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := NewCmd()
		cmd.SetArgs([]string{"check-intel", "reference-quote.bin", path, dir})
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q, got %v", want, err)
		}
	}
	run("exactly four")
	pin := strings.Repeat("a", 64)
	for _, name := range []string{"a", "b", "c", "d"} {
		m.Objects[name] = sitecollateral.Object{SHA256: pin}
	}
	delete(m.Objects, "unexpected")
	if err := os.WriteFile(filepath.Join(dir, pin), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	run("invalid content digest")
}
