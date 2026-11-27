package collateral

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/sitecollateral"
)

func TestCheckRejectsExtraOrCorruptObjects(t *testing.T) {
	dir := t.TempDir()

	m := sitecollateral.Manifest{
		Target: "inventory", Generation: 1, ExpiresAt: time.Now().Add(time.Hour),
		Objects: map[string]sitecollateral.Object{"unexpected": {}},
	}
	run := func(want string) {
		t.Helper()
		if err := check(t.Context(), "reference-quote.bin", &m, dir, time.Now(), io.Discard); err == nil || !strings.Contains(err.Error(), want) {
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
