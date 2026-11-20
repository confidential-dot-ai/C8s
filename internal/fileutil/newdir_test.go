package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A half-written set is worse than none: the caller would launch from a
// directory missing one of the files that only make sense together.
func TestWriteNewDirLeavesNothingBehindOnFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	err := WriteNewDir(dir, 0o755, []NewFile{
		{Name: "config.yaml", Data: []byte("a"), Mode: 0o644},
		{Name: "nested/pin.json", Data: []byte("b"), Mode: 0o644},
	})
	if err == nil {
		t.Fatal("WriteNewDir accepted a file it cannot write")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("output directory survived a failed write: %v", err)
	}
}

func TestWriteNewDirRefusesAnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	files := []NewFile{{Name: "config.yaml", Data: []byte("a"), Mode: 0o644}}
	if err := WriteNewDir(dir, 0o755, files); err == nil {
		t.Fatal("WriteNewDir wrote into a directory that already exists")
	}
}

func TestWriteNewDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	if err := WriteNewDurable(path, []byte("signed"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", info, err)
	}
	if err := WriteNewDurable(path, []byte("again"), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing path: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "signed" {
		t.Fatalf("refusal changed the file: %q, %v", got, err)
	}
}
