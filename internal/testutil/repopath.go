package testutil

import (
	"os"
	"path/filepath"
)

// RepoPath returns the path of elem under the repository root, found from the
// test's working directory.
func RepoPath(elem ...string) string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(append([]string{dir}, elem...)...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("repository root not found above the test directory")
		}
		dir = parent
	}
}
