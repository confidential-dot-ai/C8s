//go:build !linux

package fileutil

import (
	"fmt"
	"os"
)

// RequireRAMBackedRoot fails closed off Linux, where the filesystem behind an
// open directory handle cannot be proven memory-backed.
func RequireRAMBackedRoot(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("cannot verify a nil directory root is RAM-backed: linux only")
	}
	return fmt.Errorf("cannot verify %s is RAM-backed: linux only", root.Name())
}
