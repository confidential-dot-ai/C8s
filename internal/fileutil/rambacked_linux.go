package fileutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RequireRAMBackedRoot fails unless the directory held by root sits on tmpfs
// or ramfs. Callers staging secrets (join tokens, private keys) use it to
// enforce "memory only" rather than merely documenting it: on any other
// filesystem the bytes are readable by the host. The check uses the open
// handle rather than root.Name(), so a pathname replacement cannot change the
// filesystem that is verified.
func RequireRAMBackedRoot(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("cannot verify a nil directory root is RAM-backed")
	}
	dir, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	defer dir.Close()

	var st unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &st); err != nil {
		return fmt.Errorf("statfs %s: %w", root.Name(), err)
	}
	// f_type is a 32-bit magic; the field's signedness varies by GOARCH.
	if m := uint32(st.Type); m != uint32(unix.TMPFS_MAGIC) && m != uint32(unix.RAMFS_MAGIC) {
		return fmt.Errorf("%s is not RAM-backed (fs magic %#x)", root.Name(), m)
	}
	return nil
}
