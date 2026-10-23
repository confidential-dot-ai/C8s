package cds

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// haAllowlistMaxFill is how full an HA replica's allowlist volume may get. A
// replica that joins restores a full copy of the store onto its own volume of
// the same size, so a store more than about half full can never be copied
// and no replica could be replaced.
const haAllowlistMaxFill = 0.45

// allowlistFullGuard is an HA replica's allowlist Full check. limit (if
// positive) is the volume size when the filesystem does not report it. live
// is the store's own data size (pages in use): a pruned history frees pages
// SQLite keeps for reuse, so the volume's used space stays at its peak and
// would refuse writes for good, while what a replacement copies is only the
// live data.
func allowlistFullGuard(dir string, limit int64, live func() (int64, error)) func() error {
	return func() error {
		used, size, err := volumeUsage(dir)
		if err != nil {
			return nil // cannot tell: do not refuse
		}
		if n, err := live(); err == nil && n >= 0 && uint64(n) < used {
			used = uint64(n)
		}
		if limit > 0 && (size == 0 || uint64(limit) < size) {
			size = uint64(limit)
		}
		if size == 0 || float64(used) <= haAllowlistMaxFill*float64(size) {
			return nil
		}
		return fmt.Errorf("allowlist store nearly full: %d of %d bytes used (limit %.0f%%); lower the allowlist history bound (--allowlist-history-versions, --allowlist-history-bytes) or raise the volume size", used, size, haAllowlistMaxFill*100)
	}
}

// volumeUsage is the used and total bytes of the filesystem holding dir.
func volumeUsage(dir string) (used, size uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return (st.Blocks - st.Bfree) * bs, st.Blocks * bs, nil
}
