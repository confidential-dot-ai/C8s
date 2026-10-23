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

// fullGuardReserve is the free space below which the guard refuses writes
// whatever fills the filesystem: room for a few in-flight writes (each
// journals a document of up to the 1 MiB write body cap, plus SQLite and
// WAL overhead) before SQLite meets ENOSPC, which stops the replica.
const fullGuardReserve = 32 << 20

// allowlistFullGuard is an HA replica's allowlist Full check. limit (if
// positive) is the volume size when the filesystem does not report it. live
// is the store's own data size (pages in use): a pruned history frees pages
// SQLite keeps for reuse, so the volume's used space stays at its peak and
// would refuse writes for good, while what a replacement copies is only the
// live data. The store's directory may sit on a filesystem shared with
// other files (and in tests with other replicas' stores), so their space
// does not count against the store; instead writes are also refused when
// the filesystem itself is nearly out of space, whoever filled it, before
// SQLite meets ENOSPC.
func allowlistFullGuard(dir string, limit int64, live func() (int64, error)) func() error {
	return func() error {
		used, size, avail, err := statVolume(dir)
		if err != nil {
			return nil // cannot tell: do not refuse
		}
		if n, err := live(); err == nil && n >= 0 && uint64(n) < used {
			used = uint64(n)
		}
		if limit > 0 && (size == 0 || uint64(limit) < size) {
			size = uint64(limit)
		}
		if size == 0 {
			return nil
		}
		if float64(used) > haAllowlistMaxFill*float64(size) {
			return fmt.Errorf("allowlist store nearly full: %d of %d bytes used (limit %.0f%%); lower the allowlist history bound (--allowlist-history-versions, --allowlist-history-bytes) or raise the volume size", used, size, haAllowlistMaxFill*100)
		}
		// On a volume of its own the 45% rule leaves 55% free, so this only
		// trips first on a filesystem shared with other files.
		if reserve := min(uint64(fullGuardReserve), uint64((1-haAllowlistMaxFill)*float64(size))); avail < reserve {
			return fmt.Errorf("allowlist volume nearly out of space: %d bytes available, writes are refused below %d; free space on the volume holding %s", avail, reserve, dir)
		}
		return nil
	}
}

// statVolume is volumeStat; a var so tests can model a full filesystem.
var statVolume = volumeStat

// volumeUsage is the used and total bytes of the filesystem holding dir.
func volumeUsage(dir string) (used, size uint64, err error) {
	used, size, _, err = volumeStat(dir)
	return used, size, err
}

// volumeStat is the used, total and available (to an unprivileged writer,
// which CDS is) bytes of the filesystem holding dir.
func volumeStat(dir string) (used, size, avail uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return (st.Blocks - st.Bfree) * bs, st.Blocks * bs, st.Bavail * bs, nil
}
