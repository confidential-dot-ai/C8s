package cds

import (
	"fmt"
	"path/filepath"
	"syscall"

	"k8s.io/apimachinery/pkg/api/resource"
)

// haAllowlistMaxFill is the default --allowlist-max-fill of an HA replica. A
// replica that joins restores a full copy of the store onto its own volume of
// the same size, so a store more than about half full can never be copied
// and no replica could be replaced.
const haAllowlistMaxFill = 0.45

// allowlistFullGuard returns the allowlist handler's Full check, or nil when
// it is off. The history keeps every document, so the store only grows.
func allowlistFullGuard(cfg config) (func() error, error) {
	fill := cfg.allowlistMaxFill
	if fill == 0 && (cfg.ha.clusterID != "" || cfg.ha.configFile != "") {
		fill = haAllowlistMaxFill
	}
	if fill <= 0 {
		return nil, nil
	}
	if fill >= 1 {
		return nil, fmt.Errorf("--allowlist-max-fill %v: want a fraction below 1", fill)
	}
	var limit uint64
	if cfg.allowlistMaxBytes != "" {
		q, err := resource.ParseQuantity(cfg.allowlistMaxBytes)
		if err != nil || q.Value() <= 0 {
			return nil, fmt.Errorf("--allowlist-max-bytes %q: %v", cfg.allowlistMaxBytes, err)
		}
		limit = uint64(q.Value())
	}
	dir := filepath.Dir(cfg.allowlistDB)
	return func() error {
		used, size, err := volumeUsage(dir)
		if err != nil {
			return nil // cannot tell: do not refuse
		}
		if limit > 0 && (size == 0 || limit < size) {
			size = limit
		}
		if size == 0 || float64(used) <= fill*float64(size) {
			return nil
		}
		return fmt.Errorf("allowlist store nearly full: %d of %d bytes used (limit %.0f%%); the allowlist history keeps every document, so free space or raise the volume size", used, size, fill*100)
	}, nil
}

// volumeUsage is the used and total bytes of the filesystem holding dir.
func volumeUsage(dir string) (used, size uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return (st.Blocks - st.Bfree) * bs, st.Blocks * bs, nil
}
