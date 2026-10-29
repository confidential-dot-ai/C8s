package cds

import (
	"strings"
	"testing"
)

// The guard sees the filesystem running out of space whoever fills it (a
// file other than the store, another tenant of a shared filesystem), and
// refuses before SQLite meets ENOSPC; on a volume of its own the 45% rule
// still decides first.
func TestAllowlistFullGuardSeesTheVolumeFilling(t *testing.T) {
	saved := statVolume
	t.Cleanup(func() { statVolume = saved })
	const size = 1 << 30
	live := func() (int64, error) { return 1 << 20, nil } // a small store
	for _, c := range []struct {
		name        string
		used, avail uint64
		limit       int64
		refused     string
	}{
		{"room left", 100 << 20, size - 100<<20, 0, ""},
		{"another file fills the volume", size - 20<<20, 20 << 20, 0, "nearly out of space"},
		{"just above the reserve", size - 33<<20, 33 << 20, 0, ""},
		{"just below the reserve", size - 31<<20, 31 << 20, 0, "nearly out of space"},
		// A small volume of its own: the reserve is capped at 55% of it, so
		// the 45% rule, not the reserve, decides.
		{"small volume, 40% store", 0, 0, 64 << 20, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			used, avail, sz := c.used, c.avail, uint64(size)
			l := live
			if c.limit > 0 {
				sz = uint64(c.limit)
				used, avail = sz*40/100, sz*60/100
				l = func() (int64, error) { return int64(used), nil } //nolint:gosec // a test volume
			}
			statVolume = func(string) (uint64, uint64, uint64, error) { return used, sz, avail, nil }
			err := allowlistFullGuard(t.TempDir(), c.limit, l)()
			switch {
			case c.refused == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.refused != "" && (err == nil || !strings.Contains(err.Error(), c.refused)):
				t.Fatalf("got %v, want a refusal %q", err, c.refused)
			}
		})
	}
}
