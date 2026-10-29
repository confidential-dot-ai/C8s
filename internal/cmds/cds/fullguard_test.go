package cds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowlistFullGuard(t *testing.T) {
	// A modelled volume, not the test host's (whose use is arbitrary): 3 GiB
	// of 10 GiB used.
	const used, size = 3 << 30, 10 << 30
	saved := statVolume
	t.Cleanup(func() { statVolume = saved })
	statVolume = func(string) (uint64, uint64, uint64, error) { return used, size, size - used, nil }
	dir := t.TempDir()
	all := func() (int64, error) { return used, nil }
	// A limit far above what is used: writes pass.
	if err := allowlistFullGuard(dir, 1<<60, all)(); err != nil {
		t.Fatalf("room left: %v", err)
	}
	// A limit just above what is used (more than 45% full): refused.
	near := int64(used + used/10)
	if err := allowlistFullGuard(dir, near, all)(); err == nil || !strings.Contains(err.Error(), "nearly full") {
		t.Fatalf("a nearly full store took a write: %v", err)
	}
	// The store's live data, not the volume's peak use, decides: pages a
	// pruned history freed must not block writes for good.
	if err := allowlistFullGuard(dir, near, func() (int64, error) { return 1, nil })(); err != nil {
		t.Fatalf("freed pages still counted against the store: %v", err)
	}
	if err := allowlistFullGuard(dir, near, func() (int64, error) { return 0, os.ErrInvalid })(); err == nil {
		t.Fatal("a failing live count hid a full volume")
	}
	// A volume that cannot be read does not refuse.
	statVolume = volumeStat
	if err := allowlistFullGuard(filepath.Join(dir, "gone"), 1, all)(); err != nil {
		t.Fatalf("unknown usage refused a write: %v", err)
	}
}
