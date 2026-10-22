package cds

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAllowlistFullGuard(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "allowlist.db")
	if g, err := allowlistFullGuard(config{allowlistDB: db}); err != nil || g != nil {
		t.Fatalf("singleton default: guard %v, %v", g != nil, err)
	}
	ha := config{allowlistDB: db, ha: haConfig{clusterID: "c1"}}
	used, _, err := volumeUsage(dir)
	if err != nil {
		t.Skip(err)
	}
	// A limit far above what is used: writes pass.
	ha.allowlistMaxBytes = "1Ei"
	g, err := allowlistFullGuard(ha)
	if err != nil || g == nil || g() != nil {
		t.Fatalf("HA default with room: %v", err)
	}
	// A limit just above what is used (more than 45% full): refused.
	ha.allowlistMaxBytes = strconv.FormatUint(used+used/10, 10)
	if g, _ = allowlistFullGuard(ha); g == nil || g() == nil || !strings.Contains(g().Error(), "nearly full") {
		t.Fatal("a nearly full store took a write")
	}
	// The store's live data, not the volume's peak use, decides: pages a
	// pruned history freed must not block writes for good.
	small := func() (int64, error) { return 1, nil }
	if g, _ = allowlistFullGuard(ha, small); g == nil || g() != nil {
		t.Fatal("freed pages still counted against the store")
	}
	if g, _ = allowlistFullGuard(ha, func() (int64, error) { return 0, os.ErrInvalid }); g() == nil {
		t.Fatal("a failing live count hid a full volume")
	}
	for _, bad := range []config{{allowlistDB: db, allowlistMaxFill: 1.5}, {allowlistDB: db, allowlistMaxFill: 0.5, allowlistMaxBytes: "lots"}} {
		if _, err := allowlistFullGuard(bad); err == nil {
			t.Fatalf("bad flags accepted: %+v", bad)
		}
	}
	// A volume that cannot be read does not refuse.
	if g, _ := allowlistFullGuard(config{allowlistDB: filepath.Join(dir, "gone", "x", "db"), allowlistMaxFill: 0.1}); g() != nil {
		t.Fatal("unknown usage refused a write")
	}
	_ = os.Remove(db)
}
