package allowlist

import "testing"

// A store whose database is gone reports errors from every read and write,
// instead of an empty history or a silently skipped write.
func TestClosedStoreReportsErrors(t *testing.T) {
	s, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dump(); err == nil {
		t.Error("Dump")
	}
	if err := s.Restore(Snapshot{}); err == nil {
		t.Error("Restore")
	}
	if _, err := s.History(); err == nil {
		t.Error("History")
	}
	if _, _, err := s.Object("sha256:00"); err == nil {
		t.Error("Object")
	}
	if _, err := s.HistoryLen(); err == nil {
		t.Error("HistoryLen")
	}
	if _, err := s.PruneHistory(1); err == nil {
		t.Error("PruneHistory")
	}
	if _, err := s.LiveBytes(); err == nil {
		t.Error("LiveBytes")
	}
	if _, err := s.HistoryKeepForBytes(1 << 20); err == nil {
		t.Error("HistoryKeepForBytes")
	}
	if err := s.SignPolicy([]byte("{}"), "h.p.s"); err == nil {
		t.Error("SignPolicy")
	}
	if err := s.ConsumeToken("h.p.s"); err == nil {
		t.Error("ConsumeToken")
	}
	if err := s.StartJournal(); err == nil {
		t.Error("StartJournal")
	}
}

func TestSnapshotUnmarshalRejectsBadCells(t *testing.T) {
	var sn Snapshot
	for name, raw := range map[string]string{
		"not JSON":          `{`,
		"fractional number": `{"t":[{"c":{"v":1.5}}]}`,
		"not a scalar":      `{"t":[{"c":{"v":{"x":1}}}]}`,
	} {
		if err := sn.UnmarshalJSON([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := sn.UnmarshalJSON([]byte(`{"t":[{"c":{},"d":{"v":"s"},"e":{"v":7}}]}`)); err != nil {
		t.Fatal(err)
	}
	row := sn["t"][0]
	if row["c"] != nil || row["d"] != "s" || row["e"] != int64(7) {
		t.Fatalf("row %#v", row)
	}
}
