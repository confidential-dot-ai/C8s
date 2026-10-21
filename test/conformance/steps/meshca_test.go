package steps

import (
	"testing"
	"time"
)

func TestCARefreshVerdict(t *testing.T) {
	start := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	first := "2026-10-21T00:00:00.5Z level=INFO msg=\"mesh proxy starting\"\n"
	enabled := "2026-10-21T00:01:00.123456789Z level=INFO msg=\"CA bundle refresh enabled\"\n"
	failed := "2026-10-21T00:06:10Z level=WARN msg=\"CA bundle refresh failed\"\n"
	for _, tc := range []struct {
		name string
		log  string
		now  time.Time
		want refreshVerdict
		wait time.Duration
	}{
		{"before the first tick", first + enabled, start.Add(3 * time.Minute), refreshWait, 3*time.Minute + 35*time.Second},
		{"a tick with no failure", first + enabled, start.Add(7 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
		{"a tick that failed", first + enabled + failed, start.Add(7 * time.Minute), refreshFailed, 4*time.Minute + 35*time.Second},
		{"a failure before the last tick", first + enabled + failed, start.Add(12 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
		{"no enable line anchors on the first", first, start.Add(6 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
		{"no log yet", "", start, refreshWait, 35 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, wait, err := caRefreshVerdict(tc.log, 5*time.Minute, 35*time.Second, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || wait.Truncate(time.Second) != tc.wait {
				t.Errorf("got %v, wait %v; want %v, wait %v", got, wait, tc.want, tc.wait)
			}
		})
	}
}

func TestCARefreshVerdictRejectsAnUnstampedLine(t *testing.T) {
	if _, _, err := caRefreshVerdict("CA bundle refresh enabled", time.Minute, time.Second, time.Now()); err == nil {
		t.Error("no error")
	}
}
