package steps

import (
	"testing"
	"time"
)

func TestCARefreshVerdict(t *testing.T) {
	start := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	head := "5m 2026-10-21T00:00:00Z\n"
	enabled := "2026-10-21T00:01:00.123456789Z level=INFO msg=\"CA bundle refresh enabled\"\n"
	failedAt := func(t string) string { return t + " level=WARN msg=\"CA bundle refresh failed\"\n" }
	for _, tc := range []struct {
		name   string
		answer string
		now    time.Time
		want   refreshVerdict
		wait   time.Duration
	}{
		{"before the first tick", head + enabled, start.Add(3 * time.Minute), refreshWait, 3*time.Minute + 35*time.Second},
		{"a tick with no failure", head + enabled, start.Add(7 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
		{"a tick that failed", head + enabled + failedAt("2026-10-21T00:06:10Z"), start.Add(7 * time.Minute), refreshFailed, 4*time.Minute + 35*time.Second},
		{"a failure before the last tick", head + enabled + failedAt("2026-10-21T00:06:10Z"), start.Add(12 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
		{"no enable line anchors on the start", head, start.Add(6 * time.Minute), refreshOK, 4*time.Minute + 35*time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, wait, err := caRefreshVerdict(tc.answer, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want || wait != tc.wait {
				t.Errorf("got %v, wait %v; want %v, wait %v", got, wait, tc.want, tc.wait)
			}
		})
	}
}

func TestCARefreshVerdictRejectsAMalformedAnswer(t *testing.T) {
	for _, answer := range []string{"", "5m", "soon 2026-10-21T00:00:00Z", "5m yesterday"} {
		if _, _, err := caRefreshVerdict(answer, time.Now()); err == nil {
			t.Errorf("%q: no error", answer)
		}
	}
}
