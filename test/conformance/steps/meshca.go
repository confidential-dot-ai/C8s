package steps

import (
	"fmt"
	"strings"
	"time"
)

type refreshVerdict int

const (
	refreshWait refreshVerdict = iota
	refreshOK
	refreshFailed
)

// caRefreshVerdict reads the mesh proxy's log, with timestamps, for its
// last CA refresh. The verify set fills on the first refresh after the proxy
// switched to its CDS leaf, and a failed refresh keeps the set it had.
// Success is logged at debug level only, so the observation is the latest
// tick (one interval apart from "CA bundle refresh enabled", or from the
// first line) that has had margin to be logged, with no failure logged after
// it. It also gives how long until the next tick has.
func caRefreshVerdict(log string, interval, margin time.Duration, now time.Time) (refreshVerdict, time.Duration, error) {
	if strings.TrimSpace(log) == "" {
		return refreshWait, margin, nil
	}
	var anchor time.Time
	var failures []time.Time
	for i, line := range strings.Split(strings.TrimSpace(log), "\n") {
		stamp, msg, _ := strings.Cut(line, " ")
		t, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return 0, 0, fmt.Errorf("the mesh proxy's log line %q: %w", line, err)
		}
		switch {
		case i == 0, strings.Contains(msg, "CA bundle refresh enabled"):
			anchor, failures = t, nil
		case strings.Contains(msg, "CA bundle refresh failed"):
			failures = append(failures, t)
		}
	}
	ticks := (now.Sub(anchor) - margin) / interval
	wait := max(time.Second, anchor.Add((ticks+1)*interval+margin).Sub(now))
	if ticks < 1 {
		return refreshWait, wait, nil
	}
	last := anchor.Add(ticks * interval)
	for _, f := range failures {
		if !f.Before(last) {
			return refreshFailed, wait, nil
		}
	}
	return refreshOK, wait, nil
}
