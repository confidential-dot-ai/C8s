package steps

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// refreshMargin: a CA refresh is logged within --cds-op-timeout (30s) of its
// tick.
const refreshMargin = 35 * time.Second

type refreshVerdict int

const (
	refreshWait refreshVerdict = iota
	refreshOK
	refreshFailed
)

// caRefreshVerdict reads mesh_ca_log's answer: its first line the poll
// interval and the proxy container's start, then the proxy's log with
// timestamps. The verify set fills on the first CA refresh after the proxy
// switched to its CDS leaf, and a failed refresh keeps the set it had.
// Success is logged at debug level only, so the observation is the latest
// tick (one interval apart from "CA bundle refresh enabled") with no failure
// logged after it. It also gives how long until the next tick is logged.
func caRefreshVerdict(answer string, now time.Time) (refreshVerdict, time.Duration, error) {
	head, log, _ := strings.Cut(answer, "\n")
	intervalArg, startedArg, ok := strings.Cut(head, " ")
	if !ok {
		return 0, 0, fmt.Errorf("mesh_ca_log answered %q", head)
	}
	interval, err := time.ParseDuration(intervalArg)
	if err != nil || interval <= 0 {
		return 0, 0, fmt.Errorf("mesh_ca_log's interval %q", intervalArg)
	}
	anchor, err := logTime(startedArg)
	if err != nil {
		return 0, 0, err
	}
	var failures []time.Time
	for _, line := range strings.Split(log, "\n") {
		stamp, msg, _ := strings.Cut(line, " ")
		switch {
		case strings.Contains(msg, "CA bundle refresh enabled"):
			if anchor, err = logTime(stamp); err != nil {
				return 0, 0, err
			}
			failures = nil
		case strings.Contains(msg, "CA bundle refresh failed"):
			t, err := logTime(stamp)
			if err != nil {
				return 0, 0, err
			}
			failures = append(failures, t)
		}
	}
	ticks := int64(math.Floor(float64(now.Sub(anchor)-refreshMargin) / float64(interval)))
	wait := max(time.Second, anchor.Add(time.Duration(ticks+1)*interval+refreshMargin).Sub(now))
	if ticks < 1 {
		return refreshWait, wait, nil
	}
	last := anchor.Add(time.Duration(ticks) * interval)
	for _, f := range failures {
		if !f.Before(last.Add(-time.Second)) {
			return refreshFailed, wait, nil
		}
	}
	return refreshOK, wait, nil
}

// logTime parses a kubectl or container-status timestamp to the second.
func logTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("a log timestamp: %w", err)
	}
	return t.Truncate(time.Second), nil
}
