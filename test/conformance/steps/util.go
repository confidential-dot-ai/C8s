package steps

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// poll calls fn once a second until it reports done or timeout has passed,
// and says whether it got there; fn's error ends the wait.
func poll(timeout time.Duration, fn func() (bool, error)) (bool, error) {
	return pollEvery(time.Second, timeout, fn)
}

// pollEvery is poll at a cadence of its own, for a condition that moves on a
// slower tick than a second.
func pollEvery(every, timeout time.Duration, fn func() (bool, error)) (bool, error) {
	for deadline := time.Now().Add(timeout); ; time.Sleep(every) {
		done, err := fn()
		if err != nil || done {
			return done, err
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
	}
}

// statusLine splits a backend answer of the form "<status>[ <more>]", then
// the body on the lines after.
func statusLine(out string) (status int, more string, body []byte, err error) {
	// kubectl exec interleaves the command's stderr before its stdout, so a
	// diagnostic may precede the status line; the status line is the first
	// one that opens with a number.
	for {
		var first string
		first, out, _ = strings.Cut(out, "\n")
		fields := strings.Fields(first)
		if len(fields) == 0 {
			if out == "" {
				return 0, "", nil, errors.New("the backend answered nothing")
			}
			continue
		}
		if status, err = strconv.Atoi(fields[0]); err != nil {
			if out == "" {
				return 0, "", nil, fmt.Errorf("status %q: %w", fields[0], err)
			}
			continue
		}
		return status, strings.Join(fields[1:], " "), []byte(out), nil
	}
}

// cdsArg is the value of a flag the CDS runs with. The chart sets every one
// the scenarios read, so an unset one is a broken install, not a default.
func (w *world) cdsArg(flag string) (string, error) {
	out, err := w.be.call("cds_arg", flag)
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("the CDS runs without --%s, which the chart sets", flag)
	}
	return out, nil
}
