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
	for deadline := time.Now().Add(timeout); ; time.Sleep(time.Second) {
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
	first, rest, _ := strings.Cut(out, "\n")
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return 0, "", nil, errors.New("the backend answered nothing")
	}
	if status, err = strconv.Atoi(fields[0]); err != nil {
		return 0, "", nil, fmt.Errorf("status %q: %w", fields[0], err)
	}
	return status, strings.Join(fields[1:], " "), []byte(rest), nil
}
