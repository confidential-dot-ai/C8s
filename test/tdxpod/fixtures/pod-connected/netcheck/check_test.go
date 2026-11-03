package main

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func state(age float64, ready, healthy bool) map[string]any {
	return map[string]any{"podUID": "test", "instance": "instance", "firstPass": 0, "elapsed": age, "checkedAt": age, "ready": ready, "checks": sixChecks(healthy)}
}

// runChecker feeds the checker one report per read and returns its exit
// status and how many reads it took. The checker's own clock stays at zero,
// so only the reports' elapsed times drive the verdict.
func runChecker(t *testing.T, states []map[string]any) (int, int) {
	t.Helper()
	calls := 0
	c := &checker{cfg: config{PodUID: "test"}, now: func() float64 { return 0 }, sleep: func(time.Duration) {}, reportURL: "http://127.0.0.1:8080/report"}
	c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != c.reportURL {
			return nil, errors.New("read something other than the local report")
		}
		if calls >= len(states) {
			t.Fatal("the checker read past the scripted reports")
		}
		calls++
		return jsonResponse(http.StatusOK, states[calls-1]), nil
	})
	return c.run(io.Discard), calls
}

func TestCheckerDoesNotAcceptStaleSuccessAfterSoak(t *testing.T) {
	stale := state(3900, true, true)
	stale["checkedAt"] = 3000
	result, calls := runChecker(t, []map[string]any{state(120, true, true), state(300, false, true), state(480, true, true), stale, state(3910, true, true)})
	if result != 0 || calls != 5 {
		t.Fatalf("exit %d after %d reads, want 0 after 5", result, calls)
	}
}

func TestCheckerWaitsFullSoakAndDoesNotAcceptAFailedFinalCheck(t *testing.T) {
	result, calls := runChecker(t, []map[string]any{state(120, true, true), state(300, false, true), state(480, true, true), state(3899, true, true), state(3900, false, false), state(3910, true, true)})
	if result != 0 || calls != 6 {
		t.Fatalf("exit %d after %d reads, want 0 after 6", result, calls)
	}
}

func TestCheckerRefusesMissingNegativeReadinessTransition(t *testing.T) {
	result, _ := runChecker(t, []map[string]any{state(120, true, true), state(480, true, true), state(700, true, true)})
	if result != 11 {
		t.Fatalf("exit %d, want 11", result)
	}
}

func TestCheckerIgnoresAnotherPodAndTimesOutOnItsOwnClock(t *testing.T) {
	foreign := state(120, true, true)
	foreign["podUID"] = "other"
	now := 0.0
	calls := 0
	c := &checker{cfg: config{PodUID: "test"}, now: func() float64 { return now }, sleep: func(d time.Duration) { now += d.Seconds() }, reportURL: "http://127.0.0.1:8080/report"}
	c.transport = roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, foreign), nil
	})
	if result := c.run(io.Discard); result != 12 || now < 5400 || calls == 0 {
		t.Fatalf("exit %d at %vs after %d reads, want 12 past the checker deadline", result, now, calls)
	}
	now, calls = 0, 0
	c.transport = roundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(http.StatusOK, map[string]any{"podUID": "test", "firstPass": nil, "elapsed": now, "checks": map[string]any{}}), nil
	})
	if result := c.run(io.Discard); result != 10 || now <= 1200 || now > 1220 {
		t.Fatalf("exit %d at %vs, want 10 just past the initial deadline", result, now)
	}
}
