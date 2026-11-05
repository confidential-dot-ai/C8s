package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type transition struct {
	at    time.Duration
	ready bool
}

type proof struct {
	code        int
	exit        bool
	transitions []transition
	withdrawn   [][2]int // /ready and /live statuses right after each withdrawal
	elapsed     time.Duration
	files       []string
}

// runProbe drives the probe with a scripted CDS: reachable says whether a
// dial at a moment succeeds (true), is refused (false) or fails with the
// given errno. Time advances only through sleep.
func runProbe(t *testing.T, args []string, reachable func(at time.Duration) any) proof {
	t.Helper()
	dir := t.TempDir()
	p, code := newProbe(args)
	if code != 0 {
		t.Fatalf("usage exit %d", code)
	}
	now := time.Duration(0)
	p.dir = dir
	p.now = func() time.Duration { return now }
	p.sleep = func(d time.Duration) { now += d }
	p.dial = func(address string, timeout time.Duration) error {
		if address != "203.0.113.5:8443" || timeout != 2*time.Second {
			t.Fatalf("dialled %s with %v", address, timeout)
		}
		switch result := reachable(now).(type) {
		case bool:
			if result {
				return nil
			}
			return &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}
		case syscall.Errno:
			return &os.SyscallError{Syscall: "connect", Err: result}
		}
		panic("unreachable")
	}
	var pr proof
	p.onReady = func(ready bool) {
		pr.transitions = append(pr.transitions, transition{now, ready})
		if !ready {
			status := func(path string) int {
				rec := httptest.NewRecorder()
				p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				return rec.Code
			}
			pr.withdrawn = append(pr.withdrawn, [2]int{status("/ready"), status("/live")})
		}
	}
	if code := p.prepare(); code != 0 {
		t.Fatalf("prepare exit %d", code)
	}
	if p.restarted() {
		t.Fatal("a fresh directory counted as a restart")
	}
	pr.code, pr.exit = p.observe()
	pr.elapsed = now
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		pr.files = append(pr.files, e.Name())
	}
	return pr
}

func equalTransitions(got []transition, want ...transition) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func sec(s int) time.Duration { return time.Duration(s) * time.Second }

func TestRenewalWithdrawsReadinessThenRecoversWithoutExit(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5", "3900"}, func(at time.Duration) any { return at < sec(2) || at >= sec(3910) })
	if pr.exit || !equalTransitions(pr.transitions, transition{0, true}, transition{sec(3902), false}, transition{sec(3910), true}) {
		t.Fatalf("exit=%v code=%d transitions=%v", pr.exit, pr.code, pr.transitions)
	}
	if len(pr.withdrawn) != 1 || pr.withdrawn[0] != [2]int{http.StatusServiceUnavailable, http.StatusOK} {
		t.Fatalf("withdrawal did not fail /ready and keep /live: %v", pr.withdrawn)
	}
	if len(pr.files) != 0 {
		t.Fatalf("renewal mode wrote %v", pr.files)
	}
}

func TestReachabilityResetsTheContinuousOutage(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5", "3900"}, func(at time.Duration) any {
		return at < sec(2) || (at >= sec(500) && at < sec(502)) || at >= sec(4410)
	})
	if pr.exit || !equalTransitions(pr.transitions, transition{0, true}, transition{sec(4402), false}, transition{sec(4410), true}) || len(pr.files) != 0 {
		t.Fatalf("exit=%v transitions=%v files=%v", pr.exit, pr.transitions, pr.files)
	}
}

func TestInitialUnreachabilityCannotConfirmAnOutage(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5", "3900"}, func(time.Duration) any { return false })
	if !pr.exit || pr.code != 45 || pr.elapsed != sec(60) || len(pr.transitions) != 0 {
		t.Fatalf("exit=%v code=%d at %v transitions=%v", pr.exit, pr.code, pr.elapsed, pr.transitions)
	}
}

func TestNontransportFailureCannotConfirmAnOutage(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5", "3900"}, func(at time.Duration) any {
		if at < sec(2) {
			return true
		}
		return syscall.EACCES
	})
	if !pr.exit || pr.code != 43 || !equalTransitions(pr.transitions, transition{0, true}) {
		t.Fatalf("exit=%v code=%d transitions=%v", pr.exit, pr.code, pr.transitions)
	}
}

func TestNoOutageHitsTheBoundedDeadline(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5", "3900"}, func(time.Duration) any { return true })
	if !pr.exit || pr.code != 46 || pr.elapsed != sec(4800) || !equalTransitions(pr.transitions, transition{0, true}) {
		t.Fatalf("exit=%v code=%d at %v", pr.exit, pr.code, pr.elapsed)
	}
}

func TestShortOutageStillExitsOnceAfterTwoMinutes(t *testing.T) {
	pr := runProbe(t, []string{"203.0.113.5"}, func(at time.Duration) any { return at < sec(2) })
	if !pr.exit || pr.code != 0 || pr.elapsed != sec(122) || !equalTransitions(pr.transitions, transition{0, true}) {
		t.Fatalf("exit=%v code=%d at %v transitions=%v", pr.exit, pr.code, pr.elapsed, pr.transitions)
	}
	if len(pr.files) != 1 || pr.files[0] != "once" {
		t.Fatalf("restart marker missing: %v", pr.files)
	}
}

func TestProbeRefusesUnwritableDirectoryAndForeignHold(t *testing.T) {
	p, _ := newProbe([]string{"203.0.113.5"})
	p.dir = filepath.Join(t.TempDir(), "missing")
	if code := p.prepare(); code != 42 {
		t.Fatalf("exit %d for a missing restart directory, want 42", code)
	}
	for _, hold := range []string{"3899", "x"} {
		p, _ := newProbe([]string{"203.0.113.5", hold})
		p.dir = t.TempDir()
		if code := p.prepare(); code != 47 {
			t.Fatalf("exit %d for hold %q, want 47", code, hold)
		}
	}
	if _, code := newProbe(nil); code != 2 {
		t.Fatal("no host did not fail usage")
	}
	if _, code := newProbe([]string{"a", "b", "c"}); code != 2 {
		t.Fatal("three arguments did not fail usage")
	}
}

func TestRestartedProbeStartsReadyAndServesOnlyTheProbes(t *testing.T) {
	p, _ := newProbe([]string{"203.0.113.5"})
	p.dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(p.dir, "once"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := p.prepare(); code != 0 || !p.restarted() {
		t.Fatal("the marker did not make the restarted process ready")
	}
	for path, want := range map[string]int{"/live": http.StatusOK, "/ready": http.StatusOK, "/report": http.StatusServiceUnavailable, "/": http.StatusServiceUnavailable} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s: %d, want %d", path, rec.Code, want)
		}
	}
	p.set(false)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal("withdrawn readiness still answered 200")
	}
}

func TestTransportFailuresAreOnlyTimeoutsRefusalsAndResets(t *testing.T) {
	for errno, want := range map[syscall.Errno]bool{syscall.ECONNREFUSED: true, syscall.ECONNRESET: true, syscall.ETIMEDOUT: true, syscall.EACCES: false, syscall.ENETUNREACH: false} {
		if transport(&os.SyscallError{Syscall: "connect", Err: errno}) != want {
			t.Fatalf("%v classified as transport=%v", errno, !want)
		}
	}
	if !transport(timeoutError{}) {
		t.Fatal("a timeout is not a transport failure")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
