package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// probe is the cds-probe mode. It must observe its owned CDS reachable, then
// continuously unreachable for the hold. In restart mode it then writes the
// marker in the RAM-backed restart directory and exits once; only the
// marker survives the restart, which starts ready and observes nothing.
// In renewal mode it withdraws readiness instead and restores it when the
// CDS answers again. Readiness is withdrawn, never the process, for any
// failure that is not a transport failure: that exits ExitProbeTransport.
type probe struct {
	host    string
	hold    time.Duration
	renewal bool
	dir     string
	now     func() time.Duration
	sleep   func(time.Duration)
	dial    func(address string, timeout time.Duration) error
	ready   atomic.Bool
	onReady func(bool) // test hook, called on each transition
}

func newProbe(args []string) (*probe, int) {
	if len(args) == 0 || len(args) > 2 {
		return nil, 2
	}
	start := time.Now()
	p := &probe{host: args[0], hold: podfixture.ProbeRestartHold, dir: "/restart", now: func() time.Duration { return time.Since(start) }, sleep: time.Sleep, dial: tcpDial}
	if len(args) == 2 {
		p.renewal = true
		seconds, err := strconv.Atoi(args[1])
		p.hold = time.Duration(seconds) * time.Second
		if err != nil {
			p.hold = 0
		}
	}
	return p, 0
}

func tcpDial(address string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

// prepare checks the restart directory is writable before anything is
// served, so permission loss cannot masquerade as the outage exit, then
// the hold.
func (p *probe) prepare() int {
	marker := filepath.Join(p.dir, ".writable")
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return podfixture.ExitProbeUnwritable
	}
	f.Close()
	if err := os.Remove(marker); err != nil {
		return podfixture.ExitProbeUnwritable
	}
	if p.renewal && p.hold != podfixture.ProbeRenewalHold {
		return podfixture.ExitProbeHold
	}
	return 0
}

// restarted reports whether this is the process after the one exit: the
// marker exists, so the probe starts ready and observes nothing.
func (p *probe) restarted() bool {
	if _, err := os.Stat(filepath.Join(p.dir, "once")); err != nil {
		return false
	}
	p.set(true)
	return true
}

func (p *probe) set(ready bool) {
	if p.ready.Swap(ready) != ready && p.onReady != nil {
		p.onReady(ready)
	}
}

// transport reports whether a dial failure is one the outage contract
// counts: a timeout, a refusal or a reset.
func transport(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == syscall.ECONNRESET || errno == syscall.ETIMEDOUT)
}

// observe runs the outage watch. It returns the exit status and true when
// the process must exit, or false when renewal mode has seen the CDS come
// back and the server simply keeps running.
func (p *probe) observe() (int, bool) {
	budget := podfixture.ProbeRestartBudget
	if p.renewal {
		budget = p.hold + podfixture.ProbeRenewalGrace
	}
	deadline, reachableBy := p.now()+budget, p.now()+podfixture.ProbeReachableBy
	reachable, completed := false, false
	var failedSince *time.Duration
	address := net.JoinHostPort(p.host, "8443")
	for p.now() < deadline {
		if err := p.dial(address, podfixture.ProbeConnectTimeout); err != nil {
			if !transport(err) {
				return podfixture.ExitProbeTransport, true
			}
			if reachable {
				if failedSince == nil {
					since := p.now()
					failedSince = &since
				}
				if p.now()-*failedSince >= p.hold {
					if p.renewal {
						completed = true
						p.set(false)
						p.sleep(time.Second)
						continue
					}
					f, err := os.OpenFile(filepath.Join(p.dir, "once"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
					if err != nil {
						return podfixture.ExitProbeMarker, true
					}
					f.Close()
					return 0, true
				}
			} else if p.now() >= reachableBy {
				return podfixture.ExitProbeUnreached, true
			}
		} else {
			reachable = true
			p.set(true)
			if p.renewal && completed {
				return 0, false
			}
			failedSince = nil
		}
		p.sleep(time.Second)
	}
	return podfixture.ExitProbeNoOutage, true
}

func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/live" || (r.URL.Path == "/ready" && p.ready.Load()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}
