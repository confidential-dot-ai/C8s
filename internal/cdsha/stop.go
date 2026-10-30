package cdsha

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// A replica that cannot apply a committed entry stops following the log.
// Raft takes Apply's answer as the entry's result and moves on, so a replica
// that skipped one would serve state the rest of the group does not have.
type stopKind string

const (
	// localFault is a stop in this replica's own store or process: it stops
	// serving and exits to rejoin with the cluster's state.
	localFault stopKind = "local fault"
	// deterministic is an entry this code cannot apply: every replica stops
	// at the same one, and the log lives only in memory, so the replica keeps
	// running with its log until an operator acts, with an image that applies
	// the entry or a Restore.
	deterministic stopKind = "deterministic stop"
	// stalled is a command that has run too long: slow, not skipped. It ends
	// when that command returns.
	stalled stopKind = "stall"
)

// stopReason is why a replica stopped, of which kind, and since when.
type stopReason struct {
	kind stopKind
	msg  string
	at   time.Time
}

// stops is a replica's stop state and the command it is applying. Nothing
// here takes a lock, so Apply records a stop while it holds the state
// machine's.
type stops struct {
	reason atomic.Pointer[stopReason]
	// applying is when the command Apply is on started, and nil between
	// commands.
	applying atomic.Pointer[time.Time]
}

// Stuck is why this replica stopped applying the log, or "".
func (s *stops) Stuck() string {
	if p := s.reason.Load(); p != nil {
		return p.msg
	}
	return ""
}

// StuckLocal reports a stop in this replica's own store or process, which a
// restart cures. A stalled command is not one: it may still return.
func (s *stops) StuckLocal() bool {
	p := s.reason.Load()
	return p != nil && p.kind == localFault
}

// Not stopped, or only slow on the command it is applying.
func (s *stops) appliedEveryEntry() bool {
	p := s.reason.Load()
	return p == nil || p.kind == stalled
}

func (s *stops) stuckFor() time.Duration {
	if p := s.reason.Load(); p != nil {
		return time.Since(p.at)
	}
	return 0
}

func (s *stops) stalling() (*stopReason, bool) {
	p := s.reason.Load()
	if p == nil || p.kind != stalled {
		return nil, false
	}
	return p, true
}

// ApplyingFor is how long the command Apply is on has been applying, and 0
// between commands.
func (s *stops) ApplyingFor() time.Duration {
	if started := s.applying.Load(); started != nil {
		return time.Since(*started)
	}
	return 0
}

func (s *stops) began() func() {
	started := time.Now()
	s.applying.Store(&started)
	return func() { s.applying.Store(nil) }
}

// stop records a stop every replica on this code reaches at the same entry.
func (s *stops) stop(err error) error {
	return s.halt(err, deterministic)
}

func (s *stops) stopLocal(err error) error {
	return s.halt(err, localFault)
}

// halt records a stop. It replaces nothing but a stall: the first stop of the
// log stays, and is what an operator is told about.
func (s *stops) halt(err error, kind stopKind) error {
	stop := &stopReason{
		kind: kind,
		msg:  err.Error(),
		at:   time.Now(),
	}
	for {
		current := s.reason.Load()
		if current != nil && current.kind != stalled {
			return err
		}
		if s.reason.CompareAndSwap(current, stop) {
			break
		}
	}
	if kind == localFault {
		slog.Error("cds-ha: this replica can no longer follow the log (its own fault); it stops serving and exits to rejoin", "reason", stop.msg)
	} else {
		slog.Error("cds-ha: ALARM: this replica cannot apply a committed log entry; it stops serving and keeps its log for an operator", "reason", stop.msg)
	}
	return err
}

// Stall records that the command Apply is on has run too long, unless the
// replica has already stopped. That command may still return, so a stall
// raised for one that returned meanwhile is taken back.
func (s *stops) Stall(err error) {
	started := s.applying.Load()
	if started == nil {
		return
	}
	stall := &stopReason{
		kind: stalled,
		msg:  err.Error(),
		at:   time.Now(),
	}
	if !s.reason.CompareAndSwap(nil, stall) {
		return
	}
	if s.applying.Load() != started {
		s.reason.CompareAndSwap(stall, nil)
		return
	}
	slog.Error("cds-ha: this replica's state machine is stalled on a command; it stops serving until the command returns", "reason", stall.msg)
}

// A stall that outlasted its cluster is a fault of this replica's own: the
// restart that replays the cluster's log takes this replica back into it.
func (s *stops) hang(stall *stopReason, why string) {
	// The stall's own start stands: this replica has served nothing since
	// the command stopped returning.
	hung := &stopReason{
		kind: localFault,
		msg:  stall.msg + ", and " + why,
		at:   stall.at,
	}
	if !s.reason.CompareAndSwap(stall, hung) {
		return
	}
	slog.Error("cds-ha: this replica's state machine is held on a command for good; it stops serving and exits to rejoin",
		"reason", hung.msg)
}

// endStall ends the stall of the command that just returned: it was slow, but
// it applied, and so did every entry before it. A stop raised meanwhile
// replaced the stall and stays.
func (s *stops) endStall() {
	p := s.reason.Load()
	if p == nil || p.kind != stalled {
		return
	}
	if s.reason.CompareAndSwap(p, nil) {
		slog.Info("cds-ha: the stalled command returned; this replica follows the log again", "stalled", p.msg)
	}
}
