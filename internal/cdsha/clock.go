package cdsha

import (
	"fmt"
	"slices"
	"time"

	"github.com/hashicorp/raft"
)

type clockReport struct {
	AtMS        int64 `json:"at_ms"`
	Quarantined bool  `json:"quarantined"`
}

type clockFault struct {
	member string
	lag    time.Duration
}

func (f *clockFault) Error() string {
	return fmt.Sprintf("this replica's clock lags member %s by %s", f.member, f.lag)
}

// ClockError reports sticky, process-local evidence of relative clock lag.
func (n *Node) ClockError() error {
	n.clockMu.Lock()
	defer n.clockMu.Unlock()
	if n.clockFault == nil {
		return nil
	}
	return n.clockFault
}

func clockLag(member string, atMS int64, received time.Time, skew time.Duration) *clockFault {
	if atMS <= 0 || !time.UnixMilli(atMS).After(received.Add(skew)) {
		return nil
	}
	return &clockFault{member: member, lag: time.UnixMilli(atMS).Sub(received)}
}

func (n *Node) observeMemberClock(held reachedMember, answer controlAnswer, received time.Time, version uint64) {
	if !answer.Joined || answer.Err != "" || answer.Clock == nil {
		return
	}
	if err := held.control.attested().admittedBy(n.admits()); err != nil {
		return
	}
	// Lock order: clockMu, fsm.mu, peers.mu.
	n.clockMu.Lock()
	defer n.clockMu.Unlock()
	n.fsm.mu.RLock()
	defer n.fsm.mu.RUnlock()
	if !n.fsm.core.Joined() || n.fsm.core.Version != version {
		return
	}
	current := n.raft.GetConfiguration()
	if current.Error() != nil {
		return
	}
	servers := current.Configuration().Servers
	if !slices.ContainsFunc(servers, func(s raft.Server) bool { return string(s.ID) == held.member }) {
		return
	}
	n.peers.recordClock(held.member, answer.Clock.Quarantined, servers)
	if n.clockFault == nil {
		n.clockFault = clockLag(held.member, answer.Clock.AtMS, received, n.cfg.OperatorClockSkew)
	}
}

// Enqueue and quarantine share admission; completion waits outside the lock.
func (n *Node) enqueueMutation(submit func() raft.Future) error {
	n.clockMu.Lock()
	if n.clockFault != nil {
		err := n.clockFault
		n.clockMu.Unlock()
		return err
	}
	future := submit()
	n.clockMu.Unlock()
	return future.Error()
}
