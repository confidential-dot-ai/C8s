package nriimagepolicy

import (
	"sync"
	"time"
)

// cdsClock is the CDS's time as this node follows it: the Date of the newest
// poll reply, carried forward by the time elapsed locally since that reply.
// Component-set deadlines are judged by it, so the host's own clock cannot end
// a set early or keep a retired one alive.
//
// Before the first reply it is the local clock.
type cdsClock struct {
	local func() time.Time

	mu sync.Mutex
	// dated is the newest reply's Date and read is the local reading when it
	// arrived; both zero until the first reply carries a Date.
	dated time.Time
	read  time.Time
}

func newCDSClock(local func() time.Time) *cdsClock {
	return &cdsClock{local: local}
}

// observe takes the Date of a poll reply, a 304 included. CDS time never goes
// backwards: a reply dated before the time already carried is ignored.
func (c *cdsClock) observe(date time.Time) {
	if date.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dated.IsZero() && !date.After(c.carried()) {
		return
	}
	c.dated, c.read = date, c.local()
}

func (c *cdsClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.carried()
}

func (c *cdsClock) carried() time.Time {
	if c.dated.IsZero() {
		return c.local()
	}
	return c.dated.Add(c.local().Sub(c.read))
}
