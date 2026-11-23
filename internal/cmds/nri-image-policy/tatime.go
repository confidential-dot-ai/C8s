package nriimagepolicy

import (
	"sync"
	"time"
)

// taClock is the Trust Authority's time as this node follows it: the Date of
// the newest poll reply, carried forward by the time elapsed locally since
// that reply. Component-set deadlines are judged by it, so the host's own
// clock cannot end a set early or keep a retired one alive.
//
// Before the first reply it is the local clock.
type taClock struct {
	local func() time.Time

	mu sync.Mutex
	// dated is the newest reply's Date and read is the local reading when it
	// arrived; both zero until the first reply carries a Date.
	dated time.Time
	read  time.Time
}

func newTAClock(local func() time.Time) *taClock {
	return &taClock{local: local}
}

// observe takes the Date of a poll reply, a 304 included. Trust Authority time
// never goes backwards: a reply dated before the time already carried is
// ignored.
func (c *taClock) observe(date time.Time) {
	if date.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dated.IsZero() && !date.After(c.carried()) {
		return
	}
	c.dated = date
	c.read = c.local()
}

func (c *taClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.carried()
}

func (c *taClock) carried() time.Time {
	if c.dated.IsZero() {
		return c.local()
	}
	return c.dated.Add(c.local().Sub(c.read))
}
