// Package cdspin holds a Trust Authority replica set to the chain a node pins
// (docs/ta-ha.md, "What nodes pin"). A client sends its pin, the genesis
// hash or "<seq>:<hash>" of a later entry, in a header; a replica answers it
// back only when its chain holds that entry, and its genesis hash otherwise.
// The header travels inside the armTLS connection the client verified, so
// the host cannot change it: a re-rooted set under the same Trust Authority measurement
// is refused.
package cdspin

import (
	"errors"
	"fmt"
	"net/http"
)

// Header carries the pin a client holds a replica set to. Header names are
// case-insensitive, and net/http matches them so.
const Header = "c8s-cds-pin"

// ErrOtherGenesis is a Trust Authority answering for another replica set, or for none.
var ErrOtherGenesis = errors.New("the Trust Authority does not serve the pinned replica set")

// Client is c with every response held to pinned; with none pinned, c.
//
// INVARIANT: with a pin, no response reaches the caller unless it answers
// that pin; one without the header is refused too.
func Client(c *http.Client, pinned string) *http.Client {
	if pinned == "" {
		return c
	}
	held := *c
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	held.Transport = transport{next: next, pinned: pinned}
	return &held
}

type transport struct {
	next   http.RoundTripper
	pinned string
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(Header, t.pinned)
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if got := resp.Header.Get(Header); got != t.pinned {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: it names %q, this node pins %s", ErrOtherGenesis, got, t.pinned)
	}
	return resp, nil
}

func (t transport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
