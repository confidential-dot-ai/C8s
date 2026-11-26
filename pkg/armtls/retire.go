package armtls

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
)

// RetiringTransport is a transport whose connections carry no request that
// starts after Retire. A handshake checks the pins in force when it runs, so
// a pooled connection outlives a change of pins unless its pool is left.
type RetiringTransport struct {
	mu      sync.Mutex
	current *http.Transport
}

// NewRetiringTransport takes over t, which the caller no longer uses.
func NewRetiringTransport(t *http.Transport) *RetiringTransport {
	return &RetiringTransport{current: t}
}

// Retire continues on a clone of the transport with an empty pool. A request
// in flight finishes on its connection, which no later request reuses: it
// returns to the pool left behind and idles out there.
func (t *RetiringTransport) Retire() {
	t.mu.Lock()
	old := t.current
	t.current = old.Clone()
	t.mu.Unlock()
	old.CloseIdleConnections()
}

func (t *RetiringTransport) transport() *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.current
}

func (t *RetiringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport().RoundTrip(req)
}

// CloseIdleConnections is what http.Client.CloseIdleConnections calls.
func (t *RetiringTransport) CloseIdleConnections() { t.transport().CloseIdleConnections() }

// NewRetiringHTTPClient is [NewFollowingHTTPClient] for a client that keeps
// running: it leaves its connections when pins answers another set, which
// every request reads first. A read that fails keeps the connections; the
// next handshake fails on the same read.
func NewRetiringHTTPClient(pins func() (Pins, error), attestationApiURL string) (*http.Client, error) {
	client, err := NewFollowingHTTPClient(pins, attestationApiURL)
	if err != nil {
		return nil, err
	}
	held, err := pins()
	if err != nil {
		return nil, err
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("armtls client config: the standard client carries a %T", client.Transport)
	}
	client.Transport = &pinRetiringTransport{RetiringTransport: NewRetiringTransport(base), pins: pins, held: held}
	return client, nil
}

type pinRetiringTransport struct {
	*RetiringTransport
	pins func() (Pins, error)

	pinsMu sync.Mutex
	held   Pins
}

func (t *pinRetiringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if now, err := t.pins(); err == nil {
		t.pinsMu.Lock()
		changed := !reflect.DeepEqual(now, t.held)
		t.held = now
		t.pinsMu.Unlock()
		if changed {
			t.Retire()
		}
	}
	return t.RetiringTransport.RoundTrip(req)
}
