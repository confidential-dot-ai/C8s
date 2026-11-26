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
// every request reads first. A request whose read fails is not sent.
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

// RoundTrip reads the pins, leaves the pool on a change and selects the pool
// in one step, so no request that starts after a change runs on the pool left
// behind. Pins that cannot be read send nothing: a pooled connection would
// carry the request with no handshake to check them.
func (t *pinRetiringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.pinsMu.Lock()
	now, err := t.pins()
	if err != nil {
		t.pinsMu.Unlock()
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("armtls: read the pins in force: %w", err)
	}
	if !reflect.DeepEqual(now, t.held) {
		t.held = now
		t.Retire()
	}
	transport := t.transport()
	t.pinsMu.Unlock()
	return transport.RoundTrip(req)
}
