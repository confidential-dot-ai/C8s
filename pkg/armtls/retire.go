package armtls

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"reflect"
	"sync"
)

// RetiringTransport runs each request on a connection whose peer was checked
// against the pins in force when the request started. It keeps one pool per
// set of pins: a request reads the pins, and where they changed it continues
// on a new pool whose handshakes check that set alone. A request in flight
// finishes on its connection, which no later request reuses: it returns to
// the pool left behind and idles out there.
type RetiringTransport struct {
	base   *http.Transport
	pins   func() (Pins, error)
	verify func(Pins) func([][]byte, [][]*x509.Certificate) error

	mu      sync.Mutex
	held    Pins
	current *http.Transport
}

// NewRetiringTransport is the transport over the pools of base, an armTLS
// client transport the caller no longer uses: each pool is a clone of base
// that holds its peer to one answer of pins. The pool's check replaces the
// one base was built with ([ClientConfig.Current] included), so the set a
// request read is the only one its handshake is checked against.
func NewRetiringTransport(base *http.Transport, pins func() (Pins, error), attestationApiURL string) *RetiringTransport {
	return &RetiringTransport{
		base: base,
		pins: pins,
		verify: func(set Pins) func([][]byte, [][]*x509.Certificate) error {
			return func(raw [][]byte, chains [][]*x509.Certificate) error {
				policy := set.VerifyPolicy(attestationApiURL)
				if err := requirePins(policy.Policy); err != nil {
					return fmt.Errorf("armtls: the current pins: %w", err)
				}
				return verifyPeerCallback(policy, x509.ExtKeyUsageServerAuth)(raw, chains)
			}
		},
	}
}

// pool reads the pins, leaves the pool of another set and selects the pool
// in one step, so no request that starts after a change runs on the pool
// left behind. The read is under the lock, which orders the requests of one
// client through it: these clients make a few requests a minute (a
// certificate renewal, an allowlist pull, one callback per issuance) and the
// read is one small file or a value in memory.
func (t *RetiringTransport) pool() (*http.Transport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now, err := t.pins()
	if err != nil {
		return nil, fmt.Errorf("armtls: read the pins in force: %w", err)
	}
	if t.current != nil && reflect.DeepEqual(now, t.held) {
		return t.current, nil
	}
	next := t.base.Clone()
	next.TLSClientConfig.VerifyPeerCertificate = t.verify(now)
	if t.current != nil {
		t.current.CloseIdleConnections()
	}
	t.held, t.current = now, next
	return next, nil
}

// RoundTrip sends nothing while the pins cannot be read: a pooled connection
// would carry the request with no handshake to check them.
func (t *RetiringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pool, err := t.pool()
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return pool.RoundTrip(req)
}

// CloseIdleConnections is what http.Client.CloseIdleConnections calls.
func (t *RetiringTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current != nil {
		t.current.CloseIdleConnections()
	}
}

// NewRetiringHTTPClient is [NewFollowingHTTPClient] for a client that keeps
// running: every request reads pins and runs on the pool of that set, and
// the pool of a set no longer answered is left to idle out. A request whose
// read fails is not sent.
func NewRetiringHTTPClient(pins func() (Pins, error), attestationApiURL string) (*http.Client, error) {
	client, err := NewFollowingHTTPClient(pins, attestationApiURL)
	if err != nil {
		return nil, err
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("armtls client config: the standard client carries a %T", client.Transport)
	}
	client.Transport = NewRetiringTransport(base, pins, attestationApiURL)
	return client, nil
}
