package armtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// retiring is a RetiringTransport over a TLS server that answers each request
// with the address of the connection it came on; /slow answers once release is
// closed, after signalling started. Its handshakes record the pins they were
// checked against instead of verifying evidence.
type retiring struct {
	client           *http.Client
	url              string
	started, release chan struct{}

	mu      sync.Mutex
	pins    Pins
	pinsErr error
	checked []Pins
}

func newRetiring(t *testing.T, pins Pins) *retiring {
	t.Helper()
	r := &retiring{started: make(chan struct{}), release: make(chan struct{}), pins: pins}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			close(r.started)
			<-r.release
		}
		fmt.Fprint(w, req.RemoteAddr)
	}))
	t.Cleanup(srv.Close)
	rt := NewRetiringTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, func() (Pins, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.pins, r.pinsErr
	}, "http://127.0.0.1:1")
	rt.verify = func(set Pins) func([][]byte, [][]*x509.Certificate) error {
		return func([][]byte, [][]*x509.Certificate) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.checked = append(r.checked, set)
			return nil
		}
	}
	r.client, r.url = &http.Client{Transport: rt}, srv.URL
	t.Cleanup(r.client.CloseIdleConnections)
	return r
}

func (r *retiring) set(pins Pins, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pins, r.pinsErr = pins, err
}

// conn is the connection a GET of path ran on.
func (r *retiring) conn(path string) (string, error) {
	resp, err := r.client.Get(r.url + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func (r *retiring) mustConn(t *testing.T) string {
	t.Helper()
	conn, err := r.conn("/")
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func pinsOf(b byte) Pins { return Pins{Measurements: [][]byte{{b}}} }

// A request in flight when the pins change finishes on its connection, and
// no later request runs on it.
func TestRetiredConnectionCarriesNoLaterRequest(t *testing.T) {
	r := newRetiring(t, pinsOf(1))
	first := r.mustConn(t)
	if again := r.mustConn(t); again != first {
		t.Fatalf("an idle connection was not reused: %s then %s", first, again)
	}
	type result struct {
		conn string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := r.conn("/slow")
		done <- result{conn, err}
	}()
	<-r.started
	r.set(pinsOf(2), nil)
	// The change is seen by a request, which leaves the pool, while the slow
	// one is still on its connection.
	moved := r.mustConn(t)
	close(r.release)
	inFlight := <-done
	if inFlight.err != nil || inFlight.conn != first {
		t.Fatalf("the request in flight ran on %q (%v), want the pooled connection %s", inFlight.conn, inFlight.err, first)
	}
	if moved == first {
		t.Fatalf("a request under new pins ran on the old connection %s", first)
	}
	if after := r.mustConn(t); after != moved {
		t.Fatalf("a later request ran on %s, want the new pool's connection %s", after, moved)
	}
}

// Every connection is checked against the pins its request started under, so
// pins that change and change back share no connection with the set between.
func TestAConnectionServesOnlyThePinsItWasCheckedAgainst(t *testing.T) {
	a, b := pinsOf(1), pinsOf(2)
	r := newRetiring(t, a)
	underA := r.mustConn(t)
	r.set(b, nil)
	underB := r.mustConn(t)
	r.set(a, nil)
	back := r.mustConn(t)
	if underB == underA || back == underB {
		t.Fatalf("connections %s (a), %s (b), %s (a again): a set shares one with another", underA, underB, back)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.checked) != 3 || r.checked[0].Measurements[0][0] != 1 || r.checked[1].Measurements[0][0] != 2 || r.checked[2].Measurements[0][0] != 1 {
		t.Fatalf("handshakes were checked against %v, want a, b, a", r.checked)
	}
}

// A request is not sent while the pins cannot be read, and the pool is kept
// for when they can.
func TestUnreadablePinsSendNothing(t *testing.T) {
	r := newRetiring(t, pinsOf(1))
	first := r.mustConn(t)
	unreadable := errors.New("unreadable")
	r.set(pinsOf(1), unreadable)
	if conn, err := r.conn("/"); !errors.Is(err, unreadable) {
		t.Fatalf("a request under unreadable pins ran on %q (%v), want the read error", conn, err)
	}
	r.set(pinsOf(1), nil)
	if kept := r.mustConn(t); kept != first {
		t.Fatalf("readable pins again left the connection: %s then %s", first, kept)
	}
}

// The retiring client is refused where the following one is, and its pools
// refuse a set that names no guest.
func TestNewRetiringHTTPClient(t *testing.T) {
	pins := func() (Pins, error) { return pinsOf(1), nil }
	if _, err := NewRetiringHTTPClient(pins, ""); err == nil {
		t.Fatal("a client without an attestation-api URL was built")
	}
	client, err := NewRetiringHTTPClient(pins, "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	rt, ok := client.Transport.(*RetiringTransport)
	if !ok {
		t.Fatalf("the client carries a %T", client.Transport)
	}
	if err := rt.verify(Pins{})(nil, nil); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("a pool of empty pins checked its peer: %v", err)
	}
}
