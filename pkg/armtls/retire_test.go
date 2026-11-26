package armtls

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// connServer answers each request with the address of the connection it came
// on; /slow answers once release is closed, after signalling started.
func connServer(t *testing.T) (url string, started, release chan struct{}) {
	t.Helper()
	started, release = make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-release
		}
		fmt.Fprint(w, r.RemoteAddr)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, started, release
}

// connOf is the connection a GET of url ran on, "" with the error it failed with.
func connOf(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func mustConn(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	conn, err := connOf(client, url)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// A request in flight when the transport is retired finishes on its
// connection, and no later request runs on it.
func TestRetiredConnectionCarriesNoLaterRequest(t *testing.T) {
	url, started, release := connServer(t)
	rt := NewRetiringTransport(&http.Transport{})
	client := &http.Client{Transport: rt}
	t.Cleanup(client.CloseIdleConnections)

	first := mustConn(t, client, url)
	if again := mustConn(t, client, url); again != first {
		t.Fatalf("an idle connection was not reused: %s then %s", first, again)
	}
	type result struct {
		conn string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := connOf(client, url+"/slow")
		done <- result{conn, err}
	}()
	<-started
	rt.Retire()
	close(release)
	inFlight := <-done
	if inFlight.err != nil || inFlight.conn != first {
		t.Fatalf("the request in flight ran on %q (%v), want the pooled connection %s", inFlight.conn, inFlight.err, first)
	}
	if after := mustConn(t, client, url); after == first {
		t.Fatalf("a request after Retire ran on the retired connection %s", after)
	}
}

// A retiring client keeps its connections while its pins hold, leaves them
// when the pins change, and sends nothing while they cannot be read.
func TestPinChangeRetiresTheConnections(t *testing.T) {
	url, _, _ := connServer(t)
	pins := Pins{Measurements: [][]byte{{1}}}
	var pinsErr error
	client := &http.Client{Transport: &pinRetiringTransport{
		RetiringTransport: NewRetiringTransport(&http.Transport{}),
		pins:              func() (Pins, error) { return pins, pinsErr },
		held:              pins,
	}}
	t.Cleanup(client.CloseIdleConnections)

	first := mustConn(t, client, url)
	if again := mustConn(t, client, url); again != first {
		t.Fatalf("unchanged pins left the connection: %s then %s", first, again)
	}
	pins = Pins{Measurements: [][]byte{{2}}}
	moved := mustConn(t, client, url)
	if moved == first {
		t.Fatalf("a request under new pins ran on the old connection %s", first)
	}
	pinsErr = errors.New("unreadable")
	if conn, err := connOf(client, url); !errors.Is(err, pinsErr) {
		t.Fatalf("a request under unreadable pins ran on %q (%v), want the read error", conn, err)
	}
	pinsErr = nil
	if kept := mustConn(t, client, url); kept != moved {
		t.Fatalf("readable pins again left the connection: %s then %s", moved, kept)
	}
}

// The retiring client is refused where the following one is.
func TestNewRetiringHTTPClientNeedsAnAttestationAPI(t *testing.T) {
	pins := func() (Pins, error) { return Pins{Measurements: [][]byte{{1}}}, nil }
	if _, err := NewRetiringHTTPClient(pins, ""); err == nil {
		t.Fatal("a client without an attestation-api URL was built")
	}
	client, err := NewRetiringHTTPClient(pins, "http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Transport.(*pinRetiringTransport); !ok {
		t.Fatalf("the client carries a %T", client.Transport)
	}
}
