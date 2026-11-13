package cdsattest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	tunnelEndpoint = wellKnownPrefix + "/tunnel"
	// liveSession is the id of the session newTunnelServer holds.
	liveSession = "live"
	// tunnelClientIP is the client the front door names on a tunnel post.
	tunnelClientIP = "203.0.113.7"
)

// budgetRouter is testRouter with the tunnel budget under the test's control:
// it records every charge, counts the releases, and admits nothing while full.
type budgetRouter struct {
	testRouter
	full     bool
	charges  []budgetCharge
	releases int
}

// budgetCharge is one Acquire: the bucket charged and the bytes reserved.
type budgetCharge struct {
	client string
	bytes  int64
}

func (b *budgetRouter) Acquire(client string, recordBytes int64) (func(), bool) {
	b.charges = append(b.charges, budgetCharge{client: client, bytes: recordBytes})
	if b.full {
		return nil, false
	}
	release := func() {
		b.releases++
	}
	return release, true
}

// deadlineRecorder records a response and accepts the I/O deadlines the tunnel
// sets, which a bare recorder refuses.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
}

func (deadlineRecorder) SetReadDeadline(time.Time) error { return nil }

func (deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

// undeclaredBody is a request body whose length the request does not declare.
type undeclaredBody struct {
	io.Reader
}

// trickleReader hands out its payload in small reads, pausing before each, as
// a client uploading a record over a slow link does.
type trickleReader struct {
	payload []byte
	chunk   int
	pause   time.Duration
}

func (t *trickleReader) Read(p []byte) (int, error) {
	if len(t.payload) == 0 {
		return 0, io.EOF
	}
	time.Sleep(t.pause)
	n := copy(p[:min(len(p), t.chunk)], t.payload)
	t.payload = t.payload[n:]
	return n, nil
}

// newTunnelServer serves the tunnel over router and holds one live session, for
// the refusals that answer before anything is decrypted.
func newTunnelServer(t *testing.T, router Router) *Server {
	t.Helper()
	srv := NewServer(Config{Routes: router})
	srv.sessions[liveSession] = establishedSession{createdAt: time.Now(), lastUsed: time.Now()}
	return srv
}

// tunnelRequest is a POST of body to the tunnel naming session.
func tunnelRequest(session string, body io.Reader) *http.Request {
	req := httptest.NewRequest(http.MethodPost, tunnelEndpoint, body)
	req.Header.Set(sessionHeader, session)
	return req
}

// refusalCode is the error code of a recorded refusal.
func refusalCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var refusal types.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("refusal body %q: %v", w.Body.String(), err)
	}
	return refusal.Error
}

// postTunnelRecord posts body as a tunnel record from the client the front
// door names, and returns the HTTP status.
func postTunnelRecord(t *testing.T, base, session string, body io.Reader) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+tunnelEndpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(sessionHeader, session)
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Real-IP", tunnelClientIP)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// sealedRecord seals req on channel and returns the CBOR record a client posts.
func sealedRecord(t *testing.T, channel *overenc.Channel, req types.TunnelRequest) []byte {
	t.Helper()
	plain, err := cbor.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := channel.SealRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	record, err := cbor.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// TestTunnelRefusalsBeforeTheBodyCloseTheConnection pins the refusals that
// answer before the record is read: each closes the connection, so net/http
// never waits on a body nobody reads, and only a request the budget was asked
// about is charged.
func TestTunnelRefusalsBeforeTheBodyCloseTheConnection(t *testing.T) {
	tests := []struct {
		name        string
		session     string
		length      int64
		full        bool
		wantStatus  int
		wantCode    string
		wantCharges int
	}{
		{
			name:        "no session",
			session:     "",
			length:      1024,
			wantStatus:  http.StatusUnauthorized,
			wantCode:    types.ErrorCodeChannelError,
			wantCharges: 0,
		},
		{
			name:        "record over the cap",
			session:     liveSession,
			length:      tunnelBodyLimit + 1,
			wantStatus:  http.StatusRequestEntityTooLarge,
			wantCode:    types.ErrorCodeChannelError,
			wantCharges: 0,
		},
		{
			name:        "budget full",
			session:     liveSession,
			length:      1024,
			full:        true,
			wantStatus:  http.StatusServiceUnavailable,
			wantCode:    types.ErrorCodeTunnelBusy,
			wantCharges: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			budget := &budgetRouter{full: tc.full}
			srv := newTunnelServer(t, budget)
			req := tunnelRequest(tc.session, strings.NewReader("record"))
			req.ContentLength = tc.length
			w := httptest.NewRecorder()

			srv.handleTunnel(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if code := refusalCode(t, w); code != tc.wantCode {
				t.Fatalf("error code = %q, want %q", code, tc.wantCode)
			}
			if got := w.Header().Get("Connection"); got != "close" {
				t.Fatalf("Connection = %q, want close", got)
			}
			if len(budget.charges) != tc.wantCharges {
				t.Fatalf("budget charges = %v, want %d", budget.charges, tc.wantCharges)
			}
			if budget.releases != 0 {
				t.Fatalf("a refusal released the budget %d times, want 0", budget.releases)
			}
		})
	}
}

// TestTunnelRefusesWithoutIODeadlines pins the exit for a connection whose
// deadlines cannot be set: a request that cannot be timed out is refused and
// holds no budget.
func TestTunnelRefusesWithoutIODeadlines(t *testing.T) {
	budget := &budgetRouter{}
	srv := newTunnelServer(t, budget)
	w := httptest.NewRecorder()

	srv.handleTunnel(w, tunnelRequest(liveSession, strings.NewReader("record")))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if code := refusalCode(t, w); code != types.ErrorCodeInternal {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeInternal)
	}
	if budget.releases != 1 {
		t.Fatalf("budget releases = %d, want 1", budget.releases)
	}
}

// TestTunnelCapsAnUndeclaredRecord pins the cap on a record that declares no
// length: the body is read no further than the cap, and that refusal comes
// from the read, so it keeps the connection the declared-length refusal closes.
func TestTunnelCapsAnUndeclaredRecord(t *testing.T) {
	budget := &budgetRouter{}
	srv := newTunnelServer(t, budget)
	oversized := make([]byte, tunnelBodyLimit+1)
	req := tunnelRequest(liveSession, undeclaredBody{bytes.NewReader(oversized)})
	w := deadlineRecorder{httptest.NewRecorder()}

	srv.handleTunnel(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
	if code := refusalCode(t, w.ResponseRecorder); code != types.ErrorCodeChannelError {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeChannelError)
	}
	if got := w.Header().Get("Connection"); got != "" {
		t.Fatalf("Connection = %q, want unset: the record was read, not refused before it", got)
	}
	if len(budget.charges) != 1 || budget.charges[0].bytes != tunnelBodyLimit {
		t.Fatalf("budget charges = %v, want one of %d bytes", budget.charges, tunnelBodyLimit)
	}
	if budget.releases != 1 {
		t.Fatalf("budget releases = %d, want 1", budget.releases)
	}
}

// TestTunnelChargesTheRecordItMayRead pins what one tunnelled request reserves:
// a declared record is charged its own length, one declaring none is charged
// the cap it may grow to, and both go to the client's bucket.
func TestTunnelChargesTheRecordItMayRead(t *testing.T) {
	budget := &budgetRouter{testRouter: testRoutes(t)}
	_, ts, _ := newTestServerWith(t, func(srv *Server) {
		srv.routes = budget
	})
	channel, sessionID := establishSession(t, ts.URL, make([]byte, 32))
	declared := sealedRecord(t, channel, types.TunnelRequest{Method: "GET", Path: "/declared"})
	undeclared := sealedRecord(t, channel, types.TunnelRequest{Method: "GET", Path: "/undeclared"})

	if code := postTunnelRecord(t, ts.URL, sessionID, bytes.NewReader(declared)); code != http.StatusOK {
		t.Fatalf("tunnel with a declared length = %d, want 200", code)
	}
	if code := postTunnelRecord(t, ts.URL, sessionID, undeclaredBody{bytes.NewReader(undeclared)}); code != http.StatusOK {
		t.Fatalf("tunnel without a declared length = %d, want 200", code)
	}

	want := []budgetCharge{
		{client: "client:" + tunnelClientIP, bytes: int64(len(declared))},
		{client: "client:" + tunnelClientIP, bytes: tunnelBodyLimit},
	}
	if !reflect.DeepEqual(budget.charges, want) {
		t.Fatalf("budget charges = %v, want %v", budget.charges, want)
	}
}

// TestTunnelIODeadlineFollowsProgress pins the I/O timeout as a progress
// deadline and not a request budget: an upload that keeps sending is served
// however long it takes, and a backend slower than the timeout keeps an
// uncancelled request and gets its response sealed.
func TestTunnelIODeadlineFollowsProgress(t *testing.T) {
	const ioTimeout = 300 * time.Millisecond

	t.Run("upload slower than the timeout", func(t *testing.T) {
		_, ts, _ := newTestServerWith(t, func(srv *Server) {
			srv.cfg.TunnelIOTimeout = ioTimeout
		})
		channel, sessionID := establishSession(t, ts.URL, make([]byte, 32))
		record := sealedRecord(t, channel, types.TunnelRequest{Method: "GET", Path: "/trickled"})
		body := &trickleReader{
			payload: record,
			chunk:   len(record)/6 + 1,
			pause:   ioTimeout / 3,
		}

		if code := postTunnelRecord(t, ts.URL, sessionID, body); code != http.StatusOK {
			t.Fatalf("trickled tunnel record = %d, want 200", code)
		}
	})

	t.Run("backend slower than the timeout", func(t *testing.T) {
		forwarded := make(chan error, 1)
		backend := backendFunc(func(outer *http.Request, _ types.TunnelRequest) (types.TunnelResponse, error) {
			time.Sleep(2 * ioTimeout)
			forwarded <- outer.Context().Err()
			return types.TunnelResponse{Status: http.StatusOK}, nil
		})
		_, ts, _ := newTestServerWith(t, func(srv *Server) {
			srv.cfg.TunnelIOTimeout = ioTimeout
			srv.routes = testRouter{State: testRoutes(t).State, backendFunc: backend}
		})
		channel, sessionID := establishSession(t, ts.URL, make([]byte, 32))

		resp := tunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/slow"})

		if resp.Status != http.StatusOK {
			t.Fatalf("sealed response from a slow backend = %d, want 200", resp.Status)
		}
		if err := <-forwarded; err != nil {
			t.Fatalf("request context while the backend answered = %v, want it uncancelled", err)
		}
	})

	t.Run("undeclared record, backend slower than the timeout", func(t *testing.T) {
		forwarded := make(chan error, 1)
		backend := backendFunc(func(outer *http.Request, _ types.TunnelRequest) (types.TunnelResponse, error) {
			time.Sleep(2 * ioTimeout)
			forwarded <- outer.Context().Err()
			return types.TunnelResponse{Status: http.StatusOK}, nil
		})
		_, ts, _ := newTestServerWith(t, func(srv *Server) {
			srv.cfg.TunnelIOTimeout = ioTimeout
			srv.routes = testRouter{State: testRoutes(t).State, backendFunc: backend}
		})
		channel, sessionID := establishSession(t, ts.URL, make([]byte, 32))
		record := sealedRecord(t, channel, types.TunnelRequest{Method: "GET", Path: "/slow-chunked"})

		code := postTunnelRecord(t, ts.URL, sessionID, undeclaredBody{bytes.NewReader(record)})

		if code != http.StatusOK {
			t.Fatalf("chunked record to a slow backend = %d, want 200", code)
		}
		if err := <-forwarded; err != nil {
			t.Fatalf("request context while the backend answered = %v, want it uncancelled", err)
		}
	})
}
