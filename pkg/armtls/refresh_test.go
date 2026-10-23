package armtls

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// fakePins stands in for cdspins: Name of the one image says which server
// certificate the transport trusts.
type fakePins struct {
	cur, next string
	gen       uint64
	refreshes atomic.Int32
}

func (f *fakePins) Current() refvalues.ReferenceValues {
	return refvalues.ReferenceValues{Images: []remote.ImagePin{{Name: f.cur, Digest: pinDigest(f.cur)}}}
}

// pinDigest is the launch measurement the image named name pins.
func pinDigest(name string) []byte     { d := sha512.Sum384([]byte(name)); return d[:] }
func (f *fakePins) Generation() uint64 { return f.gen }
func (f *fakePins) Refresh(context.Context) (bool, error) {
	f.refreshes.Add(1)
	if f.next == "" || f.next == f.cur {
		return false, nil
	}
	f.cur, f.next = f.next, ""
	f.gen++
	return true, nil
}

// A peer that fails the pins makes the client look for newer pins; with
// them the request goes through, body and all. Without them it fails.
func TestRefreshingTransportRetriesOnceWithNewPins(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(string(b))
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	pools := map[string]*x509.CertPool{"old": x509.NewCertPool(), "new": x509.NewCertPool()}
	pools["new"].AddCert(srv.Certificate())
	src := &fakePins{cur: "old"}
	tr := &refreshingTransport{src: src, build: func(rv refvalues.ReferenceValues) (*http.Transport, error) {
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pools[rv.Images[0].Name], MinVersion: tls.VersionTLS12}}, nil
	}}
	hc := &http.Client{Transport: tr}
	// No newer pins: the failure stands.
	if _, err := hc.Post(srv.URL, "text/plain", strings.NewReader("a")); err == nil {
		t.Fatal("a peer outside the pins was accepted")
	}
	// The operator moved the pins: one refresh, one retry, the body intact.
	src.next = "new"
	before := src.refreshes.Load()
	resp, err := hc.Post(srv.URL, "text/plain", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Load() != "body" || src.refreshes.Load() != before+1 {
		t.Fatalf("retry: body %v, refreshes %d", got.Load(), src.refreshes.Load()-before)
	}
	// Later requests use the new pins without refreshing.
	before = src.refreshes.Load()
	resp, err = hc.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if src.refreshes.Load() != before {
		t.Fatal("refreshed although the pins matched")
	}
}

// A server pinning its clients through a PinSource re-checks a refused
// handshake once against newer pins, and only when they changed.
func TestRefreshingPeerVerifier(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(pinDigest("new"))))
	src := &fakePins{cur: "old"}
	verify := RefreshingPeerVerifier(src, stub.URL())
	raw := [][]byte{cert.Raw}
	if err := verify(raw, nil); err == nil {
		t.Fatal("a client outside the pins passed")
	}
	if src.refreshes.Load() != 1 {
		t.Fatalf("refreshes %d, want 1", src.refreshes.Load())
	}
	// The operator moved the pins: the same handshake is checked again
	// against them, and passes.
	src.next = "new"
	if err := verify(raw, nil); err != nil {
		t.Fatalf("client on the new pins refused: %v", err)
	}
	if src.refreshes.Load() != 2 {
		t.Fatalf("refreshes %d, want 2", src.refreshes.Load())
	}
	// Later handshakes use the new pins without refreshing.
	if err := verify(raw, nil); err != nil || src.refreshes.Load() != 2 {
		t.Fatalf("later handshake: %v, refreshes %d", err, src.refreshes.Load())
	}
}

func TestRefreshingTransportBuildError(t *testing.T) {
	src := &fakePins{cur: "old"}
	if _, err := NewRefreshingTransport(src, func(Pins) (*http.Transport, error) { return nil, errors.New("boom") }); err == nil {
		t.Fatal("build error swallowed")
	}
}

// A body that cannot be replayed is not retried, even though a retry on the
// new pins would succeed.
func TestRefreshingTransportDoesNotReplayABody(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served.Add(1) }))
	defer srv.Close()
	src := &fakePins{cur: "old", next: "new"}
	tr, err := NewRefreshingTransport(src, func(p Pins) (*http.Transport, error) {
		pool := x509.NewCertPool()
		if p.Images[0].Name == "new" {
			pool.AddCert(srv.Certificate())
		}
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, io.NopCloser(strings.NewReader("x")))
	if _, err := tr.RoundTrip(req); err == nil || served.Load() != 0 {
		t.Fatalf("non-replayable body retried: err %v, served %d", err, served.Load())
	}
	if src.refreshes.Load() != 1 || src.cur != "new" {
		t.Fatalf("refreshes %d cur %q", src.refreshes.Load(), src.cur)
	}
	// The next request runs on the new pins.
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
