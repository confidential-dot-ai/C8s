package cds

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/server"
)

func TestObjectServerNeverPublishesAnOlderCARevision(t *testing.T) {
	published := make(
		chan uint64,
		4,
	)
	s := newObjectServer(
		t.Context(),
		config{
			measured: &cdsconfig.Config{
				ObjectState: &cdsconfig.ObjectState{
					Workers:       1,
					QueueCapacity: 1,
				},
			},
		},
		nil,
		nil,
		nil,
		func(cert *x509.Certificate) {
			published <- cert.SerialNumber.Uint64()
		},
	)
	t.Cleanup(s.Stop)
	for _, revision := range []uint64{
		2,
		1,
		2,
		3,
	} {
		s.publishCA(
			t.Context(),
			revision,
			&x509.Certificate{SerialNumber: new(big.Int).SetUint64(revision)},
		)
	}
	s.Stop()
	if len(published) != 2 {
		t.Fatalf(
			"published %d certificates, want only revisions 2 and 3",
			len(published),
		)
	}
	for _, want := range []uint64{
		2,
		3,
	} {
		if got := <-published; got != want {
			t.Fatalf(
				"published revision %d, want %d",
				got,
				want,
			)
		}
	}
}

func TestObjectServerMaintenancePublishesCommittedCAWithoutWriting(t *testing.T) {
	h := newObjectAcceptance(t)
	published := make(
		chan *x509.Certificate,
		1,
	)
	s := newObjectServer(
		t.Context(),
		h.cfg,
		h.store,
		h.cipher,
		h.servers[0].dependencies,
		func(cert *x509.Certificate) {
			published <- cert
		},
	)
	t.Cleanup(s.Stop)
	if err := s.refreshCA(); err != nil {
		t.Fatal(err)
	}
	select {
	case cert := <-published:
		if !cert.Equal(h.root) {
			t.Fatal("read published a different CA")
		}
	case <-time.After(time.Second):
		t.Fatal("read did not refresh the committed client CA")
	}
	if s.commits.Load() != 0 {
		t.Fatal("a read without a renewal wrote state")
	}
}

func TestObjectServerStopInterruptsAnHTTP1Upload(t *testing.T) {
	h := newObjectAcceptance(t)
	read := make(chan struct{})
	returned := make(chan struct{})
	endpoint := httptest.NewServer(server.RequestLogger(http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		defer close(returned)
		r.Body = &objectHTTPReadNotice{
			ReadCloser: r.Body,
			read:       read,
		}
		h.servers[0].ServeHTTP(
			w,
			r,
		)
	})))
	t.Cleanup(endpoint.Close)
	connection, err := net.DialTimeout(
		"tcp",
		endpoint.Listener.Addr().String(),
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Keep the HTTP/1 connection open with almost all declared bytes missing.
	// Body.Close itself then attempts to drain them unless Read is interrupted.
	if _, err := fmt.Fprint(
		connection,
		"PUT /allowlist HTTP/1.1\r\nHost: test\r\nContent-Length: 1024\r\n\r\n{",
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never read the HTTP request body")
	}
	stopped := make(chan struct{})
	go func() {
		h.servers[0].Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop waited for the client to finish uploading")
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("request body cancellation did not become quiescent")
	}
	response, err := http.ReadResponse(
		bufio.NewReader(connection),
		&http.Request{Method: http.MethodPut},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf(
			"canceled HTTP request status = %d, want 503",
			response.StatusCode,
		)
	}
}

type objectHTTPReadNotice struct {
	io.ReadCloser
	read chan struct{}
	once sync.Once
}

func (b *objectHTTPReadNotice) Read(dst []byte) (int, error) {
	n, err := b.ReadCloser.Read(dst)
	if n > 0 {
		b.once.Do(func() { close(b.read) })
	}
	return n, err
}
