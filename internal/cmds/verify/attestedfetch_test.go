package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAttestedFetchRejectsPlaintextAndRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer target.Close()
	base, pin := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	for _, tc := range []struct {
		name string
		get  func(string) error
	}{
		{"keys", func(url string) error {
			_, _, _, err := fetchOperatorKeyFingerprints(context.Background(), url, "", pin, time.Second, fetchAttested)
			return err
		}},
		{"measurements", func(url string) error {
			_, err := fetchServedMeasurements(context.Background(), url, "", pin, time.Second, fetchAttested)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, url := range []string{target.URL, base} {
				if err := tc.get(url); err == nil {
					t.Fatalf("accepted %s", url)
				}
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("sent %d unauthenticated requests", hits.Load())
	}
}

func TestAttestedFetchClosesConnection(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "attested.example" {
			t.Errorf("SNI = %q", r.TLS.ServerName)
		}
		w.Write([]byte("document"))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.StartTLS()
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	resp, err := fetchAttested(context.Background(), srv.URL, "attested.example", hex.EncodeToString(sum[:]), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "document" {
		t.Fatalf("body = %q, error = %v", body, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("fetch retained an idle connection")
	}
}

func TestAttestedFetchBoundsBodyRead(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	base, pin := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// Keep the response incomplete until the client observes cancellation.
		<-release
	})
	for _, cancelEarly := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		timeout := time.Second
		if cancelEarly {
			timeout = 5 * time.Second
		}
		resp, err := fetchAttested(ctx, base, "", pin, timeout)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if cancelEarly {
			cancel()
		}
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		want := context.DeadlineExceeded
		if cancelEarly {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatalf("body read: got %v, want %v", err, want)
		}
	}
}

func TestAttestedFetchRejectsMalformedURL(t *testing.T) {
	if _, err := fetchAttested(context.Background(), "://", "", strings.Repeat("ab", 32), time.Second); err == nil {
		t.Fatal("accepted malformed URL")
	}
}

func TestAttestedFetchRejectsDifferentDERForSameKey(t *testing.T) {
	_, first := selfSignedServerCert(t)
	second := remintServerCert(t, first)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{second}}
	srv.StartTLS()
	defer srv.Close()
	pin := sha256.Sum256(first.Certificate[0])
	if _, err := fetchAttested(context.Background(), srv.URL, "", hex.EncodeToString(pin[:]), time.Second); err == nil {
		t.Fatal("accepted another certificate with the same key")
	}
	if hits.Load() != 0 {
		t.Fatal("sent a request under a substituted certificate")
	}
}
