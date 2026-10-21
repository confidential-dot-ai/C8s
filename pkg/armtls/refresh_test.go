package armtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// fakePins stands in for cdspins: Name of the one image says which server
// certificate the transport trusts.
type fakePins struct {
	cur, next string
	gen       uint64
	refreshes atomic.Int32
}

func (f *fakePins) Current() refvalues.ReferenceValues {
	return refvalues.ReferenceValues{Images: []remote.ImagePin{{Name: f.cur}}}
}
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
