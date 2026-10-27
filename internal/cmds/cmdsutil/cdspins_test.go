package cmdsutil

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// A credential client follows the policy the enforcer rewrites in place; a
// half-written document leaves its set as it was.
func TestNodePinsFollowsTheMountedPolicy(t *testing.T) {
	src, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := refvalues.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cds-pins.json")
	if n, err := FollowNodePins(path); n != nil || err != nil {
		t.Fatalf("absent policy: %v %v", n, err)
	}
	if _, err := NewNodePins(path); err == nil {
		t.Fatal("absent policy accepted")
	}
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FollowNodePins(filepath.Join(path, "x")); err == nil {
		t.Fatal("a stat error other than absent ignored")
	}
	n, err := FollowNodePins(path)
	if err != nil || n.Generation() != 1 || len(n.Current().Images) != len(set.Images) {
		t.Fatalf("start: %v", err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err != nil {
		t.Fatalf("unchanged file: %v %v", changed, err)
	}
	if err := os.WriteFile(path, src[:len(src)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); changed || err == nil || n.Generation() != 1 {
		t.Fatalf("half-written: %v %v", changed, err)
	}
	fewer := set
	fewer.Images = set.Images[:1]
	doc, err := refvalues.Format(fewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.Refresh(t.Context()); !changed || err != nil || n.Generation() != 2 || len(n.Current().Images) != 1 {
		t.Fatalf("rewritten: %v %v", changed, err)
	}
}

// A client whose requests keep succeeding still drops a CDS the operator
// removed: within the recheck interval it stops reusing the connection made
// under the old pins and handshakes against the new ones.
func TestNodePinsDropsARemovedCDSWithoutAFailure(t *testing.T) {
	src, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := refvalues.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	old := nodePinsRecheck
	nodePinsRecheck = 50 * time.Millisecond
	t.Cleanup(func() { nodePinsRecheck = old })
	n, err := NewNodePins(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	// The server's certificate stands for the image named "server": a set
	// without it does not trust the server.
	rt, err := armtls.NewRefreshingTransport(n, func(p armtls.Pins) (*http.Transport, error) {
		pool := x509.NewCertPool()
		if slices.ContainsFunc(p.Images, func(i remote.ImagePin) bool { return i.Name == "server" }) {
			pool.AddCert(srv.Certificate())
		}
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: rt}
	get := func() error {
		resp, err := hc.Get(srv.URL)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}
	if err := get(); err != nil {
		t.Fatalf("pinned CDS refused: %v", err)
	}
	// Negative control: an unchanged policy keeps the connection usable.
	time.Sleep(2 * nodePinsRecheck)
	if err := get(); err != nil {
		t.Fatalf("unchanged policy: %v", err)
	}
	// The enforcer rewrites the policy without the server's image.
	fewer := set
	fewer.Images = slices.DeleteFunc(slices.Clone(set.Images), func(i remote.ImagePin) bool { return i.Name == "server" })
	doc, err := refvalues.Format(fewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * nodePinsRecheck)
	if err := get(); err == nil {
		t.Fatal("a CDS the policy no longer pins still answered over the old connection")
	}
}
