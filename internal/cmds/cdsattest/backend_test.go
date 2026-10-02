package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// writeClientKeyPair writes a self-signed client cert + key PEM pair.
func writeClientKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "c8s-router-client"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestNewHTTPBackendTimeouts pins the client timeout fallback and the
// transport's idle-connection timeout.
func TestNewHTTPBackendTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero falls back to default", 0, 30 * time.Second},
		{"negative falls back to default", -time.Second, 30 * time.Second},
		{"positive kept verbatim", 5 * time.Second, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hb, err := NewHTTPBackend("http://backend", HTTPBackendOptions{Timeout: tc.timeout})
			if err != nil {
				t.Fatal(err)
			}
			if hb.client.Timeout != tc.want {
				t.Fatalf("client timeout = %v, want %v", hb.client.Timeout, tc.want)
			}
			rt, ok := hb.client.Transport.(*resettableTransport)
			if !ok {
				t.Fatalf("transport is %T, want *resettableTransport", hb.client.Transport)
			}
			transport := rt.current
			if transport.IdleConnTimeout != 90*time.Second {
				t.Fatalf("IdleConnTimeout = %v, want 90s", transport.IdleConnTimeout)
			}
		})
	}
}

// TestHTTPBackendAcceptsMaxSizedUpstreamResponse: a response of exactly the cap
// must pass; only strictly-larger bodies are rejected.
func TestHTTPBackendAcceptsMaxSizedUpstreamResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), maxUpstreamResponseBytes))
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "GET", Path: "/"})
	if err != nil {
		t.Fatalf("max-sized upstream response rejected: %v", err)
	}
	if len(resp.Body) != maxUpstreamResponseBytes {
		t.Fatalf("body length = %d, want %d", len(resp.Body), maxUpstreamResponseBytes)
	}
}

func TestNewHTTPBackendErrors(t *testing.T) {
	dir := t.TempDir()
	garbageCA := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbageCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		base    string
		opts    HTTPBackendOptions
		wantSub string
	}{
		{"bad scheme", "ftp://backend", HTTPBackendOptions{}, "must be an http:// or https:// URL"},
		{"missing CA file", "https://backend", HTTPBackendOptions{TrustedCAFile: filepath.Join(dir, "missing-ca.pem")}, "read upstream CA"},
		{"CA file with no certs", "https://backend", HTTPBackendOptions{TrustedCAFile: garbageCA}, "has no certificates"},
		{"missing client keypair", "https://backend", HTTPBackendOptions{
			ClientCertFile: filepath.Join(dir, "missing.pem"),
			ClientKeyFile:  filepath.Join(dir, "missing.key"),
		}, "load upstream client cert"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTPBackend(tc.base, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("NewHTTPBackend() error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestHTTPBackendHTTPSWithMTLSMaterial(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure hello "+r.Method+" "+r.URL.Path)
	}))
	defer backend.Close()

	// Trust the httptest server's own certificate as the "mesh CA".
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeClientKeyPair(t)

	hb, err := NewHTTPBackend(backend.URL+"/", HTTPBackendOptions{
		TrustedCAFile:  caPath,
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Empty method defaults to GET; a path without a leading slash gets one.
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{Path: "v1/models"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "secure hello GET /v1/models" {
		t.Fatalf("unexpected response: %d %q", resp.Status, resp.Body)
	}
}

func TestHTTPBackendStripsHopByHopHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-C8s-Session"); got != "" {
			t.Errorf("session header leaked upstream: %q", got)
		}
		if got := r.Header.Get("X-App"); got != "kept" {
			t.Errorf("app header not forwarded: %q", got)
		}
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Resp", "kept")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{
		Method: "GET",
		Path:   "/",
		Headers: []types.HeaderField{
			{Name: "X-C8s-Session", Value: "sess-id"},
			{Name: "X-App", Value: "kept"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := headerValues(resp.Headers, "Keep-Alive"); len(got) != 0 {
		t.Error("hop-by-hop response header not stripped")
	}
	if got := headerValues(resp.Headers, "X-Resp"); len(got) != 1 || got[0] != "kept" {
		t.Errorf("response header lost: %+v", resp.Headers)
	}
}

// headerValues collects the values a pair list carries under name.
func headerValues(fields []types.HeaderField, name string) []string {
	var values []string
	for _, f := range fields {
		if f.Name == name {
			values = append(values, f.Value)
		}
	}
	return values
}

// TestHTTPBackendPreservesDuplicateHeaders: the pair-based envelope must carry
// every value of a repeated field in both directions — the map envelope's
// collapse of Set-Cookie was the bug the v2 envelope exists to fix.
func TestHTTPBackendPreservesDuplicateHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Values("X-Multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
			t.Errorf("duplicate request header not forwarded intact: %v", got)
		}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{
		Method: "GET",
		Path:   "/",
		Headers: []types.HeaderField{
			{Name: "X-Multi", Value: "one"},
			{Name: "X-Multi", Value: "two"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := headerValues(resp.Headers, "Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Fatalf("duplicate response header collapsed: %v", got)
	}
}

func TestHTTPBackendForwardErrors(t *testing.T) {
	// Point at a closed listener so client.Do fails.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	hb, err := NewHTTPBackend(deadURL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "GET", Path: "/"}); err == nil ||
		!strings.Contains(err.Error(), "forward to upstream") {
		t.Fatalf("expected forward error, got %v", err)
	}

	// An invalid method makes request construction itself fail.
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "BAD METHOD", Path: "/"}); err == nil ||
		!strings.Contains(err.Error(), "build upstream request") {
		t.Fatalf("expected build error, got %v", err)
	}
}

// The upstream client credential is get-cert-managed and rotates under a
// long-lived process. Loading it once into tls.Config.Certificates pinned one
// leaf forever: the upstream verifies it against its ClientCAs, so the first
// expiry broke the backend hop until the sidecar restarted. The loader must
// re-read the files and refuse a credential outside its validity window.
func TestUpstreamCertLoaderReloadsAndEnforcesValidity(t *testing.T) {
	now := time.Now()
	expired := writeTestMeshIdentityWithLeafValidity(t, now.Add(-2*time.Hour), now.Add(-time.Hour))

	// Startup is deliberately tolerant: the files parse, so a sidecar
	// restarting during a CDS outage still comes up.
	loader, err := newUpstreamCertLoader(expired.certFile, expired.keyFile)
	if err != nil {
		t.Fatalf("newUpstreamCertLoader on an expired but well-formed pair: %v", err)
	}
	if _, err := loader.getClientCertificate(nil); err == nil {
		t.Fatal("an expired client credential was handed to a handshake")
	}

	// get-cert rotates: the same paths now hold a valid credential, and the
	// loader must pick it up without a restart.
	fresh := writeTestMeshIdentityWithLeafValidity(t, now.Add(-time.Minute), now.Add(time.Hour))
	copyFile(t, fresh.certFile, expired.certFile)
	copyFile(t, fresh.keyFile, expired.keyFile)

	got, err := loader.getClientCertificate(nil)
	if err != nil {
		t.Fatalf("rotated credential not picked up: %v", err)
	}
	if !got.Leaf.Equal(fresh.leaf) {
		t.Fatal("loader served a leaf other than the rotated one")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
