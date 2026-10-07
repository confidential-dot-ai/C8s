package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// writeLeaf stages a certificate and key where the cert sidecar would leave
// them.
func writeLeaf(t *testing.T, dir string) (certPath, keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	write(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath, &key.PublicKey
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testConfig(url string) Config {
	return Config{
		CDSURL:            url,
		AttestationApiURL: "http://127.0.0.1:8080",
		Attempts:          3,
		RetryInterval:     time.Millisecond,
		RequestTimeout:    5 * time.Second,
		InventoryTimeout:  5 * time.Second,
	}
}

// The sandbox token binds to the leaf's key, so NewClient must return the key
// of the certificate it presents — not a fresh one.
func TestNewClientReturnsLeafKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, want := writeLeaf(t, dir)
	cfg := testConfig("https://cds.example")
	cfg.CertPath, cfg.KeyPath = certPath, keyPath

	client, pub, err := NewClient(cfg, armtls.Pins{})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("no client returned")
	}
	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	if !got.Equal(want) {
		t.Fatal("returned key is not the leaf's")
	}
}

// A missing or unreadable leaf is a retryable failure, not a panic: the cert
// sidecar may not have written it yet.
func TestNewClientWithoutLeaf(t *testing.T) {
	for _, tc := range []struct{ name, cert, key string }{
		{"absent", "nope.crt", "nope.key"},
		{"garbage", "bad.crt", "bad.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := testConfig("https://cds.example")
			cfg.CertPath = filepath.Join(dir, tc.cert)
			cfg.KeyPath = filepath.Join(dir, tc.key)
			if tc.name == "garbage" {
				write(t, cfg.CertPath, []byte("not a pem"))
				write(t, cfg.KeyPath, []byte("not a pem"))
			}
			if _, _, err := NewClient(cfg, armtls.Pins{}); err == nil {
				t.Fatal("a missing leaf was accepted")
			}
		})
	}
}

// The provider reloads from disk, so a renewal written by the cert sidecar is
// picked up without restarting this one.
func TestLeafProviderReloads(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, first := writeLeaf(t, dir)
	p := leafProvider{certPath: certPath, keyPath: keyPath}

	got, ttl, err := p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("ttl = %v, want positive", ttl)
	}
	parsed, _ := x509.ParseCertificate(got.Certificate[0])
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(first) {
		t.Fatal("first provision returned the wrong key")
	}

	_, _, second := writeLeaf(t, dir) // renewal lands on the same paths
	got, _, err = p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = x509.ParseCertificate(got.Certificate[0])
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(second) {
		t.Fatal("provision did not pick up the renewed leaf")
	}
}

func TestFetchChallengeFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"server refuses", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusServiceUnavailable)
		}},
		{"not json", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("not json"))
		}},
		{"not base64", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"challenge":"!!!"}`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			if _, err := fetchChallenge(context.Background(), testConfig(srv.URL), http.DefaultClient); err == nil {
				t.Fatal("a bad challenge response was accepted")
			}
		})
	}
}

// An unreachable CDS is an error, not a hang or a nil value.
func TestFetchChallengeUnreachable(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.RequestTimeout = 200 * time.Millisecond
	if _, err := fetchChallenge(context.Background(), cfg, http.DefaultClient); err == nil {
		t.Fatal("an unreachable CDS reported success")
	}
}
