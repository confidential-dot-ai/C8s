package podprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The guest status server renews its certificate long before a Pod's lifetime
// ends; with the key the server is given, the pin taken at assignment still
// accepts the renewed certificate.
func TestServingKeyPinAcceptsRenewedCertificate(t *testing.T) {
	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		done <- armtls.ServeListener(ctx, ln, "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &armtls.ServerConfig{
			Platform: "sev-snp",
			AttestFunc: func(context.Context, string) (string, error) {
				return string(make([]byte, armtls.SNPReportSize)), nil
			},
			CertTTL: 2 * time.Second,
			Key:     key,
		})
	}()

	// Pin the key the first handshake shows, as assignment does.
	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	first := resp.TLS.PeerCertificates[0].SerialNumber.String()
	assigned, err := x509.MarshalPKIXPublicKey(resp.TLS.PeerCertificates[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if client, err = pinServingKey(client, assigned); err != nil {
		t.Fatal(err)
	}
	serial := func() string {
		t.Helper()
		resp, err := client.Get("https://" + ln.Addr().String())
		if err != nil {
			t.Fatalf("pinned client refused the guest: %v", err)
		}
		resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}
	for deadline := time.Now().Add(10 * time.Second); serial() == first; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the certificate was never renewed")
		}
	}
}
