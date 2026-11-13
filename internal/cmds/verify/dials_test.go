package verify

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Every gather that dials rides pendingattestation.TLSConfig, whose floor is
// TLS 1.3: a peer that speaks only TLS 1.2 never carries evidence.
func TestDialsRefuseTLS12(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	for _, tc := range []struct {
		name string
		dial func() error
	}{
		{
			name: "armTLS serving cert",
			dial: func() error {
				_, err := gatherFromARMTLSCert(context.Background(), addr, "", 5*time.Second, leafTrust{})
				return err
			},
		},
		{
			name: "attestation endpoint",
			dial: func() error {
				_, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second, testRoute)
				return err
			},
		},
		{
			name: "attest-lb",
			dial: func() error {
				_, err := gatherFromAttestLB(context.Background(), srv.URL, "", 5*time.Second, testRoute)
				return err
			},
		},
		{
			name: "attested fetch",
			dial: func() error {
				_, err := fetchAttested(context.Background(), srv.URL, "", strings.Repeat("ab", 32), 5*time.Second)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.dial()
			if err == nil {
				t.Fatal("a peer below the TLS 1.3 floor must be refused")
			}
			if !strings.Contains(err.Error(), "protocol version") {
				t.Fatalf("want a TLS version failure, got %v", err)
			}
		})
	}
}
