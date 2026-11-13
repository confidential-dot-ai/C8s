package verify

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// A gather reads one document per target. A peer that answers past the cap is
// refused where the body is read, so no verdict rests on the prefix that
// arrived.
func TestGathersRefuseADocumentOverTheCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20+1))
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name   string
		gather func() error
	}{
		{
			name: "attestation endpoint",
			gather: func() error {
				_, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second, testRoute)
				return err
			},
		},
		{
			name: "discovery document",
			gather: func() error {
				_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
				return err
			},
		},
		{
			name: "attest-lb",
			gather: func() error {
				_, err := gatherFromAttestLB(context.Background(), srv.URL, "", 5*time.Second, testRoute)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.gather()
			if !errors.Is(err, readutil.ErrTooLarge) {
				t.Fatalf("err = %v, want a refused read", err)
			}
			if !isConnectError(err) {
				t.Fatalf("err = %v, want a connectError so auto mode may try the next target", err)
			}
		})
	}
}

// A complete document followed by trailing data is over the cap too: the
// trailing bytes a parser refuses must not fall off the read.
func TestADocumentPaddedToTheCapWithTrailingDataIsRefused(t *testing.T) {
	document := discoveryDocWith(t, "", []byte("challenge"), `{"hcl_report":"fake"}`)
	padded := append(document, bytes.Repeat([]byte(" "), 1<<20-len(document))...)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(append(padded, []byte("trailing")...))
	}))
	defer srv.Close()

	_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
	if !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("err = %v, want a refused read", err)
	}
}
