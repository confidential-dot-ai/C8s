package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

func testPubKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// A malformed success body must not be mistaken for a secret.
func TestSecretResponseMustBeDecodable(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"value not base64", `{"value":"!!!"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := "unix://" + testutil.StartInventory(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/secrets" {
					w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
					return
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, _, err := Do(context.Background(), testConfig(srv.URL), http.DefaultClient, testPubKey(t), endpoint, http.MethodGet, "/api/db")
			if err == nil {
				t.Fatal("an undecodable body was accepted as a secret")
			}
		})
	}
}

// The inventory is where the sandbox token comes from; without it there is no
// request to make.
func TestUnreachableInventoryFails(t *testing.T) {
	endpoint := "unix://" + filepath.Join(t.TempDir(), "absent.sock")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	}))
	defer srv.Close()
	_, _, err := Do(context.Background(), testConfig(srv.URL), http.DefaultClient, testPubKey(t), endpoint, http.MethodGet, "/api/db")
	if err == nil || !strings.Contains(err.Error(), "sandbox token") {
		t.Fatalf("err = %v, want a sandbox-token failure", err)
	}
}
