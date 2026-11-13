package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
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

// A CDS answer is one document: a second document after it, or a body past the
// cap, is refused rather than read as the challenge or the secret.
func TestCDSAnswersMustBeOneDocument(t *testing.T) {
	const challenge = `{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	const secret = `{"value":"czNjcmV0"}`

	challengeError := func(t *testing.T, body string) error {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		_, err := FetchChallenge(context.Background(), http.DefaultClient, srv.URL, 5*time.Second)
		return err
	}
	secretError := func(t *testing.T, body string) error {
		t.Helper()
		endpoint := "unix://" + testutil.StartInventory(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/secrets" {
				_, _ = w.Write([]byte(challenge))
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		_, _, err := Do(context.Background(), testConfig(srv.URL), http.DefaultClient, testPubKey(t), endpoint, http.MethodGet, "/api/db")
		return err
	}

	if err := challengeError(t, challenge+challenge); err == nil {
		t.Fatal("a challenge followed by a second document was accepted")
	}
	if err := challengeError(t, challenge+strings.Repeat(" ", 1<<16)); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("challenge past the cap = %v, want a refused read", err)
	}
	if err := secretError(t, secret+secret); err == nil {
		t.Fatal("a secret response followed by a second document was accepted")
	}
	if err := secretError(t, secret+strings.Repeat(" ", 1<<20)); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("secret response past the cap = %v, want a refused read", err)
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
