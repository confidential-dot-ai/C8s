package routesclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
)

const manifest = `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`

// fakeCDS stores what an authorized PUT sends and serves it back, verifying
// the token as the CDS does.
type fakeCDS struct {
	mu  sync.Mutex
	env *routes.Envelope
	key *ecdsa.PublicKey
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != routes.Path {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if f.env == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.env)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if err := (operatorauth.Verifier{Keys: []*ecdsa.PublicKey{f.key}}).Authorize(r, body); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.env != nil {
			http.Error(w, "revision not greater", http.StatusConflict)
			return
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.env = &routes.Envelope{Manifest: body, Token: token}
		w.WriteHeader(http.StatusNoContent)
	}
}

func newSigner(t *testing.T) (*operatorauth.Signer, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return s, &key.PublicKey
}

func newClient(t *testing.T, h http.Handler) routesclient.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := routesclient.New(srv.URL+"/", &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRejectsURLWithPath(t *testing.T) {
	for _, u := range []string{"https://cds.example/api", "https://cds.example/routes", "https://cds.example?x=1", "https://cds.example#f", "cds.example", "://", "//cds.example", "ftp://cds.example"} {
		if _, err := routesclient.New(u, http.DefaultClient); err == nil {
			t.Errorf("New(%q) = nil error, want a refusal", u)
		}
	}
	for _, u := range []string{"https://cds.example", "https://cds.example:8443/"} {
		if _, err := routesclient.New(u, http.DefaultClient); err != nil {
			t.Errorf("New(%q) = %v, want nil", u, err)
		}
	}
}

// W2 end to end: Put signs PUT /routes over the exact bytes, and the
// envelope Get returns verifies under the signer's key.
func TestPutThenGet(t *testing.T) {
	signer, key := newSigner(t)
	c := newClient(t, &fakeCDS{key: key})
	ctx := context.Background()

	if _, err := c.Get(ctx); !errors.Is(err, routesclient.ErrNotFound) {
		t.Fatalf("Get() before Put error = %v, want ErrNotFound", err)
	}
	if err := c.Put(ctx, []byte(manifest), signer, ""); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	env, err := c.Get(ctx)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(env.Manifest, []byte(manifest)) {
		t.Fatalf("Get() manifest = %q, want %q", env.Manifest, manifest)
	}
	if _, err := routes.VerifySigned(env, []*ecdsa.PublicKey{key}, nil); err != nil {
		t.Fatalf("VerifySigned(Get()) error = %v", err)
	}

	var se *operatorauth.StatusError
	if err := c.Put(ctx, []byte(manifest), signer, ""); !errors.As(err, &se) || se.Status != http.StatusConflict {
		t.Fatalf("second Put() error = %v, want a 409 StatusError", err)
	}
}

// C2: Put sends If-Match only when given an expected digest.
func TestPutIfMatch(t *testing.T) {
	signer, _ := newSigner(t)
	for _, want := range []string{"", strings.Repeat("ab", 32)} {
		var got []string
		c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Values("If-Match")
			w.WriteHeader(http.StatusNoContent)
		}))
		if err := c.Put(context.Background(), []byte(manifest), signer, want); err != nil {
			t.Fatalf("Put(%q) error = %v", want, err)
		}
		if (want == "" && len(got) != 0) || (want != "" && (len(got) != 1 || got[0] != want)) {
			t.Fatalf("Put(%q) sent If-Match %q", want, got)
		}
	}
}

func TestGetRejectsMalformedResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"wrong content type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, `{"manifest":"","token":""}`)
		},
		"extra member": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"manifest":"e30=","token":"t","x":1}`)
		},
		"unpadded base64": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"manifest":"e30","token":"t"}`)
		},
		"server error": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newClient(t, h).Get(context.Background()); err == nil {
				t.Fatal("Get() = nil error, want a rejection")
			}
		})
	}
}
