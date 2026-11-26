package operatorauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRequestBinding(t *testing.T) {
	key, pub := genKey(t, elliptic.P256())
	signer, err := NewSignerFromKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier := Verifier{Keys: []*ecdsa.PublicKey{pub}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if err := verifier.Authorize(r, body); err != nil {
			t.Errorf("verify received request: %v", err)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPut, "/secrets/key", []byte(`{"value":"secret"}`)},
		{http.MethodPost, "/prefix/release", []byte(`{"csr":"test"}`)},
		{http.MethodDelete, "/allowlist/workloads/a%20b", nil},
		{"", "/secrets-explain/sandbox?detail=true", nil},
		{http.MethodPut, "/empty", []byte{}},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			ctx := t.Context()
			req, err := NewRequest(ctx, tc.method, server.URL+tc.path, tc.body, signer)
			if err != nil {
				t.Fatal(err)
			}
			if req.Context() != ctx {
				t.Fatal("request lost its context")
			}
			// Neither the initial send nor a replay may alias the caller's bytes.
			for i := range tc.body {
				tc.body[i] = 'x'
			}
			if req.GetBody != nil {
				replay, err := req.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(replay)
				replay.Close()
				if err != nil {
					t.Fatal(err)
				}
				if err := verifier.Authorize(req, body); err != nil {
					t.Fatalf("verify replay body: %v", err)
				}
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
		})
	}
}

type failedAuthorizer struct{ err error }

func (a failedAuthorizer) Authorization(string, string, []byte) (string, error) {
	return "", a.err
}

func TestNewRequestErrors(t *testing.T) {
	failure := errors.New("signing failed")
	for _, tc := range []struct {
		name, url string
		auth      Authorizer
		want      error
	}{
		{"signer failure", "http://ta/secrets/key", failedAuthorizer{failure}, failure},
		{"invalid URL", "://", failedAuthorizer{failure}, nil},
		{"nil authorizer", "http://ta/secrets/key", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := NewRequest(context.Background(), http.MethodPut, tc.url, nil, tc.auth)
			if req != nil || err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("request = %v, error = %v; want no request and error %v", req, err, tc.want)
			}
		})
	}
}
