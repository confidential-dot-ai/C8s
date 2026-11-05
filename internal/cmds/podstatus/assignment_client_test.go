package podstatus

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestAssignmentClientRequiresEmptyEvidenceAndPersistsBeforePOST(t *testing.T) {
	s, key, _, store := assignmentFixture(t)
	var posts atomic.Int32
	var peer atomic.Pointer[ecdsa.PublicKey]
	cfg := attestFixture(t, nil, nil, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == AssignNoncePath {
				s.serveNonce(w, r)
				return
			}
			if r.URL.Path == AssignPath {
				posts.Add(1)
				// The TLS server's key is installed below after fresh verification.
				s.serveAssign(w, r.WithContext(armtls.WithServingKey(r.Context(), peer.Load())))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	target, err := VerifyAssignmentTarget(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	peer.Store(target.peer.(*ecdsa.PublicKey))
	body, err := target.Prepare(t.Context(), key, assignmentManifest("pod-a"), []byte(assignmentEntries), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 || store.record != nil {
		t.Fatal("Prepare sent assignment before durable intent")
	}
	req, err := podassign.Decode(body)
	if err != nil || podassign.Verify(&key.PublicKey, target.peer, req) != nil {
		t.Fatal("prepared bytes do not bind verified channel")
	}
	frozen := bytes.Clone(body)
	uid, err := target.Send(t.Context(), frozen)
	if err != nil || uid != "pod-a" || posts.Load() != 1 || !bytes.Equal(store.record.Request, frozen) {
		t.Fatalf("persisted intent changed: %s %v", uid, err)
	}
	_, err = target.Send(t.Context(), frozen)
	var held *AlreadyAssignedError
	if !errors.Is(err, ErrAlreadyAssigned) || !errors.As(err, &held) || held.HeldUID != "pod-a" {
		t.Fatalf("duplicate assignment was not distinguished by the held Pod: %v", err)
	}
}

func TestAssignmentTargetRefusesMeasuredGuest(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil)
	if target, err := VerifyAssignmentTarget(t.Context(), cfg); err == nil || target != nil {
		t.Fatal("measured guest became an assignment target")
	}
}

// A guest that refuses because it holds another Pod, or names none, is not the
// guest holding the caller's Pod: the error still matches ErrAlreadyAssigned but
// carries what the guest named.
func TestAssignmentClientReportsTheHeldPod(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req, err := podassign.Sign(key, &key.PublicKey, podassign.Request{Nonce: make([]byte, podassign.NonceSize), Manifest: assignmentManifest("pod-a"), Entries: []byte(assignmentEntries), MeshPeers: []byte("[]")})
	if err != nil {
		t.Fatal(err)
	}
	data, err := podassign.Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ body, want string }{
		{`{"uid":"pod-b"}`, "pod-b"},
		{"Pod already assigned\n", ""},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, tc.body)
		}))
		target := &AssignmentTarget{client: srv.Client(), base: srv.URL}
		_, err := target.Send(t.Context(), data)
		srv.Close()
		var held *AlreadyAssignedError
		if !errors.Is(err, ErrAlreadyAssigned) || !errors.As(err, &held) || held.HeldUID != tc.want {
			t.Fatalf("409 %q: %v, want held UID %q", tc.body, err, tc.want)
		}
	}
}
