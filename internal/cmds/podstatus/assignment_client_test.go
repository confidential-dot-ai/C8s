package podstatus

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// assignmentTarget verifies a fresh empty guest whose /v1/assign is served by
// assign, and returns the target with the bytes Prepare kept.
func assignmentTarget(t *testing.T, s *assignmentService, key *ecdsa.PrivateKey, assign http.HandlerFunc) (*AssignmentTarget, []byte) {
	t.Helper()
	cfg := attestFixture(t, nil, nil, nil, wrapGuest(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case AssignNoncePath:
				s.serveNonce(w, r)
			case AssignPath:
				assign(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}))
	target, err := VerifyAssignmentTarget(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	if len(lastClaimed) != 0 {
		t.Fatal("assignment target was not verified with an empty measured list")
	}
	body, err := target.Prepare(t.Context(), key, assignmentManifest("pod-a"), []byte(assignmentEntries), []byte("[]"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return target, body
}

// The kept bytes bind the verified channel, reach the guest unchanged
// after Prepare kept them, are acknowledged with the manifest's UID, and a
// re-send is the held Pod's 409.
func TestAssignmentClientAssignsOverTheVerifiedChannel(t *testing.T) {
	s, key, _, store := assignmentFixture(t)
	var posts atomic.Int32
	var peer atomic.Pointer[ecdsa.PublicKey]
	target, body := assignmentTarget(t, s, key, func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		// The TLS server's key is installed below after fresh verification.
		s.serveAssign(w, r.WithContext(armtls.WithServingKey(r.Context(), peer.Load())))
	})
	peer.Store(target.peer.(*ecdsa.PublicKey))
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

// A measured guest is no target; the kept bytes never reach a
// guest with another serving key; 409 is the held Pod, named or not; any other
// status and any 200 whose strict body is not the manifest's UID is refused.
func TestAssignmentClientRefusals(t *testing.T) {
	cfg := attestFixture(t, []string{dA}, []string{dA}, nil)
	if target, err := VerifyAssignmentTarget(t.Context(), cfg); err == nil || target != nil {
		t.Fatal("measured guest became an assignment target")
	}
	for _, tc := range []struct {
		name, body string
		status     int
		held       string
		assigned   bool
	}{
		{name: "changed key"},
		{name: "409 with UID", status: http.StatusConflict, body: `{"uid":"pod-b"}`, assigned: true, held: "pod-b"},
		{name: "409 unnamed", status: http.StatusConflict, body: "Pod already assigned\n", assigned: true},
		{name: "other status", status: http.StatusServiceUnavailable, body: `unavailable`},
		{name: "200 wrong Pod", status: http.StatusOK, body: `{"uid":"another-pod"}`},
		{name: "200 unknown member", status: http.StatusOK, body: `{"uid":"pod-a","accepted":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, key, _, _ := assignmentFixture(t)
			var expected []byte
			target, body := assignmentTarget(t, s, key, func(w http.ResponseWriter, r *http.Request) {
				if got, err := io.ReadAll(r.Body); err != nil || !bytes.Equal(got, expected) {
					t.Error("kept bytes changed in flight")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			expected = body
			if tc.name == "changed key" {
				other := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("kept bytes reached a guest with another serving key")
				}))
				other.TLS = &tls.Config{Certificates: []tls.Certificate{ecdsaCert(t)}}
				other.StartTLS()
				t.Cleanup(other.Close)
				target.base = other.URL
			}
			uid, err := target.Send(t.Context(), body)
			var held *AlreadyAssignedError
			if err == nil || uid != "" || errors.Is(err, ErrAlreadyAssigned) != tc.assigned || (tc.assigned && (!errors.As(err, &held) || held.HeldUID != tc.held)) {
				t.Fatalf("refusal reported %q, %v", uid, err)
			}
			if tc.name == "changed key" && !strings.Contains(err.Error(), "serving key differs") {
				t.Fatalf("pinned channel did not refuse the other key: %v", err)
			}
		})
	}
}

func TestAlreadyAssignedErrorNamesTheHeldPod(t *testing.T) {
	if got := (&AlreadyAssignedError{HeldUID: "pod-a"}).Error(); got != "guest already holds Pod pod-a" {
		t.Fatalf("named: %q", got)
	}
	if got := (&AlreadyAssignedError{}).Error(); !strings.Contains(got, "did not name") {
		t.Fatalf("unnamed: %q", got)
	}
}

// The frozen serving key cannot be changed through the returned copy.
func TestAssignmentTargetServingKeyIsACopy(t *testing.T) {
	target := &AssignmentTarget{spki: []byte("spki")}
	key := target.ServingKey()
	key[0] = 'x'
	if !bytes.Equal(target.ServingKey(), []byte("spki")) {
		t.Fatal("serving key changed through its copy")
	}
}

// A guest that refuses the nonce or returns a malformed one gets nothing
// signed; bytes that are not an assignment of an identified Pod, and an
// oversized answer, are refused.
func TestAssignmentTargetRefusesMalformedExchanges(t *testing.T) {
	var nonceStatus int
	var nonceBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case AssignNoncePath:
			w.WriteHeader(nonceStatus)
			_, _ = io.WriteString(w, nonceBody)
		case AssignPath:
			_, _ = w.Write(bytes.Repeat([]byte("x"), 4097))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := &AssignmentTarget{client: srv.Client(), base: srv.URL, peer: &key.PublicKey}
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{name: "refused", status: http.StatusServiceUnavailable, body: "unavailable", want: "503"},
		{name: "short nonce", status: http.StatusOK, body: `{"nonce":"AAAA"}`, want: "invalid assignment nonce"},
		{name: "unknown member", status: http.StatusOK, body: `{"nonce":"AAAA","extra":1}`, want: "invalid assignment nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonceStatus, nonceBody = tc.status, tc.body
			data, err := target.Prepare(t.Context(), key, assignmentManifest("pod-a"), []byte(assignmentEntries), []byte("[]"), nil)
			if err == nil || data != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("prepared %q, %v; want %q", data, err, tc.want)
			}
		})
	}
	nonce := make([]byte, podassign.NonceSize)
	if _, err := target.Send(t.Context(), []byte("{")); !errors.Is(err, podassign.ErrMalformed) {
		t.Fatalf("undecodable assignment: %v", err)
	}
	anonymous := encodeAssignment(t, podassign.Request{Nonce: nonce, Manifest: assignmentManifest("")})
	if _, err := target.Send(t.Context(), anonymous); err == nil || !strings.Contains(err.Error(), "no valid Pod identity") {
		t.Fatalf("assignment without a Pod UID: %v", err)
	}
	assignment := encodeAssignment(t, podassign.Request{Nonce: nonce, Manifest: assignmentManifest("pod-a")})
	if uid, err := target.Send(t.Context(), assignment); err == nil || uid != "" || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("oversized answer: %q, %v", uid, err)
	}
	broken := &AssignmentTarget{client: srv.Client(), base: "https://guest\x7f"}
	if _, err := broken.Send(t.Context(), assignment); err == nil {
		t.Fatal("assignment sent to an invalid address")
	}
}
