package podstatus

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestAssignmentClientRejectsUntrustedAcknowledgment(t *testing.T) {
	for _, response := range []struct {
		name, body string
		status     int
	}{
		{"wrong Pod", `{"uid":"another-pod"}`, http.StatusOK},
		{"duplicate identity", `{"uid":"pod-a","uid":"pod-a"}`, http.StatusOK},
		{"unknown member", `{"uid":"pod-a","accepted":true}`, http.StatusOK},
		{"malformed", `{`, http.StatusOK},
		{"oversized", strings.Repeat(" ", 4097), http.StatusOK},
		{"unavailable", `unavailable`, http.StatusServiceUnavailable},
	} {
		t.Run(response.name, func(t *testing.T) {
			s, key, _, _ := assignmentFixture(t)
			var expected []byte
			cfg := attestFixture(t, nil, nil, nil, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case AssignNoncePath:
						s.serveNonce(w, r)
					case AssignPath:
						got, err := io.ReadAll(r.Body)
						if err != nil || !bytes.Equal(got, expected) {
							t.Error("persisted request changed")
						}
						w.WriteHeader(response.status)
						_, _ = io.WriteString(w, response.body)
					default:
						next.ServeHTTP(w, r)
					}
				})
			})
			target, err := VerifyAssignmentTarget(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			expected, err = target.Prepare(t.Context(), key, assignmentManifest("pod-a"), []byte(assignmentEntries), []byte("[]"))
			if err != nil {
				t.Fatal(err)
			}
			if uid, err := target.Send(t.Context(), expected); err == nil || uid != "" {
				t.Fatal("untrusted acknowledgment reported success")
			}
		})
	}
}

func TestAssignmentClientAmbiguousPOSTReplaysExactIntent(t *testing.T) {
	s, key, _, store := assignmentFixture(t)
	var peer atomic.Pointer[ecdsa.PublicKey]
	var posts atomic.Int32
	cfg := attestFixture(t, nil, nil, nil, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case AssignNoncePath:
				s.serveNonce(w, r)
			case AssignPath:
				if posts.Add(1) == 1 {
					// Record the first POST, then lose its acknowledgment as the connection
					// drops. The caller cannot infer whether the commit happened.
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					recorder := postAssignment(s, peer.Load(), body)
					if recorder.Code != http.StatusOK {
						t.Error(recorder.Code)
					}
					conn, _, err := http.NewResponseController(w).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				s.serveAssign(w, r.WithContext(armtls.WithServingKey(r.Context(), peer.Load())))
			default:
				next.ServeHTTP(w, r)
			}
		})
	})
	target, err := VerifyAssignmentTarget(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	peer.Store(target.peer.(*ecdsa.PublicKey))
	frozenKey := target.ServingKey()
	exposed := target.ServingKey()
	exposed[0] ^= 1
	if !bytes.Equal(frozenKey, target.ServingKey()) {
		t.Fatal("caller changed frozen serving identity")
	}
	body, err := target.Prepare(t.Context(), key, assignmentManifest("pod-a"), []byte(assignmentEntries), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Send(t.Context(), body); err == nil {
		t.Fatal("lost acknowledgment reported success")
	}
	if _, err := target.Send(t.Context(), body); !errors.Is(err, ErrAlreadyAssigned) {
		t.Fatalf("replay did not preserve committed conflict: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if posts.Load() != 2 || store.commits != 1 || !bytes.Equal(store.record.Request, body) {
		t.Fatal("ambiguous POST changed or duplicated intent")
	}
}
