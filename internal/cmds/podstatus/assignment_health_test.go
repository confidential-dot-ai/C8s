package podstatus

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

func TestAssignmentRegistrationPrecedesManifestPublication(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "assignment-health-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "health.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	type reply struct {
		status int
		body   string
	}
	var response atomic.Pointer[reply]
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			t.Errorf("unexpected health request: %s %s", r.Method, r.URL.Path)
		}
		current := response.Load()
		w.WriteHeader(current.status)
		_, _ = w.Write([]byte(current.body))
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	for _, tc := range []struct {
		name, uid, body string
		status          int
		ready           bool
	}{
		{"waiting before CDS pull", "", `{"pod_registered":true,"pod_waiting":true}`, http.StatusServiceUnavailable, true},
		{"assigned before CDS pull", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a","pod_waiting":false}`, http.StatusServiceUnavailable, true},
		{"unregistered", "pod-a", `{"pod_registered":false,"pod_uid":"pod-a","pod_waiting":false}`, http.StatusOK, false},
		{"wrong assignment", "pod-a", `{"pod_registered":true,"pod_uid":"pod-b","pod_waiting":false}`, http.StatusOK, false},
		{"still waiting", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a","pod_waiting":true}`, http.StatusOK, false},
		{"malformed", "pod-a", "{", http.StatusOK, false},
		{"server error", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a","pod_waiting":false}`, http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response.Store(&reply{status: tc.status, body: tc.body})
			if err := assignmentHealthAt(t.Context(), tc.uid, socket); (err == nil) != tc.ready {
				t.Fatalf("registration verdict: %v, ready=%v", err, tc.ready)
			}
			if tc.uid == "" {
				return
			}
			manifests, policy := assignmentTestRoot(t), assignmentTestRoot(t)
			runtime := nodeservices.PodRuntime{UID: "pod-a", Policy: []byte("policy"), Manifest: []byte("manifest")}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			health := func(ctx context.Context, uid string) error {
				err := assignmentHealthAt(ctx, uid, socket)
				if err != nil {
					cancel()
				}
				return err
			}
			noOp := func(context.Context) error { return nil }
			err := installAssignment(ctx, runtime, manifests, policy, noOp, noOp, health)
			if (err == nil) != tc.ready {
				t.Fatalf("install verdict: %v, ready=%v", err, tc.ready)
			}
			data, err := manifests.ReadFile("pod.yaml")
			if tc.ready {
				if err != nil || string(data) != "manifest" {
					t.Fatalf("registered assignment not published: %v", err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unregistered assignment exposed manifest: %v", err)
			}
		})
	}
	_ = server.Close()
	if err := assignmentHealthAt(t.Context(), "pod-a", socket); err == nil {
		t.Fatal("disconnected plugin reported registration")
	}
}
