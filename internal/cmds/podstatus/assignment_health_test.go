package podstatus

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The plugin must report the assigned UID registered; registration before the
// first CDS pull (503) suffices.
func TestAssignmentPluginReportsTheExpectedFloor(t *testing.T) {
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
		{"assigned before CDS pull", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a"}`, http.StatusServiceUnavailable, true},
		{"assigned and ready", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a"}`, http.StatusOK, true},
		{"unregistered", "pod-a", `{"pod_registered":false,"pod_uid":"pod-a"}`, http.StatusOK, false},
		{"wrong assignment", "pod-a", `{"pod_registered":true,"pod_uid":"pod-b"}`, http.StatusOK, false},
		{"no assignment", "pod-a", `{"pod_registered":true}`, http.StatusOK, false},
		{"ended identity", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a","pod_ended":true}`, http.StatusOK, false},
		{"malformed", "pod-a", "{", http.StatusOK, false},
		{"server error", "pod-a", `{"pod_registered":true,"pod_uid":"pod-a"}`, http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response.Store(&reply{status: tc.status, body: tc.body})
			if err := assignmentHealthAt(t.Context(), tc.uid, socket); (err == nil) != tc.ready {
				t.Fatalf("registration verdict: %v, ready=%v", err, tc.ready)
			}
		})
	}
}
