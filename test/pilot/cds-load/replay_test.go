package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestReplayRequiresAcknowledgedMutationAndSpentToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		text     string
		age      time.Duration
		accepted bool
	}{
		{"spent token", 409, operatorauth.ErrTokenReused.Error(), 0, true},
		{"generic conflict", 409, "path exists", 0, false},
		{"write accepted twice", 201, "", 0, false},
		{"expired", 409, operatorauth.ErrTokenReused.Error(), 6 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PUT" || r.URL.Path != "/secrets/pilot/test/0" || r.Header.Get("Authorization") != "synthetic" {
					t.Error("recorded request changed")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.text))
			}))
			defer server.Close()
			file := filepath.Join(t.TempDir(), "requests.json")
			journal := requestJournal{Run: "test", CreatedAt: time.Now().Add(-tc.age), Requests: []recordedRequest{{Method: "PUT", Path: "/secrets/pilot/test/0", Authorization: "synthetic", Body: []byte("test"), Expected: 201, Status: 201}}}
			if err := saveJournal(file, journal, true); err != nil {
				t.Fatal(err)
			}
			err := replay([]endpoint{{server.URL, server.Client()}}, file, time.Second)
			if (err == nil) != tc.accepted {
				t.Fatalf("replay error=%v, want accepted=%v", err, tc.accepted)
			}
		})
	}
}
