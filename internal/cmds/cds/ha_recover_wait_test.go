package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// fakeRestoreReplica is the pre-join replica on node n2 as recover sees it:
// status, the restore route, and the decree record, which answers only once
// the full server serves.
type fakeRestoreReplica struct {
	mu     sync.Mutex
	joined bool
	record []cdsha.DecreeRecord // nil: the record does not answer yet (503)
	onPost func(w http.ResponseWriter, r *http.Request)
	posts  int
	intent string
}

func (f *fakeRestoreReplica) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	switch r.URL.Path {
	case "/ha/status":
		st := cdsha.Status{ClusterID: "c1", NodeName: "n2", ID: "n2/1-a", Joined: f.joined}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(st)
		return
	case "/ha/decrees":
		rec := f.record
		f.mu.Unlock()
		if rec == nil {
			http.Error(w, "cds-ha: this replica has not joined the cluster yet", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
		return
	case "/ha/restore":
		f.posts++
		on := f.onPost
		f.mu.Unlock()
		on(w, r)
		return
	}
	f.mu.Unlock()
	http.NotFound(w, r)
}

// restoreDone is the replica after the Restore applied: joined at once, the
// full server (and its decree record) a little later.
func (f *fakeRestoreReplica) restoreDone(after time.Duration) {
	time.AfterFunc(after, func() {
		f.mu.Lock()
		f.joined = true
		f.mu.Unlock()
	})
	time.AfterFunc(after+2*time.Second, func() {
		f.mu.Lock()
		f.record = []cdsha.DecreeRecord{{Decree: cdsha.SignedDecree{Decree: cdsha.Decree{Kind: cdsha.Restore, IntentID: f.intent}}}}
		f.mu.Unlock()
	})
}

// dropConnection ends the request without an answer, as the server's write
// deadline or the client's timeout does to a restore that runs long.
func dropConnection(t *testing.T, w http.ResponseWriter) {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	_ = conn.Close()
}

func runDeliver(t *testing.T, f *fakeRestoreReplica, attempts int) (string, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	conn := cdsconn.Options{URL: srv.URL, Insecure: true, Timeout: 2 * time.Second}
	err := deliverRestore(context.Background(), conn, &out, &out, restoreTarget{clusterID: "c1", node: "n2", intent: f.intent, attempts: attempts},
		func(member string) ([]byte, error) {
			return []byte(`{"decree":{"decree":{"target_member":"` + member + `"}}}`), nil
		})
	return out.String(), err
}

// A restore that outlasts its request still succeeded: recover waits for the
// decree record of the restored replica, which answers only once its full
// server serves, rather than reporting a refusal.
func TestRecoverWaitsForASlowRestore(t *testing.T) {
	f := &fakeRestoreReplica{intent: "restore-slow"}
	f.onPost = func(w http.ResponseWriter, _ *http.Request) {
		f.restoreDone(time.Second)
		dropConnection(t, w)
	}
	out, err := runDeliver(t, f, 3)
	if err != nil || !strings.Contains(out, "restored on n2") {
		t.Fatalf("a slow restore that applied was reported as: %v\n%s", err, out)
	}
}

// A second request meets the restore the first started (429): recover waits
// for its outcome.
func TestRecoverWaitsForARestoreInProgress(t *testing.T) {
	f := &fakeRestoreReplica{intent: "restore-busy"}
	f.onPost = func(w http.ResponseWriter, _ *http.Request) {
		f.restoreDone(time.Second)
		http.Error(w, "restore already in progress", http.StatusTooManyRequests)
	}
	out, err := runDeliver(t, f, 3)
	if err != nil || !strings.Contains(out, "restored on n2") {
		t.Fatalf("a restore in progress was reported as: %v\n%s", err, out)
	}
}

// Waiting never turns a refusal into success: a serving cluster whose record
// lacks the decree, and a replica that refuses and stays fresh, both fail.
func TestRecoverReportsARefusal(t *testing.T) {
	serving := &fakeRestoreReplica{intent: "restore-x", joined: true, record: []cdsha.DecreeRecord{}}
	serving.onPost = func(http.ResponseWriter, *http.Request) { t.Error("posted a restore to a serving replica") }
	if out, err := runDeliver(t, serving, 3); err == nil || !strings.Contains(err.Error(), "serving") {
		t.Fatalf("restore over a serving cluster: %v\n%s", err, out)
	}
	refused := &fakeRestoreReplica{intent: "restore-y"}
	refused.onPost = func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cds-ha: restore preflight: snapshot is of cluster", http.StatusConflict)
	}
	if out, err := runDeliver(t, refused, 3); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("refused restore: %v\n%s", err, out)
	}
	if refused.posts != 1 {
		t.Fatalf("a refused restore was sent %d times", refused.posts)
	}
}
