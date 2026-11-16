package podstatus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
)

// Any failure re-verifying the record stops the service, one row per
// check; the record itself is never touched.
func TestAssignmentRecoveryRefusesUntrustedRecord(t *testing.T) {
	for _, failure := range []string{"version", "request", "serving-key", "launch-binding", "signature", "payload", "renderer"} {
		t.Run(failure, func(t *testing.T) {
			s, key, peer, store := assignmentFixture(t)
			request := issuedAssignment(t, s, key, peer, "pod-a")
			if response := postAssignment(s, peer, encodeAssignment(t, request)); response.Code != http.StatusOK {
				t.Fatal(response.Code)
			}
			switch failure {
			case "version":
				store.record.Version++
			case "request":
				store.record.Request = []byte("{}")
			case "serving-key":
				store.record.ServingKey = []byte("invalid SPKI")
			case "launch-binding":
				s.boundKey = func(context.Context) (*ecdsa.PublicKey, error) { return nil, errors.New("binding unavailable") }
			case "signature":
				// The recorded request no longer verifies against another serving key.
				store.record.ServingKey, _ = x509.MarshalPKIXPublicKey(&ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey)
			case "payload":
				request.MeshPeers = []byte("null")
				var err error
				request, err = podassign.Sign(key, peer, request)
				if err != nil {
					t.Fatal(err)
				}
				store.record.Request = encodeAssignment(t, request)
			case "renderer":
				s.render = func(*podlaunch.AssignedPod) (nodeservices.PodRuntime, error) {
					return nodeservices.PodRuntime{}, errors.New("baked floor conflict")
				}
			}
			before := bytes.Clone(store.record.Request)
			recovered, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply)
			if err == nil || recovered != nil {
				t.Fatal("invalid durable record reopened assignment authority")
			}
			if store.commits != 1 || !bytes.Equal(before, store.record.Request) {
				t.Fatal("failed recovery changed the accepted record")
			}
		})
	}
}

// A record is never replaced, even one the service cannot read.
func TestAssignmentFileRecoveryRefusesCorruptionWithoutReplacingRecord(t *testing.T) {
	for _, failure := range []string{"truncated", "oversized", "symlink"} {
		t.Run(failure, func(t *testing.T) {
			s, key, peer, memory := assignmentFixture(t)
			if response := postAssignment(s, peer, encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))); response.Code != http.StatusOK {
				t.Fatal(response.Code)
			}
			root := assignmentTestRoot(t)
			store, err := lockAssignmentStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.lock.Close()
			data, err := json.Marshal(memory.record)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "truncated":
				data = data[:len(data)/2]
			case "oversized":
				data = bytes.Repeat([]byte(" "), podassign.MaxBody+16385)
			}
			if err := fileutil.WriteAtomicRoot(root, assignmentRecordName, data, 0600); err != nil {
				t.Fatal(err)
			}
			if failure == "symlink" {
				if err := root.Rename(assignmentRecordName, "saved.json"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("saved.json", assignmentRecordName); err != nil {
					t.Fatal(err)
				}
			}
			restored, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, s.apply)
			if err == nil || restored != nil {
				t.Fatal("corrupt durable record accepted")
			}
			if err := store.Commit(memory.record); err == nil {
				t.Fatal("corrupt accepted record was replaced")
			}
			got, err := root.ReadFile(assignmentRecordName)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("recovery changed forensic record: %v", err)
			}
		})
	}
}

// Retry until it succeeds, and a restart with a record completes the
// assignment from the committed record and refuses a second one).
func TestAssignmentWorkerRetriesCommittedIntentAfterRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, key, peer, store := assignmentFixture(t)
		body := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
		if response := postAssignment(s, peer, body); response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		attempts := 0
		apply := func(_ context.Context, runtime nodeservices.PodRuntime) error {
			attempts++
			if runtime.UID != "pod-a" || store.commits != 1 || !bytes.Equal(store.record.Request, body) {
				t.Error("retry lost committed identity")
			}
			if attempts == 1 {
				return errors.New("runtime restart interrupted")
			}
			cancel()
			return nil
		}
		restarted, err := newAssignmentService(t.Context(), s.doc, store, s.boundKey, s.render, s.available, apply)
		if err != nil {
			t.Fatal(err)
		}
		restarted.run(ctx)
		if attempts != 2 {
			t.Fatalf("apply attempts=%d, want 2", attempts)
		}
		if response := postAssignment(restarted, peer, body); response.Code != http.StatusConflict {
			t.Fatal("worker failure reopened assignment")
		}
	})
}

// An abandoned install stops the worker's retries; the accepted assignment
// stands and a second one is still refused.
func TestAssignmentWorkerStopsRetryingAnAbandonedInstall(t *testing.T) {
	s, key, peer, _ := assignmentFixture(t)
	body := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	attempts := 0
	s.apply = func(context.Context, nodeservices.PodRuntime) error {
		attempts++
		go cancel()
		return errors.Join(errAssignmentAbandoned, errors.New("plugin ended the pod identity"))
	}
	if response := postAssignment(s, peer, body); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	s.run(ctx)
	if attempts != 1 {
		t.Fatalf("apply attempts=%d, want 1", attempts)
	}
	if response := postAssignment(s, peer, body); response.Code != http.StatusConflict {
		t.Fatal("abandoned install reopened assignment")
	}
}

// Before an assignment nothing runs, so the register must have measured no
// workload; an unreadable journal refuses the assignment too.
func TestAssignmentAvailabilityRequiresAnEmptyJournal(t *testing.T) {
	for _, state := range []string{"absent", "empty", "unreadable", "measured"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal")
			switch state {
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "measured":
				if err := os.WriteFile(path, []byte("sha256:"+strings.Repeat("a", 64)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := guestAssignmentRuntime{journal: path}.available(t.Context())
			if available := state == "absent" || state == "empty"; (err == nil) != available {
				t.Fatalf("availability with a %s journal: %v", state, err)
			}
		})
	}
}

// The launch key the document binds is exactly one P-256 key.
func TestAssignmentPublicKeyRequiresExactlyOneBoundP256Key(t *testing.T) {
	s, key, _, _ := assignmentFixture(t)
	if got, err := assignmentPublicKey([]byte(s.doc.PodOperatorPublicKey)); err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("valid binding refused: %v", err)
	}
	for _, data := range []string{"", "invalid PEM", s.doc.PodOperatorPublicKey + s.doc.PodOperatorPublicKey} {
		if _, err := assignmentPublicKey([]byte(data)); err == nil {
			t.Fatal("ambiguous launch authority accepted")
		}
	}
}
