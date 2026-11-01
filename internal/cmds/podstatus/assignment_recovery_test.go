package podstatus

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

func TestAssignmentRecoveryRefusesUntrustedRecord(t *testing.T) {
	for _, failure := range []string{"version", "request", "serving-key", "launch-binding", "payload", "renderer"} {
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
			case "payload":
				request.MeshPeers = []byte("null")
				var err error
				request, err = podassign.Sign(key, peer, request)
				if err != nil {
					t.Fatal(err)
				}
				store.record.Request = encodeAssignment(t, request)
			case "renderer":
				s.render = func(*launchconfig.Document) (nodeservices.PodRuntime, error) {
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

func TestAssignmentFileRecoveryRefusesCorruptionWithoutReplacingRecord(t *testing.T) {
	for _, failure := range []string{"unknown-field", "trailing-data", "truncated", "oversized", "symlink"} {
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
			case "unknown-field":
				data = append([]byte(`{"extra":true,`), data[1:]...)
			case "trailing-data":
				data = append(data, []byte(" {}")...)
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

func TestAssignmentWorkerRetriesCommittedIntentUntilSuccessOrShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "shutdown"}[shutdown], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, key, peer, store := assignmentFixture(t)
				body := encodeAssignment(t, issuedAssignment(t, s, key, peer, "pod-a"))
				if response := postAssignment(s, peer, body); response.Code != http.StatusOK {
					t.Fatal(response.Code)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				attempts := 0
				s.apply = func(_ context.Context, runtime nodeservices.PodRuntime) error {
					attempts++
					if runtime.UID != "pod-a" || store.commits != 1 || !bytes.Equal(store.record.Request, body) {
						t.Error("retry lost committed identity")
					}
					if attempts == 1 {
						if shutdown {
							cancel()
						}
						return errors.New("runtime restart interrupted")
					}
					cancel()
					return nil
				}
				s.run(ctx)
				want := 2
				if shutdown {
					want = 1
				}
				if attempts != want {
					t.Fatalf("apply attempts=%d, want %d", attempts, want)
				}
				if response := postAssignment(s, peer, body); response.Code != http.StatusConflict {
					t.Fatal("worker failure reopened assignment")
				}
			})
		})
	}
}

func TestAssignmentAvailabilityRejectsJournalAndKubeletUncertainty(t *testing.T) {
	for _, failure := range []string{"journal-unreadable", "measured", "kubelet-unavailable", "malformed", "wrong-kind", "existing-pod"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal")
			body := []byte(`{"kind":"PodList","items":[]}`)
			var podErr error
			switch failure {
			case "journal-unreadable":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "measured":
				if err := os.WriteFile(path, []byte("sha256:"+strings.Repeat("a", 64)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "kubelet-unavailable":
				podErr = errors.New("kubelet unavailable")
			case "malformed":
				body = []byte("{")
			case "wrong-kind":
				body = []byte(`{"kind":"Status"}`)
			case "existing-pod":
				body = []byte(`{"kind":"PodList","items":[{"metadata":{"uid":"old"}}]}`)
			}
			called := false
			runtime := guestAssignmentRuntime{journal: path, pods: func(context.Context) ([]byte, error) { called = true; return body, podErr }}
			err := runtime.available(t.Context())
			if err == nil {
				t.Fatal("uncertain guest accepted assignment")
			}
			if errors.Is(err, errAssignmentRuntimeUnavailable) != (failure == "kubelet-unavailable") {
				t.Fatalf("incorrect runtime availability classification: %v", err)
			}
			if podErr != nil && !errors.Is(err, podErr) {
				t.Fatal("kubelet availability lost its underlying cause")
			}
			if (failure == "journal-unreadable" || failure == "measured") && called {
				t.Fatal("journal refusal still consulted kubelet")
			}
		})
	}
}

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
