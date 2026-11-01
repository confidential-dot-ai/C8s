//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func TestCloudAcceptanceWarmDiagnosticReaderKeepsVerificationAndBudgets(t *testing.T) {
	cfg := fixtureConfig(t)
	req, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	rec := &record{Request: req, Manifest: cfg.manifest}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	for _, outcome := range []string{"failure", "unknown-field", "trailing-json", "valid"} {
		t.Run(outcome, func(t *testing.T) {
			deadline := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(t.Context(), deadline)
			defer cancel()
			calls := 0
			get := func(gotCtx context.Context, got podstatus.AttestConfig) ([]byte, error) {
				calls++
				if got.Node != "192.0.2.1:8443" || got.Timeout != 15*time.Second || got.ExpectDigests != nil {
					t.Fatal("diagnostics changed verification policy")
				}
				if end, ok := gotCtx.Deadline(); !ok || !end.Equal(deadline) {
					t.Fatal("diagnostics extended the caller deadline")
				}
				pub, err := cloudPrivateRead(got.LaunchKeyPubPath, 1<<20)
				if err != nil || string(pub) != rec.Request.Trust.LaunchKey {
					t.Fatal("diagnostics changed the frozen launch key")
				}
				manifest, err := cloudPrivateRead(got.ImageManifestPath, 1<<20)
				if err != nil || !bytes.Equal(manifest, rec.Manifest) {
					t.Fatal("diagnostics changed the frozen image policy")
				}
				switch outcome {
				case "failure":
					return nil, errors.New("503 Service Unavailable: kubelet unavailable")
				case "unknown-field":
					return []byte(`{"metadata":{},"status":{},"untrusted":true}`), nil
				case "trailing-json":
					return []byte(`{"metadata":{},"status":{}} {}`), nil
				default:
					return []byte(`{"metadata":{"uid":"owned"},"status":{"phase":"Running"}}`), nil
				}
			}
			projection, public, private := cloudReadGuest(ctx, rec, "192.0.2.1:8443", get)
			if calls != 1 {
				t.Fatal("diagnostics retried attestation")
			}
			if outcome == "valid" {
				if public != nil || private != nil || projection.Metadata.UID != "owned" {
					t.Fatal("verified projection changed")
				}
			} else {
				want := "guest status projection is invalid"
				if outcome == "failure" {
					want = "guest status attestation unavailable"
				}
				if public == nil || public.Error() != want || private == nil {
					t.Fatal("diagnostics changed the production-facing refusal")
				}
			}
			files, err := os.ReadDir(tmp)
			if err != nil || len(files) != 0 {
				t.Fatal("temporary trust files retained")
			}
		})
	}
}

func TestCloudAcceptanceWarmDiagnosticReaderRejectsRealUnattestedReady(t *testing.T) {
	cfg := fixtureConfig(t)
	req, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	rec := &record{Request: req, Manifest: cfg.manifest}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"uid":"owned"},"status":{"phase":"Running"}}`))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, production := readGuest(ctx, rec, address)
	projection, observed, detail := cloudReadGuest(ctx, rec, address, podstatus.Get)
	if production == nil || observed == nil || observed.Error() != production.Error() || detail == nil || projection.Status.Phase != "" {
		t.Fatal("diagnostic reader accepted an unauthenticated Ready projection")
	}
}

func TestCloudAcceptanceWarmDiagnosticsRetainPrivateBoundedFirstAndLatest(t *testing.T) {
	cfg := fixtureConfig(t)
	r, _, _ := cloudOwnershipFixture(t)
	rec := &record{UID: "owned-pod", Pool: &poolRef{Name: "owned-slot", UID: "owned-slot-uid"}}
	base := time.Date(2026, 10, 29, 17, 31, 0, 0, time.UTC)
	deadline := base.Add(10 * time.Minute)
	rec.VerificationDeadline = &deadline
	r.ledger.Owned = map[string]*cloudOwned{"allocation-key": {Key: "allocation-key", SlotUID: string(rec.Pool.UID), Receipt: &cloudReceipt{ID: "i-owned"}}}
	r.ledger.Pods = map[string]cloudPodIntent{"a": {UID: string(rec.UID), Key: "record-key", Allocation: "allocation-key"}}
	o := &cloudAssignmentObserver{run: r, reader: &Reconciler{cfg: cfg}}
	o.posts.Store(1)
	in := &instance{ID: "i-owned", Status: "running", Endpoints: []endpoint{{Name: "pod-status", Host: "192.0.2.1", Port: 8443}}}
	in.Boot.Count = 1
	in.Network.Ingress = []ingress{{Name: "pod-status", Port: 8443}}
	o.diagnostics.observeCloud(base.Add(-2*time.Second), base.Add(-time.Second), in)
	in.Status, in.Endpoints[0].Host, in.Network.Ingress[0].Name = "mutated", "different", "different"
	secret := "-----BEGIN PRIVATE KEY-----\nprivate-value\n-----END PRIVATE KEY-----"
	failure := errors.New("503 kubelet unavailable " + cfg.token + " Bearer another-secret " + secret + strings.Repeat("x", 4096))
	for i := 0; i < 50; i++ {
		start := base.Add(time.Duration(i) * 21 * time.Second)
		o.observeRead(rec, "192.0.2.1:8443", start, start.Add(time.Second), false, failure)
	}
	if err := o.diagnostics.failure(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(r.dir, "warm-read-*.json"))
	if err != nil || len(files) != 24 {
		t.Fatalf("diagnostic file count = %d, err=%v", len(files), err)
	}
	seen := map[int]bool{}
	for _, path := range files {
		raw, err := cloudPrivateRead(path, 16<<10)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{cfg.token, "another-secret", "PRIVATE KEY", "private-value"} {
			if forbidden != "" && bytes.Contains(raw, []byte(forbidden)) {
				t.Fatal("private diagnostic retained a credential")
			}
		}
		var got cloudWarmReadObservation
		if err = decode(raw, &got); err != nil {
			t.Fatal(err)
		}
		seen[got.Sequence] = true
		if len(got.Detail) > 2048 || !strings.HasPrefix(got.Detail, "503 kubelet unavailable") || got.Accepted || got.Address != "192.0.2.1:8443" || got.InstanceID != "i-owned" || got.Allocation != "allocation-key" || got.PodUID != string(rec.UID) || !got.Deadline.Equal(deadline) {
			t.Fatal("bounded diagnostic lost identity, deadline, or failure")
		}
		if got.BeforeDeadline != got.FinishedAt.Before(deadline) || got.StartedAt.After(got.FinishedAt) {
			t.Fatal("diagnostic lost timing attribution")
		}
		if got.Cloud == nil || got.Cloud.InstanceID != "i-owned" || got.Cloud.Status != "running" || got.Cloud.BootCount != 1 || got.Cloud.Endpoints[0].Host != "192.0.2.1" || got.Cloud.Ingress[0].Name != "pod-status" || !got.Cloud.FinishedAt.Before(got.StartedAt) {
			t.Fatal("Cloud snapshot aliased mutable input or lost independent timing")
		}
	}
	for _, sequence := range []int{1, 2, 3, 30, 50} {
		if !seen[sequence] {
			t.Fatal("first or latest diagnostic was lost")
		}
	}
	for sequence := range seen {
		if sequence > 3 && sequence < 30 {
			t.Fatal("diagnostic ring retained stale middle entries")
		}
	}
}

func TestCloudAcceptanceWarmAssignmentRetryProofFreezesAfterReadiness(t *testing.T) {
	for _, change := range []string{"uid", "allocation", "body", "serving", "after-ready", "second-acceptance"} {
		t.Run(change, func(t *testing.T) {
			r, _, _ := cloudOwnershipFixture(t)
			o := &cloudAssignmentObserver{run: r}
			if err := o.beginPost("pod", "allocation", []byte("signed"), []byte("spki")); err != nil {
				t.Fatal(err)
			}
			if err := o.finishPost("pod", nil); err != nil {
				t.Fatal(err)
			}
			if err := o.beginPost("pod", "allocation", []byte("signed"), []byte("spki")); err != nil {
				t.Fatal(err)
			}
			if err := o.finishPost("", podstatus.ErrAlreadyAssigned); err != nil {
				t.Fatal(err)
			}
			if err := o.beginPost("pod", "allocation", []byte("signed"), []byte("spki")); err != nil {
				t.Fatal(err)
			}
			if err := o.finishPost("", context.DeadlineExceeded); err != nil {
				t.Fatal(err)
			}
			uid, allocation, body, serving := "pod", "allocation", []byte("signed"), []byte("spki")
			switch change {
			case "uid":
				uid = "other"
			case "allocation":
				allocation = "other"
			case "body":
				body = []byte("different")
			case "serving":
				serving = []byte("different")
			case "after-ready":
				if err := o.freezePosts(); err != nil {
					t.Fatal(err)
				}
				if err := o.checkFrozenPosts(3); err != nil {
					t.Fatal(err)
				}
			case "second-acceptance":
				if err := o.beginPost(uid, allocation, body, serving); err != nil {
					t.Fatal(err)
				}
				if err := o.finishPost("pod", nil); err == nil {
					t.Fatal("second acceptance was admitted")
				}
				if err := o.freezePosts(); err == nil {
					t.Fatal("invalid acceptance proof was frozen")
				}
				return
			}
			if err := o.beginPost(uid, allocation, body, serving); err == nil {
				t.Fatal("assignment mutation or post-readiness retry was admitted")
			}
			if err := o.freezePosts(); err == nil {
				t.Fatal("violated proof was accepted")
			}
		})
	}
}
