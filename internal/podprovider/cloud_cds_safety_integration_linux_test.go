//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

func TestCloudAcceptanceCDSServedOnlyWorkload(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "cds-outage"
	r.cfg.MeshImage = "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:" + strings.Repeat("b", 64)
	pod, wire, err := r.cdsWorkload(endpoint{Name: "cds", Host: "203.0.113.5", Port: 30808})
	if err != nil {
		t.Fatal(err)
	}
	if r.cfg.instanceCount() != 2 || pod.Spec.RestartPolicy != corev1.RestartPolicyAlways || len(pod.Spec.Containers) != 1 || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 || len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].EmptyDir == nil || pod.Spec.Volumes[0].EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatal("CDS scenario lost its bounded normally scheduled single-app RAM-only workload")
	}
	app := pod.Spec.Containers[0]
	if app.Image != podfixture.PythonImage || len(app.Args) != 4 || app.Args[3] != "203.0.113.5" || len(app.VolumeMounts) != 1 || app.VolumeMounts[0].MountPath != "/restart" || app.SecurityContext == nil || app.SecurityContext.RunAsNonRoot == nil || !*app.SecurityContext.RunAsNonRoot {
		t.Fatal("CDS probe lost its exact owned target, RAM mount or unprivileged identity")
	}
	raw, _ := json.Marshal(wire)
	policy, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	rule := policy.Workloads["cloud-a"].Containers[0]
	if !slices.Equal(rule.Args.Argv, app.Args) || rule.Args.Policy != pkgallowlist.PolicyExact || !slices.Equal(rule.Command.Argv, app.Command) {
		t.Fatal("served rule does not pin the actual guest probe")
	}
	if err = cloudWriteBytes(filepath.Join(r.dir, "cds-app-policy.json"), raw); err != nil {
		t.Fatal(err)
	}
	basePath := filepath.Join(r.dir, "base.json")
	base := map[string]any{"schema": "c8s.allowlist/v1", "workloads": map[string]any{"pod-mesh-membership": map[string]any{"containers": []any{map[string]any{"image": r.cfg.MeshImage, "digest": "sha256:" + strings.Repeat("b", 64), "command": map[string]any{"policy": "any"}, "args": map[string]any{"policy": "any"}}}}}}
	if err = cloudWrite(basePath, base); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{WorkloadsFile: basePath}
	before, after, err := r.cdsPolicies(cfg)
	if err != nil || bytes.Equal(before, after) {
		t.Fatalf("served-only composition failed: %v", err)
	}
	base["workloads"].(map[string]any)["cloud-a"] = wire["workloads"].(map[string]any)["cloud-a"]
	if err = cloudWrite(basePath, base); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.cdsPolicies(cfg); err == nil {
		t.Fatal("immutable app admission invalidated the retention proof")
	}
	if _, _, err = r.cdsWorkload(endpoint{Name: "cds", Host: "127.0.0.1", Port: 30808}); err == nil {
		t.Fatal("guest probe accepted a non-owned local target")
	}
}

func TestCloudAcceptanceCDSRestartAndRevocationEvidence(t *testing.T) {
	start := time.Unix(1700000000, 0)
	first := cloudCDSState{Ready: true, Running: true, AppStart: start, MeshStart: start.Add(-time.Second)}
	finished := metav1.NewTime(start.Add(120 * time.Second))
	began := metav1.NewTime(start)
	second := cloudCDSState{Ready: true, Running: true, Restarts: 1, AppStart: finished.Add(time.Second), MeshStart: first.MeshStart, Exit: &podstatus.ContainerTerminated{StartedAt: &began, FinishedAt: &finished}}
	if done, err := cloudCDSRestart(first, second, true); err != nil || !done {
		t.Fatalf("valid retained admission refused: %v", err)
	}
	for name, mutate := range map[string]func(*cloudCDSState){
		"extra-restart":   func(s *cloudCDSState) { s.Restarts = 2 },
		"mesh-restart":    func(s *cloudCDSState) { s.MeshStart = s.MeshStart.Add(time.Second) },
		"unchanged-start": func(s *cloudCDSState) { s.AppStart = first.AppStart },
		"failed-probe":    func(s *cloudCDSState) { copy := *s.Exit; copy.ExitCode = 45; s.Exit = &copy },
		"missing-exit":    func(s *cloudCDSState) { s.Exit = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := second
			mutate(&s)
			if _, err := cloudCDSRestart(first, s, true); err == nil {
				t.Fatal("invalid restart was accepted")
			}
		})
	}
	if _, err := cloudCDSRestart(first, second, false); err == nil {
		t.Fatal("restart before the root outage interval was accepted")
	}
	if done, err := cloudCDSRevoked(second, cloudCDSState{Running: true, Restarts: 1, AppStart: second.AppStart, MeshStart: second.MeshStart}); err != nil || done {
		t.Fatal("transient non-readiness was counted as revocation")
	}
	began = metav1.NewTime(second.AppStart)
	finished = metav1.NewTime(second.AppStart.Add(time.Minute))
	stopped := cloudCDSState{Restarts: 2, MeshStart: second.MeshStart, Exit: &podstatus.ContainerTerminated{StartedAt: &began, FinishedAt: &finished, ExitCode: 143}}
	if done, err := cloudCDSRevoked(second, stopped); err != nil || !done {
		t.Fatalf("actual revoked process was not recognized: %v", err)
	}
	stopped.Running = true
	stopped.AppStart = finished.Add(time.Second)
	if _, err := cloudCDSRevoked(second, stopped); err == nil {
		t.Fatal("post-revocation admission was accepted")
	}
}

func TestCloudAcceptanceCDSIngressAndTransportProof(t *testing.T) {
	before := &instance{ID: "i-owned", Status: "running", Network: instanceNetwork{Ingress: []ingress{{Name: "cds", Port: 30808}, {Name: "pod-status", Port: 8443}}}, Endpoints: []endpoint{{Name: "cds", Host: "203.0.113.5", Port: 30808}, {Name: "pod-status", Host: "203.0.113.5", Port: 8443}}}
	before.Boot.Count = 1
	closed := *before
	closed.Network.Ingress = []ingress{{Name: "pod-status", Port: 8443}}
	closed.Endpoints = []endpoint{before.Endpoints[1]}
	if matched, err := cloudCDSIngressState(&closed, before, false); err != nil || !matched {
		t.Fatalf("exact owned closure refused: %v", err)
	}
	for name, mutate := range map[string]func(*instance){
		"reboot":         func(s *instance) { s.Boot.Count++ },
		"foreign":        func(s *instance) { s.ID = "i-foreign" },
		"other-rule":     func(s *instance) { s.Network.Ingress = []ingress{{Name: "pod-status", Port: 8444}} },
		"other-endpoint": func(s *instance) { s.Endpoints = []endpoint{{Name: "pod-status", Host: "203.0.113.6", Port: 8443}} },
		"pending":        func(s *instance) { s.Network.IngressUpdating = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := closed
			mutate(&s)
			if matched, err := cloudCDSIngressState(&s, before, false); err == nil && matched {
				t.Fatal("unproven closure accepted")
			}
		})
	}
	for _, err := range []error{errors.New("certificate rejected"), context.Canceled, &net.OpError{Op: "dial", Err: &net.DNSError{IsTimeout: true}}, &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}} {
		if cloudCDSTransportFailure(err) {
			t.Fatal("unrelated failure counted as transport outage")
		}
	}
	if !cloudCDSTransportFailure(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}) {
		t.Fatal("actual connection refusal rejected")
	}
}

func TestCloudAcceptanceCDSIngressChecksOwnershipBeforeMutation(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	owned.Image = r.cfg.CDSImage
	receipt.Image.Family = "c8s-pod-cds"
	receipt.Image.Launch = "c8s-node/1"
	owned.Receipt = &receipt
	r.ledger.Owned = map[string]*cloudOwned{"cds": owned}
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		foreign := receipt
		foreign.Labels = map[string]string{"foreign": "true"}
		_ = json.NewEncoder(w).Encode(foreign)
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, http: server.Client()}
	if err := r.cdsIngress(t.Context(), &instance{ID: receipt.ID}, false); err == nil || writes.Load() != 0 {
		t.Fatal("foreign CDS allowed network mutation")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "cds-ingress-close-intent.json")); !os.IsNotExist(err) {
		t.Fatal("foreign CDS acquired mutation authority")
	}
}

func TestCloudAcceptanceCDSProjectionRejectsForeignAndMalformedStatus(t *testing.T) {
	pod := fixturePod()
	reader, _ := fixtureReconciler(t, pod)
	rec, _, err := reader.ensureRecord(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	projection := fixtureProjection(rec)
	start := metav1.NewTime(time.Unix(1700000000, 0))
	projection.Status.ContainerStatuses[0].State.Running.StartedAt = &start
	projection.Status.InitContainerStatuses[0].State.Running.StartedAt = &start
	if _, err := cloudCDSStatus(projection, rec); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*podstatus.PodProjection){
		func(p *podstatus.PodProjection) { p.Metadata.UID = "foreign" },
		func(p *podstatus.PodProjection) { p.Metadata.Name = "foreign" },
		func(p *podstatus.PodProjection) { p.Metadata.Namespace = "foreign" },
		func(p *podstatus.PodProjection) { p.Status.InitContainerStatuses[0].RestartCount = 1 },
		func(p *podstatus.PodProjection) { p.Status.ContainerStatuses[0].State.Waiting = &struct{}{} },
	} {
		raw, _ := json.Marshal(projection)
		var changed podstatus.PodProjection
		_ = json.Unmarshal(raw, &changed)
		change(&changed)
		if _, err := cloudCDSStatus(changed, rec); err == nil {
			t.Fatal("malformed or foreign attested state accepted")
		}
	}
	if r, _, _ := cloudOwnershipFixture(t); r.cdsProofComplete() {
		t.Fatal("missing CDS evidence produced acceptance")
	}
}

func TestCloudAcceptanceCDSIngressPersistsIntentAndRestoresUncertainClose(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	owned.Image = r.cfg.CDSImage
	receipt.Image.Family = "c8s-pod-cds"
	receipt.Image.Launch = "c8s-node/1"
	owned.Receipt = &receipt
	r.ledger.Owned = map[string]*cloudOwned{"cds": owned}
	before := &instance{ID: receipt.ID, Status: "running", Network: instanceNetwork{Ingress: []ingress{{Name: "cds", Port: 30808}, {Name: "pod-status", Port: 8443}}}, Endpoints: []endpoint{{Name: "cds", Host: "203.0.113.5", Port: 30808}, {Name: "pod-status", Host: "203.0.113.5", Port: 8443}}}
	before.Boot.Count = 1
	var closed atomic.Bool
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			action := "close"
			if req.Method == http.MethodPost {
				action = "restore"
			}
			if req.Header.Get("Idempotency-Key") != r.ledger.Run+"-cds-"+action {
				t.Error("network mutation lost its frozen idempotency key")
			}
			if _, err := os.Stat(filepath.Join(r.dir, "cds-ingress-"+action+"-intent.json")); err != nil {
				t.Error("network mutation preceded durable intent")
			}
			writes.Add(1)
			if req.Method == http.MethodDelete {
				if req.URL.Path != "/v1/instances/"+receipt.ID+"/ingress/cds" {
					t.Error("wrong deletion target")
				}
				closed.Store(true)
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":"uncertain"}`))
				return
			}
			var rule ingress
			if json.NewDecoder(req.Body).Decode(&rule) != nil || rule != (ingress{Name: "cds", Port: 30808}) {
				t.Error("restoration changed the owned port")
			}
			closed.Store(false)
		}
		raw, _ := json.Marshal(receipt)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		body["status"] = "running"
		body["boot"] = map[string]int{"count": 1}
		body["network"] = before.Network
		body["endpoints"] = before.Endpoints
		if closed.Load() {
			body["network"] = instanceNetwork{Ingress: before.Network.Ingress[1:]}
			body["endpoints"] = before.Endpoints[1:]
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	r.api = &cloudClient{base: server.URL, http: server.Client()}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := r.cdsIngress(ctx, before, false); err == nil {
		t.Fatal("uncertain close was silently accepted")
	}
	if err := r.cdsIngress(ctx, before, true); err != nil {
		t.Fatal(err)
	}
	if closed.Load() || writes.Load() != 2 {
		t.Fatal("uncertain owned close was not restored exactly once")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "cds-ingress-restore.json")); err != nil {
		t.Fatal("restore receipt missing")
	}
	r.cfg.Scenario = "cds-outage"
	if err := r.writeResult(nil); err == nil {
		t.Fatal("cleanup without scenario evidence produced acceptance")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "result.json")); !os.IsNotExist(err) {
		t.Fatal("failed acceptance wrote a result")
	}
}
