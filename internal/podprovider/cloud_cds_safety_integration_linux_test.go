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
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	storeallowlist "github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

func TestCloudAcceptanceCDSServedOnlyWorkload(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "cds-outage"
	r.cfg.MeshImage = "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:" + strings.Repeat("b", 64)
	pod, wire, err := r.cdsWorkload(endpoint{Name: "cds", Host: "203.0.113.5", Port: 8443})
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
	if _, _, err = r.cdsWorkload(endpoint{Name: "cds", Host: "127.0.0.1", Port: 8443}); err == nil {
		t.Fatal("guest probe accepted a non-owned local target")
	}
}

func TestCloudAcceptanceCDSImmutablePolicyDefaults(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	mesh := `{"containers":[{"digest":"sha256:` + strings.Repeat("b", 64) + `","image":"mesh","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"deny"}}]}`
	signed := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"pod-mesh-membership":` + mesh + `}}`)
	policy, err := pkgallowlist.ParseJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := policy.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var rawSigned, rawExpected any
	if json.Unmarshal(signed, &rawSigned) != nil || json.Unmarshal(expected, &rawExpected) != nil || reflect.DeepEqual(rawSigned, rawExpected) {
		t.Fatal("regression does not reproduce the old raw-default mismatch")
	}
	if err = r.cdsImmutablePolicy(expected, signed); err != nil {
		t.Fatalf("omitted env/initContainers defaults changed policy meaning: %v", err)
	}
	for name, actual := range map[string][]byte{
		"changed-rule":  bytes.Replace(signed, []byte(`"policy":"any"`), []byte(`"policy":"deny"`), 1),
		"added-app":     []byte(`{"schema":"c8s.allowlist/v1","workloads":{"pod-mesh-membership":` + mesh + `,"cloud-a":` + mesh + `}}`),
		"unknown-field": bytes.Replace(signed, []byte(`"image":"mesh"`), []byte(`"image":"mesh","unknownAdmission":true`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.cdsImmutablePolicy(expected, actual); err == nil {
				t.Fatal("changed or invalid immutable policy accepted")
			}
			receipt, err := os.ReadFile(filepath.Join(r.dir, "cds-policy-immutable-base-mismatch.json"))
			if err != nil || !bytes.Contains(receipt, []byte(`"sha256"`)) || bytes.Contains(receipt, []byte(`"containers"`)) {
				t.Fatal("immutable policy refusal lost its bounded hash/key diagnostic")
			}
		})
	}
}

// Exercise the production seed-store and export serializer. An authenticated
// CDS starts with measured component rules as well as the signed mesh entry.
func TestCloudAcceptanceCDSSeededBaseline(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	mesh := `{"containers":[{"digest":"sha256:` + strings.Repeat("b", 64) + `","image":"mesh","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	component := `{"containers":[{"digest":"sha256:` + strings.Repeat("c", 64) + `","image":"component","command":{"policy":"exact","argv":["component"]}}]}`
	app := `{"containers":[{"digest":"sha256:` + strings.Repeat("a", 64) + `","image":"app","command":{"policy":"exact","argv":["app"]}}]}`
	launch := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"pod-mesh-membership":` + mesh + `}}`)
	application := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"pod-mesh-membership":` + mesh + `,"cloud-a":` + app + `}}`)
	seed, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"component":` + component + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	authored, err := pkgallowlist.ParseJSON(launch)
	if err != nil {
		t.Fatal(err)
	}
	// The measured CDS configuration can contain component and tenant rules;
	// both seed the production SQLite store before any authenticated update.
	seed.Workloads["pod-mesh-membership"] = authored.Workloads["pod-mesh-membership"]
	if err = seed.Normalize(); err != nil {
		t.Fatal(err)
	}
	wire, _ := seed.Canonical()
	seed, err = pkgallowlist.ParseJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storeallowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	writes := store.Local()
	if _, _, err = writes.SeedWorkloads(seed.Workloads); err != nil {
		t.Fatal(err)
	}
	export := func() []byte {
		t.Helper()
		doc, _, loadErr := store.LoadAll()
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		raw, marshalErr := doc.Canonical()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return raw
	}
	baseline := export()
	oldExpected, _ := authored.Canonical()
	if bytes.Equal(oldExpected, baseline) {
		t.Fatal("regression no longer reproduces the old mesh-only comparison failure")
	}
	before, after, err := cloudCDSServedPolicies(launch, application, baseline)
	if err != nil || !bytes.Equal(before, baseline) {
		t.Fatalf("measured component baseline was not preserved: %v", err)
	}
	added, _ := pkgallowlist.ParseJSON(application)
	// The store commits whole documents; mutate its actual current policy so
	// the comparison below still detects loss or drift of a seeded entry.
	current, version, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	current.Workloads["cloud-a"] = added.Workloads["cloud-a"]
	if err = writes.ReplaceAll(current, storeallowlist.OperatorWrite{Version: version}); err != nil {
		t.Fatal(err)
	}
	if err = r.cdsPolicyRequire("add-after", after, export()); err != nil {
		t.Fatal(err)
	}
	current, version, err = store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := current.Workloads["cloud-a"]; !exists {
		t.Fatal("application entry disappeared before deletion")
	}
	delete(current.Workloads, "cloud-a")
	if err = writes.ReplaceAll(current, storeallowlist.OperatorWrite{Version: version}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err = r.cdsPolicyRequire("delete-after", before, export()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*pkgallowlist.Allowlist){
		"missing-mesh": func(p *pkgallowlist.Allowlist) { delete(p.Workloads, "pod-mesh-membership") },
		"changed-mesh": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["pod-mesh-membership"]
			w.Containers[0].Env.Policy = pkgallowlist.PolicyDeny
			p.Workloads["pod-mesh-membership"] = w
		},
		"app-name": func(p *pkgallowlist.Allowlist) { p.Workloads["cloud-a"] = p.Workloads["component"] },
		"alternate-app-digest": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["component"]
			w.Containers[0].Digest = added.Workloads["cloud-a"].Containers[0].Digest
			p.Workloads["other"] = w
		},
		"alternate-app-image": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["component"]
			w.Containers[0].Image = "app"
			p.Workloads["component"] = w
		},
		"init-app-digest": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["component"]
			w.InitContainers = added.Workloads["cloud-a"].Containers
			p.Workloads["component"] = w
		},
		"init-app-image": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["component"]
			c := w.Containers[0]
			c.Image = "app"
			w.InitContainers = []pkgallowlist.Container{c}
			p.Workloads["component"] = w
		},
		"missing-digest": func(p *pkgallowlist.Allowlist) {
			w := p.Workloads["component"]
			w.Containers[0].Digest = types.Digest{}
			p.Workloads["component"] = w
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := pkgallowlist.ParseJSON(baseline)
			mutate(p)
			raw, _ := p.Canonical()
			if _, _, err := cloudCDSServedPolicies(launch, application, raw); err == nil {
				t.Fatal("unsafe initial baseline accepted")
			}
		})
	}
	if _, _, err = cloudCDSServedPolicies(launch, application, bytes.Replace(baseline, []byte(strings.Repeat("c", 64)), []byte("*"), 1)); err == nil {
		t.Fatal("wildcard digest accepted")
	}
	for _, stage := range []string{"add-before", "add-after", "outage-before", "delete-before", "delete-after"} {
		t.Run(stage+"-drift", func(t *testing.T) {
			want := before
			if stage == "add-after" || stage == "outage-before" || stage == "delete-before" {
				want = after
			}
			p, _ := pkgallowlist.ParseJSON(want)
			w := p.Workloads["component"]
			w.Containers[0].Command.Argv = []string{"changed-component"}
			p.Workloads["component"] = w
			drifted, _ := p.Canonical()
			if err := r.cdsPolicyRequire(stage, want, drifted); err == nil {
				t.Fatal("component drift was accepted after baseline capture")
			}
			receipt, err := os.ReadFile(filepath.Join(r.dir, "cds-policy-"+stage+"-mismatch.json"))
			if err != nil || bytes.Contains(receipt, []byte("changed-component")) || !bytes.Contains(receipt, []byte(cloudHash(drifted))) {
				t.Fatal("policy mismatch diagnostic lost its hash or leaked policy content")
			}
		})
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
	before := &instance{ID: "i-owned", Status: "running", Network: instanceNetwork{Ingress: []ingress{{Name: "cds", Port: 8443}}}, Endpoints: []endpoint{{Name: "cds", Host: "203.0.113.5", Port: 8443}}}
	before.Boot.Count = 1
	closed := *before
	closed.Network.Ingress = nil
	closed.Endpoints = nil
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
	receipt.Image.Family = "c8s-cds"
	receipt.Image.Launch = "c8s-cds/1"
	owned.LaunchKey, owned.LaunchFileSHA256 = "", cloudHash([]byte("measured config"))
	receipt.Image.Digest = r.cfg.CDSDiskDigest
	receipt.Attestation.ReferenceManifest.Digest = r.cfg.CDSManifestDigest
	receipt.Attestation.LaunchBinding.SHA256 = owned.LaunchFileSHA256
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
	if _, err := cloudCDSStatus(projection, rec, cloudCDSActive); err != nil {
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
		if _, err := cloudCDSStatus(changed, rec, cloudCDSActive); err == nil {
			t.Fatal("malformed or foreign attested state accepted")
		}
	}
	if r, _, _ := cloudOwnershipFixture(t); r.cdsProofComplete() {
		t.Fatal("missing CDS evidence produced acceptance")
	}
}

func TestCloudAcceptanceCDSRevocationMeshWithdrawal(t *testing.T) {
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
	projection.Status.InitContainerStatuses[0].Ready = false
	if _, err = cloudCDSStatus(projection, rec, cloudCDSActive); err == nil {
		t.Fatal("mesh unready accepted before signed deletion")
	}
	state, err := cloudCDSStatus(projection, rec, cloudCDSRevocation)
	if err != nil || state.MeshReady || !state.MeshStart.Equal(start.Time) {
		t.Fatalf("post-delete credential withdrawal lost the same running mesh: %v", err)
	}
	if _, err = cloudCDSStatus(projection, rec, cloudCDSPhase("untrusted")); err == nil {
		t.Fatal("unknown phase relaxed mesh validation")
	}
	for name, change := range map[string]func(*podstatus.ContainerStatus){
		"restarted": func(mesh *podstatus.ContainerStatus) { mesh.RestartCount = 1 },
		"stopped": func(mesh *podstatus.ContainerStatus) {
			mesh.State = &podstatus.ContainerState{Terminated: &podstatus.ContainerTerminated{}}
		},
		"waiting": func(mesh *podstatus.ContainerStatus) { mesh.State = &podstatus.ContainerState{Waiting: &struct{}{}} },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(projection)
			var changed podstatus.PodProjection
			_ = json.Unmarshal(raw, &changed)
			change(&changed.Status.InitContainerStatuses[0])
			if _, err := cloudCDSStatus(changed, rec, cloudCDSRevocation); err == nil {
				t.Fatal("post-delete mesh process continuity was relaxed")
			}
		})
	}
	before := cloudCDSState{Ready: true, Running: true, MeshReady: true, MeshStart: start.Time, AppStart: start.Time, Restarts: 1}
	finished := metav1.NewTime(start.Add(time.Second))
	stopped := cloudCDSState{MeshReady: true, MeshStart: start.Time, Restarts: 1, Exit: &podstatus.ContainerTerminated{StartedAt: &start, FinishedAt: &finished, ExitCode: 137}}
	if done, err := cloudCDSRevoked(before, stopped); err != nil || done {
		t.Fatal("termination alone passed before credential withdrawal")
	}
	stopped.MeshReady = false
	if done, err := cloudCDSRevoked(before, stopped); err != nil || !done {
		t.Fatal("actual termination and credential withdrawal were refused")
	}
	stopped.Running, stopped.AppStart = true, before.AppStart
	if done, err := cloudCDSRevoked(before, stopped); err != nil || done {
		t.Fatal("mesh unready alone passed without actual process termination")
	}
	stopped.Running = false
	stopped.MeshStart = stopped.MeshStart.Add(time.Second)
	if _, err := cloudCDSRevoked(before, stopped); err == nil {
		t.Fatal("post-delete mesh start changed")
	}
	// The old failure discarded precisely this authenticated-but-unready sample.
	r, _, _ := cloudOwnershipFixture(t)
	in := &instance{ID: "i-owned"}
	in.Boot.Count = 1
	if _, err := r.cdsRecordObservation(1, cloudCDSActive, rec, in, projection, json.RawMessage(`{"unitTestOnly":true}`)); err == nil {
		t.Fatal("invalid active-phase observation was accepted")
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, "cds-observation-0001.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"phase": "active"`)) || !bytes.Contains(raw, []byte(`"ready": false`)) {
		t.Fatal("semantic failure lost its retained observation")
	}
}

func TestCloudAcceptanceCDSIngressPersistsIntentAndRestoresUncertainClose(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	owned.Image = r.cfg.CDSImage
	receipt.Image.Family = "c8s-cds"
	receipt.Image.Launch = "c8s-cds/1"
	owned.LaunchKey, owned.LaunchFileSHA256 = "", cloudHash([]byte("measured config"))
	receipt.Image.Digest = r.cfg.CDSDiskDigest
	receipt.Attestation.ReferenceManifest.Digest = r.cfg.CDSManifestDigest
	receipt.Attestation.LaunchBinding.SHA256 = owned.LaunchFileSHA256
	owned.Receipt = &receipt
	r.ledger.Owned = map[string]*cloudOwned{"cds": owned}
	before := &instance{ID: receipt.ID, Status: "running", Network: instanceNetwork{Ingress: []ingress{{Name: "cds", Port: 8443}}}, Endpoints: []endpoint{{Name: "cds", Host: "203.0.113.5", Port: 8443}}}
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
			if json.NewDecoder(req.Body).Decode(&rule) != nil || rule != (ingress{Name: "cds", Port: 8443}) {
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
