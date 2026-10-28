//go:build linux

package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/adaptation"
	"github.com/containerd/nri/pkg/api"
	"github.com/google/nftables"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/internal/podstart"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// These tests run the production configured plugin over NRI RPCs, real kernel
// namespaces and protected RAM state. Containerd metadata, the register and CDS
// issuance are explicit fixtures; actual task execution belongs to the separate
// pod_runtime_integration lane.
func assertPodRecovery(t *testing.T, cfg *config, root string, podKey []byte, digest string) {
	t.Helper()
	for _, scenario := range []string{"completed", "empty-registration-restart", "protected-sandbox-restart", "creation-refusal-restart", "unconsumed-start", "issuer-preserved", "removed-while-disconnected", "stopped-while-disconnected", "missing-issuer", "changed-issuer", "missing-broker-marker", "changed-network", "changed-rules", "changed-selected-image", "changed-launch", "changed-mesh-uid", "missing-state", "malformed-state", "pending-state", "missing-journal", "unknown-container", "changed-sandbox", "changed-process", "changed-assignment", "public-state", "changed-credential-volume", "missing-full-history", "missing-removed-authorization", "live-checkpoint-failure", "live-issuer-change", "credential-worker-failure", "live-protection-loss", "policy-replay-after-recovery", "policy-capability-change", "missing-runtime-sandbox", "missing-policy-document", "unknown-container-state", "changed-measured-order", "duplicate-runtime-entry", "live-credential-permissions", "live-credential-replacement"} {
		t.Run("recovery-"+scenario, func(t *testing.T) {
			local := *cfg
			runPodRecovery(t, &local, root, podKey, digest, scenario)
		})
	}
}

type podRecoveryRuntime struct {
	mu         sync.RWMutex
	pod        *api.PodSandbox
	containers map[string]*api.Container
	duplicate  bool
}

func (r *podRecoveryRuntime) snapshot() ([]*api.PodSandbox, []*api.Container) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.pod == nil {
		return nil, nil
	}
	pods := []*api.PodSandbox{proto.Clone(r.pod).(*api.PodSandbox)}
	containers := make([]*api.Container, 0, len(r.containers))
	for _, c := range r.containers {
		containers = append(containers, proto.Clone(c).(*api.Container))
	}
	slices.SortFunc(containers, func(a, b *api.Container) int { return bytes.Compare([]byte(a.Id), []byte(b.Id)) })
	if r.duplicate && len(containers) != 0 {
		containers = append(containers, proto.Clone(containers[0]).(*api.Container))
	}
	return pods, containers
}

type podRecoveryRunner struct {
	cancel     context.CancelFunc
	done       chan error
	syncResult <-chan error
	nri        *adaptation.Adaptation
	healthPath string
	stopped    bool
}

func (r *podRecoveryRunner) stop(t *testing.T) {
	t.Helper()
	if r.stopped {
		return
	}
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("stop configured recovery runner: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("configured recovery runner did not stop")
	}
	r.nri.Stop()
	// Wait for the old health listener to remove its pathname before a new
	// generation binds it; otherwise its deferred close can unlink the new one.
	until := time.Now().Add(time.Second)
	for {
		if _, err := os.Lstat(r.healthPath); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(until) {
			t.Error("old recovery health listener did not close")
			break
		}
		time.Sleep(time.Millisecond)
	}
	r.stopped = true
}

func runPodRecovery(t *testing.T, cfg *config, root string, podKey []byte, digest, scenario string) {
	t.Helper()
	liveCredentialLoss := scenario == "live-credential-permissions" || scenario == "live-credential-replacement"
	dir, err := os.MkdirTemp("", "pod-recover-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg.WorkloadClaims.SocketDir = filepath.Join(dir, "journal")
	cfg.Policy.BootMarkerPath = filepath.Join(dir, "registered")
	cfg.Containerd.Socket = filepath.Join(dir, "containerd.sock")
	cfg.Plugin.HealthAddr = "unix://" + filepath.Join(dir, "health.sock")
	cfg.Allowlist.Pull.CDSMeasurementsConfig = filepath.Join(root, cfg.Allowlist.Pull.CDSMeasurementsConfig)
	cfg.Allowlist.Pull.Timeout = time.Second
	cfg.Allowlist.Pull.Interval = 20 * time.Millisecond
	pod, credentialSource := preparePodBootstrapRuntime(t, cfg, dir)
	startSocket := filepath.Join(dir, "start.sock")
	originalListen := listenPodStarts
	listenPodStarts = func() (net.Listener, error) { return podstart.Listen(startSocket) }
	t.Cleanup(func() { listenPodStarts = originalListen })

	live := &podRecoveryRuntime{containers: map[string]*api.Container{}}
	var selected sync.Map
	// Synthetic runtime IDs have no containerd cgroup; birth and liveness are real.
	originalIdentity := podProcessIdentity
	podProcessIdentity = func(pid uint32, _ string) (uint64, error) { return readPodProcessBirth(pid) }
	t.Cleanup(func() { podProcessIdentity = originalIdentity })
	originalResolver := newContainerdResolver
	newContainerdResolver = func(socket, namespace string) (containerdConnection, error) {
		if socket != cfg.Containerd.Socket || namespace != cfg.Containerd.Namespace {
			return nil, errors.New("unexpected recovery containerd connection")
		}
		return &fakeContainerd{verify: func(ctx context.Context, id, sandbox, pin string) error {
			actual, exists := selected.Load(id)
			if !exists || actual != pin || sandbox != pod.Id {
				return errors.New("recovery selected-image mismatch")
			}
			return ctx.Err()
		}}, nil
	}
	t.Cleanup(func() { newContainerdResolver = originalResolver })
	reg := &fakeRegister{value: runtimemeasure.Seed(podKey)}
	originalKey, originalRegister, originalRetries := readOperatorKey, openRegister, allowlistApiMaxRetries
	readOperatorKey = func() ([]byte, error) { return podKey, nil }
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return reg, nil }
	allowlistApiMaxRetries = 1
	t.Cleanup(func() {
		readOperatorKey, openRegister, allowlistApiMaxRetries = originalKey, originalRegister, originalRetries
	})
	brokers := make(chan getcert.GuestConfig, 4)
	brokerStopped := make(chan struct{}, 4)
	workerFailure := make(chan error)
	originalCredentials := runGuestCredentials
	runGuestCredentials = func(ctx context.Context, guest getcert.GuestConfig) error {
		select {
		case brokers <- guest:
		case <-ctx.Done():
			return nil
		}
		select {
		case err := <-workerFailure:
			return err
		case <-ctx.Done():
			brokerStopped <- struct{}{}
			return nil
		}
	}
	t.Cleanup(func() { runGuestCredentials = originalCredentials })
	var available atomic.Bool
	available.Store(true)
	served := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "served"}))
	narrowed := []byte(nil)
	if scenario == "policy-capability-change" {
		policy := anyAllowlist(map[string]string{digest: "executed-app"})
		for name, workload := range policy.Workloads {
			workload.Secrets = &allowlist.SecretsPolicy{Policy: allowlist.PolicyAllow, Read: []string{"/runtime/**"}}
			policy.Workloads[name] = workload
		}
		served = canonicalBody(t, policy)
		for name, workload := range policy.Workloads {
			workload.Secrets = &allowlist.SecretsPolicy{Policy: allowlist.PolicyAllow, Read: []string{"/runtime/public/**"}}
			policy.Workloads[name] = workload
		}
		narrowed = canonicalBody(t, policy)
		for _, body := range [][]byte{served, narrowed} {
			if _, err := allowlist.ParseServedJSON(body); err != nil {
				t.Fatalf("invalid policy capability fixture: %v", err)
			}
		}
	}
	var servedMu sync.RWMutex
	servedETag := `W/"1"`
	expectedVersion := uint64(1)
	if scenario == "policy-replay-after-recovery" {
		servedETag, expectedVersion = `W/"2"`, 2
	}
	var servedRequests atomic.Uint64
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		servedMu.RLock()
		defer servedMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", servedETag)
		_, _ = w.Write(served)
		servedRequests.Add(1)
	}))
	defer cds.Close()
	cfg.Allowlist.Pull.URL = cds.URL
	healthClient := unixHealthClient(filepath.Join(dir, "health.sock"))
	defer healthClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	start := func() *podRecoveryRunner {
		registered := make(chan struct{})
		syncResult := make(chan error, 1)
		nri := startPodNRIRuntimeObserved(t, dir, registered, func(err error) {
			// Adaptation also synchronizes before any external plugin registers.
			// Keep the actual refusal, not that earlier successful empty sync.
			if err == nil {
				return
			}
			select {
			case syncResult <- err:
			default:
			}
		}, live.snapshot)
		child, stop := context.WithCancel(ctx)
		r := &podRecoveryRunner{cancel: stop, done: make(chan error, 1), syncResult: syncResult, nri: nri, healthPath: filepath.Join(dir, "health.sock")}
		go func() {
			r.done <- runConfigured(child, cfg, discardLogger(), healthServerConfig{readTimeout: time.Second, writeTimeout: time.Second})
		}()
		t.Cleanup(func() { r.stop(t) })
		return r
	}
	waitReady := func(r *podRecoveryRunner) {
		t.Helper()
		until := time.After(5 * time.Second)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			response, err := healthClient.Get("http://unix/healthz")
			if err == nil {
				var state healthResponse
				decodeErr := json.NewDecoder(response.Body).Decode(&state)
				_ = response.Body.Close()
				if decodeErr == nil && response.StatusCode == http.StatusOK && state.PodRegistered && state.PodUID == cfg.Pod.UID && state.AllowlistVersion == expectedVersion {
					return
				}
			}
			select {
			case err := <-r.done:
				r.stopped = true
				r.cancel()
				r.nri.Stop()
				t.Fatalf("production plugin exited before registration: %v", err)
			case <-until:
				t.Fatal("production plugin did not recover registered policy readiness")
			case <-tick.C:
			}
		}
	}
	broker := func() getcert.GuestConfig {
		t.Helper()
		select {
		case b := <-brokers:
			return b
		case <-ctx.Done():
			t.Fatal("production broker did not start")
			return getcert.GuestConfig{}
		}
	}
	waitRefused := func(r *podRecoveryRunner, want string) {
		t.Helper()
		select {
		case err := <-r.done:
			r.stopped = true
			r.nri.Stop()
			r.cancel()
			if err == nil {
				t.Fatal("untrustworthy history ended startup without a refusal")
			}
			if want != "" && !strings.Contains(err.Error(), want) {
				// Synchronize returns the detailed refusal to the runtime; the
				// plugin itself can observe only the resulting connection close.
				select {
				case syncErr := <-r.syncResult:
					if syncErr == nil || !strings.Contains(syncErr.Error(), want) {
						t.Fatalf("synchronization refusal = %v, want %q (startup: %v)", syncErr, want, err)
					}
					if _, fenceErr := os.Stat(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile)); fenceErr != nil {
						t.Fatalf("failed synchronization lost its durable interruption fence: %v", fenceErr)
					}
				case <-time.After(time.Second):
					t.Fatalf("startup refused without expected synchronization error %q: %v", want, err)
				}
			}
		case <-brokers:
			t.Fatal("untrustworthy history resumed credential issuance")
		case <-time.After(5 * time.Second):
			t.Fatal("untrustworthy recovery did not refuse startup promptly")
		}
		select {
		case <-brokers:
			t.Fatal("refused startup also resumed credential issuance")
		default:
		}
	}
	runner := start()
	waitReady(runner)
	if scenario == "empty-registration-restart" {
		runner.stop(t)
		runner = start()
		waitReady(runner)
	}
	live.mu.Lock()
	live.pod = proto.Clone(pod).(*api.PodSandbox)
	live.mu.Unlock()
	if err := runner.nri.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod}); err != nil {
		t.Fatal(err)
	}
	if scenario == "protected-sandbox-restart" {
		runner.stop(t)
		runner = start()
		waitReady(runner)
	}
	processes := map[string]*exec.Cmd{}
	startContainer := func(ctr *api.Container, consume bool) podstart.Request {
		t.Helper()
		// The synthetic runtime supplies genuine distinct process birth identities;
		// actual containerd-selected task PIDs are covered by the runtime lane.
		process := exec.Command("sleep", "600")
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		processes[ctr.Id] = process
		t.Cleanup(func() {
			if process.ProcessState == nil {
				_ = process.Process.Kill()
				_ = process.Wait()
			}
		})
		ctr.Pid = uint32(process.Process.Pid)
		ctr.State = api.ContainerState_CONTAINER_CREATED
		selected.Store(ctr.Id, extractDigest(ctr.Annotations[annotationImageName]))
		if _, err := runner.nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr}); err != nil {
			t.Fatal(err)
		}
		live.mu.Lock()
		live.containers[ctr.Id] = proto.Clone(ctr).(*api.Container)
		live.mu.Unlock()
		if err := runner.nri.StartContainer(ctx, &api.StartContainerRequest{Pod: pod, Container: ctr}); err != nil {
			t.Fatal(err)
		}
		request := podstart.Request{ContainerID: ctr.Id, SandboxID: pod.Id, PID: ctr.Pid}
		if consume {
			if err := podstart.Consume(ctx, startSocket, request); err != nil {
				t.Fatal(err)
			}
			ctr.State = api.ContainerState_CONTAINER_RUNNING
		}
		live.mu.Lock()
		live.containers[ctr.Id] = proto.Clone(ctr).(*api.Container)
		live.mu.Unlock()
		return request
	}
	var mesh *api.Container
	for _, workload := range cfg.Allowlist.Base.Workloads {
		for _, entry := range workload.Containers {
			if entry.Role != meshRole {
				continue
			}
			mesh = podBootstrapContainer(pod, "recovery-mesh", workloadclaims.MeshContainerName, entry.Digest.String())
			mesh.Args = slices.Concat(entry.Command.Argv, entry.Args.Argv)
			mesh.User = &api.User{Uid: workloadclaims.MeshUID, Gid: workloadclaims.MeshUID}
			mesh.Mounts = append(mesh.Mounts, readOnlyBind(credentialSource, podmesh.CertDir))
		}
	}
	if mesh == nil {
		t.Fatal("prepared policy lacks mesh endpoint")
	}
	if scenario == "creation-refusal-restart" {
		refused := proto.Clone(mesh).(*api.Container)
		refused.Args = []string{"unapproved-mesh-command"}
		if _, err := runner.nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: refused}); err == nil {
			t.Fatal("unapproved creation was accepted")
		}
		runner.stop(t)
		runner = start()
		waitReady(runner)
		retained, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile))
		if err != nil {
			t.Fatal(err)
		}
		var state podRecoveryState
		if err := json.Unmarshal(retained, &state); err != nil {
			t.Fatal(err)
		}
		if state.Denials[pod.Id].Creations[mesh.Name] == "" {
			t.Fatal("restart erased the unresolved named creation refusal")
		}
	}
	startContainer(mesh, true)
	initialBroker := broker()
	removed := podBootstrapContainer(pod, "removed-job", "unknown", digest)
	removed.Args = []string{"/app/workload", "completed-init"}
	startContainer(removed, true)
	if err := processes[removed.Id].Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := processes[removed.Id].Wait(); err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal(err)
		}
	}
	removed.State = api.ContainerState_CONTAINER_STOPPED
	if _, err := runner.nri.StopContainer(ctx, &api.StopContainerRequest{Pod: pod, Container: removed}); err != nil {
		t.Fatal(err)
	}
	if err := runner.nri.RemoveContainer(ctx, &api.RemoveContainerRequest{Pod: pod, Container: removed}); err != nil {
		t.Fatal(err)
	}
	live.mu.Lock()
	delete(live.containers, removed.Id)
	live.mu.Unlock()
	app := podBootstrapContainer(pod, "running-app", "app", digest)
	app.Args = []string{"/app/workload", "live-app"}
	consumed := startContainer(app, !liveCredentialLoss && !slices.Contains([]string{"unconsumed-start", "live-checkpoint-failure", "live-issuer-change", "credential-worker-failure", "live-protection-loss"}, scenario))
	before, err := initialBroker.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeWire, err := before.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Containers) != 3 || len(before.RuntimeExtensions) != 2 {
		t.Fatalf("fixture did not retain two distinct admissions for one image: %+v", before)
	}
	if scenario == "policy-capability-change" {
		// Hold the old issuance snapshot while the next served policy narrows the
		// running image's secret grant. Every container remains admitted by base.
		servedMu.Lock()
		served, servedETag = narrowed, `W/"2"`
		servedMu.Unlock()
		until := time.Now().Add(5 * time.Second)
		for {
			response, err := healthClient.Get("http://unix/healthz")
			if err == nil {
				var state healthResponse
				decode := json.NewDecoder(response.Body).Decode(&state)
				_ = response.Body.Close()
				if decode == nil && state.AllowlistVersion == 2 {
					break
				}
			}
			if time.Now().After(until) {
				t.Fatal("narrowed policy was not applied")
			}
			time.Sleep(10 * time.Millisecond)
		}
		published := false
		if err := initialBroker.Commit(before, func() error { published = true; return nil }); err == nil || published {
			t.Fatal("stale issuance response published after capability narrowing")
		}
		current, err := initialBroker.Snapshot(ctx)
		if err != nil || current.Revision <= before.Revision {
			t.Fatalf("still-admitted Pod lost current issuance or policy revision: %+v %v", current, err)
		}
		if err := initialBroker.Commit(current, func() error { return nil }); err != nil {
			t.Fatalf("current admitted snapshot could not commit: %v", err)
		}
		runner.stop(t)
		return
	}
	// The fake issuer writes only its public binding under the production
	// publication fence. Certificate issuance itself is tested in getcert.
	issuerPath := filepath.Join(credentialSource, "issuer")
	bound := slices.Contains([]string{"issuer-preserved", "missing-issuer", "changed-issuer"}, scenario)
	if scenario == "live-checkpoint-failure" || scenario == "live-issuer-change" {
		replacement := strings.Repeat("z", 64) + "\n"
		if scenario == "live-issuer-change" {
			if err := initialBroker.Commit(before, func() error {
				return os.WriteFile(issuerPath, []byte(strings.Repeat("a", 64)+"\n"), 0644)
			}); err != nil {
				t.Fatal(err)
			}
			replacement = strings.Repeat("b", 64) + "\n"
		}
		if err := os.WriteFile(issuerPath, []byte(replacement), 0644); err != nil {
			t.Fatal(err)
		}
		_, snapshotErr := initialBroker.Snapshot(ctx)
		if snapshotErr == nil {
			t.Fatal("failed checkpoint returned usable attestation claims")
		}
		if scenario == "live-issuer-change" && !strings.Contains(snapshotErr.Error(), "issuer binding changed after publication") {
			t.Fatalf("valid issuer replacement did not violate retained identity: %v", snapshotErr)
		}
		if _, err := os.Stat(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile)); err != nil {
			t.Fatalf("failed checkpoint lost its durable transition fence: %v", err)
		}
		if err := podstart.Consume(ctx, startSocket, consumed); err == nil {
			t.Fatal("failed checkpoint retained an unconsumed execution grant")
		}
		select {
		case <-brokerStopped:
		case <-time.After(time.Second):
			t.Fatal("failed checkpoint retained broker authority")
		}
	} else if err := initialBroker.Commit(before, func() error {
		if bound {
			return os.WriteFile(issuerPath, []byte(strings.Repeat("a", 64)+"\n"), 0644)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	runner.stop(t)
	journalBefore, err := os.ReadFile(journalPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	registerBefore := reg.value
	available.Store(false) // Recovery must retain the last authoritative policy.
	switch scenario {
	case "missing-issuer":
		if err := os.Remove(issuerPath); err != nil {
			t.Fatal(err)
		}
	case "changed-issuer":
		if err := os.WriteFile(issuerPath, []byte(strings.Repeat("b", 64)+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	case "missing-broker-marker":
		if err := os.Remove(filepath.Join(cfg.WorkloadClaims.SocketDir, podBrokerMarker)); err != nil {
			t.Fatal(err)
		}
	case "changed-network":
		other := sandboxProcess(t)
		live.mu.Lock()
		for _, ns := range live.pod.Linux.Namespaces {
			if ns.Type == "network" {
				ns.Path = sandboxNetNSPath(other)
			}
		}
		live.mu.Unlock()
	case "changed-rules":
		changePodRecoveryRules(t, pod.Pid)
	case "changed-selected-image":
		selected.Store(app.Id, extractDigest(mesh.Annotations[annotationImageName]))
	case "changed-launch":
		live.mu.Lock()
		live.containers[app.Id].Args = []string{"/app/workload", "unrecorded"}
		live.mu.Unlock()
	case "changed-mesh-uid":
		live.mu.Lock()
		live.containers[mesh.Id].User.Uid = 0
		live.mu.Unlock()
	case "removed-while-disconnected", "stopped-while-disconnected":
		if err := processes[app.Id].Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := processes[app.Id].Wait(); err != nil {
			var exited *exec.ExitError
			if !errors.As(err, &exited) {
				t.Fatal(err)
			}
		}
		live.mu.Lock()
		if scenario == "removed-while-disconnected" {
			delete(live.containers, app.Id)
		} else {
			live.containers[app.Id].State = api.ContainerState_CONTAINER_STOPPED
		}
		live.mu.Unlock()
	case "changed-assignment":
		assigned := *cfg.Pod
		assigned.UID = "different-signed-assignment"
		cfg.Pod = &assigned
	case "public-state":
		if err := os.Chmod(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile), 0644); err != nil {
			t.Fatal(err)
		}
	case "changed-credential-volume":
		if err := os.Chmod(credentialSource, 0755); err != nil {
			t.Fatal(err)
		}
	case "missing-full-history", "missing-removed-authorization", "missing-policy-document", "changed-measured-order":
		path := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var state podRecoveryState
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		switch scenario {
		case "missing-full-history":
			state.Histories = map[string]json.RawMessage{}
		case "missing-removed-authorization":
			delete(state.Processes, removed.Id)
		case "missing-policy-document":
			state.Policy.Document = nil
		case "changed-measured-order":
			slices.Reverse(state.Digests)
		}
		raw, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	case "missing-state":
		if err := os.Remove(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)); err != nil {
			t.Fatal(err)
		}
	case "malformed-state":
		if err := os.WriteFile(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile), []byte(`{"incomplete":`), 0600); err != nil {
			t.Fatal(err)
		}
	case "pending-state":
		if err := os.WriteFile(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile), []byte("interrupted"), 0600); err != nil {
			t.Fatal(err)
		}
	case "missing-journal":
		if err := os.Remove(journalPath(cfg)); err != nil {
			t.Fatal(err)
		}
	case "unknown-container":
		unexpected := proto.Clone(app).(*api.Container)
		unexpected.Id = "unrecorded-runtime-container"
		live.mu.Lock()
		live.containers[unexpected.Id] = unexpected
		live.mu.Unlock()
	case "changed-process":
		live.mu.Lock()
		live.containers[app.Id].Pid = pod.Pid
		live.mu.Unlock()
	case "changed-sandbox":
		live.mu.Lock()
		live.pod.Uid = "replaced-runtime-pod"
		live.mu.Unlock()
	case "missing-runtime-sandbox":
		live.mu.Lock()
		live.pod = nil
		live.mu.Unlock()
	case "unknown-container-state":
		live.mu.Lock()
		live.containers[app.Id].State = api.ContainerState_CONTAINER_UNKNOWN
		live.mu.Unlock()
	case "duplicate-runtime-entry":
		live.mu.Lock()
		live.duplicate = true
		live.mu.Unlock()
	}
	runner = start()
	if !liveCredentialLoss && !slices.Contains([]string{"completed", "empty-registration-restart", "protected-sandbox-restart", "creation-refusal-restart", "unconsumed-start", "issuer-preserved", "removed-while-disconnected", "stopped-while-disconnected", "credential-worker-failure", "live-protection-loss", "policy-replay-after-recovery"}, scenario) {
		want := ""
		switch scenario {
		case "live-checkpoint-failure", "live-issuer-change":
			want = "interrupted transition"
		case "missing-runtime-sandbox":
			want = "requires the original sandbox"
		case "missing-policy-document":
			want = "policy checkpoint lost its document"
		case "unknown-container-state":
			want = "container state is unknown"
		case "changed-measured-order":
			want = "journal differs from retained history"
		case "duplicate-runtime-entry":
			want = "runtime repeated a container"
		}
		waitRefused(runner, want)
		if err := podstart.Consume(ctx, startSocket, consumed); err == nil {
			t.Fatal("failed recovery restored an old start permission")
		}
		return
	}
	waitReady(runner)
	recoveredBroker := broker()
	after, err := recoveredBroker.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision < before.Revision || recoveredBroker.InstanceID != initialBroker.InstanceID {
		t.Fatal("recovery rewound admission revision or changed credential identity")
	}
	normalized := after
	normalized.Revision = before.Revision
	afterWire, err := normalized.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeWire, afterWire) {
		t.Fatal("recovery lost removed admission observations or changed assignment/boot identity")
	}
	if err := podstart.Consume(ctx, startSocket, consumed); err == nil {
		t.Fatal("completed restart restored a consumed start permission")
	}
	if err := recoveredBroker.Commit(after, func() error { return nil }); err != nil {
		t.Fatalf("restored complete snapshot could not commit: %v", err)
	}
	journalAfter, err := os.ReadFile(journalPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(journalBefore, journalAfter) || registerBefore != reg.value {
		t.Fatal("restart remeasured or rewrote executed workload history")
	}
	if scenario == "credential-worker-failure" || scenario == "live-protection-loss" || liveCredentialLoss {
		// A fresh admission after recovery leaves an unconsumed grant.
		if err := runner.nri.StartContainer(ctx, &api.StartContainerRequest{Pod: pod, Container: app}); err != nil {
			t.Fatal(err)
		}
		reason := errors.New("recovered credential worker lost issuer authority")
		if scenario == "credential-worker-failure" {
			// Inject outside every admission/publication transaction.
			select {
			case workerFailure <- reason:
			case <-ctx.Done():
				t.Fatal("recovered credential worker did not accept its failure")
			}
		} else {
			// The first broker already joined during restart; its stop receipt
			// must not satisfy the recovered worker's cancellation check.
			select {
			case <-brokerStopped:
			default:
				t.Fatal("original credential worker did not report shutdown")
			}
			var stillChanged func()
			if liveCredentialLoss {
				stillChanged = changePodRecoveryCredentials(t, credentialSource, scenario == "live-credential-replacement")
			} else {
				stillChanged = changePodRecoveryRules(t, pod.Pid)
			}
			_, reason = recoveredBroker.Snapshot(ctx)
			if reason == nil {
				t.Fatal("live custody loss retained snapshot authority")
			}
			if liveCredentialLoss {
				want := "credential root lost its protected ownership"
				if scenario == "live-credential-replacement" {
					want = "retained Pod credential volume was replaced"
				}
				if !strings.Contains(reason.Error(), want) {
					t.Fatalf("credential custody loss refused for an unrelated reason: %v", reason)
				}
			}
			stillChanged()
			select {
			case <-brokerStopped:
			case <-time.After(time.Second):
				t.Fatal("lost custody retained the credential worker")
			}
		}
		pendingPath := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile)
		if liveCredentialLoss {
			// Custody loss also prevents committing a complete checkpoint. The
			// durable interruption fence must survive every later refusal.
			if _, err := os.Stat(pendingPath); err != nil {
				t.Fatalf("credential custody loss did not retain its fence: %v", err)
			}
		} else {
			checkpointPath := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)
			until := time.Now().Add(5 * time.Second)
			for {
				raw, err := os.ReadFile(checkpointPath)
				if err != nil {
					t.Fatal(err)
				}
				var retained podRecoveryState
				if err := json.Unmarshal(raw, &retained); err != nil {
					t.Fatal(err)
				}
				if retained.Terminal == reason.Error() {
					_, fenceErr := os.Stat(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile))
					if errors.Is(fenceErr, os.ErrNotExist) {
						break
					}
					if fenceErr != nil {
						t.Fatal(fenceErr)
					}
				}
				if time.Now().After(until) {
					t.Fatal("authority failure did not durably end the recovered identity")
				}
				time.Sleep(time.Millisecond)
			}
			// For the asynchronous worker error, this first Snapshot must not be
			// what establishes the terminal checkpoint.
			if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("authority failure left an incomplete terminal checkpoint: %v", err)
			}
		}
		if _, err := recoveredBroker.Snapshot(ctx); err == nil || (!liveCredentialLoss && err.Error() != reason.Error()) {
			t.Fatalf("ended identity retained snapshot authority: %v", err)
		}
		published := false
		if err := recoveredBroker.Commit(after, func() error { published = true; return nil }); err == nil || published {
			t.Fatal("ended identity retained credential publication authority")
		}
		if err := podstart.Consume(ctx, startSocket, consumed); err == nil {
			t.Fatal("ended identity retained a fresh unconsumed grant")
		}
		want := "pod identity previously ended"
		if liveCredentialLoss {
			if _, err := os.Stat(pendingPath); err != nil {
				t.Fatalf("credential refusal cleared its interruption fence: %v", err)
			}
			want = "interrupted transition"
		}
		runner.stop(t)
		runner = start()
		waitRefused(runner, want)
		return
	}
	if scenario == "policy-replay-after-recovery" {
		retainedPolicy, err := allowlist.ParseServedJSON(served)
		if err != nil {
			t.Fatal(err)
		}
		retainedBody := canonicalBody(t, retainedPolicy)
		changedBody := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "replacement"}))
		changedPolicy, err := allowlist.ParseServedJSON(changedBody)
		if err != nil {
			t.Fatal(err)
		}
		changedEffectiveBody := canonicalBody(t, changedPolicy)
		for _, etag := range []string{`W/"1"`, `W/"2"`} {
			servedMu.Lock()
			served, servedETag = changedBody, etag
			requestsBefore := servedRequests.Load()
			servedMu.Unlock()
			available.Store(true)
			until := time.Now().Add(5 * time.Second)
			// Pulls are serialized. The following request proves the previous
			// response reached policy application, rather than merely delivery.
			for servedRequests.Load() < requestsBefore+2 {
				if time.Now().After(until) {
					t.Fatalf("recovered policy did not process replay %s", etag)
				}
				time.Sleep(time.Millisecond)
			}
			current, err := recoveredBroker.Snapshot(ctx)
			if err != nil || current.Revision != after.Revision {
				t.Fatalf("refused replay changed issuance revision: %+v %v", current, err)
			}
			raw, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile))
			if err != nil {
				t.Fatal(err)
			}
			var retained podRecoveryState
			if err := json.Unmarshal(raw, &retained); err != nil {
				t.Fatal(err)
			}
			if retained.Policy.Version != 2 || !bytes.Equal(retained.Policy.Document, retainedBody) {
				t.Fatalf("replay %s replaced the retained policy", etag)
			}
			if err := recoveredBroker.Commit(after, func() error { return nil }); err != nil {
				t.Fatalf("refused replay invalidated current issuance: %v", err)
			}
		}
		servedMu.Lock()
		servedETag = `W/"3"`
		servedMu.Unlock()
		expectedVersion = 3
		waitReady(runner)
		current, err := recoveredBroker.Snapshot(ctx)
		if err != nil || current.Revision <= after.Revision {
			t.Fatalf("newer policy did not advance recovered issuance: %+v %v", current, err)
		}
		published := false
		if err := recoveredBroker.Commit(after, func() error { published = true; return nil }); err == nil || published {
			t.Fatal("newer policy retained stale issuance authority")
		}
		if err := recoveredBroker.Commit(current, func() error { return nil }); err != nil {
			t.Fatalf("newer policy could not authorize current issuance: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile))
		if err != nil {
			t.Fatal(err)
		}
		var retained podRecoveryState
		if err := json.Unmarshal(raw, &retained); err != nil {
			t.Fatal(err)
		}
		if retained.Policy.Version != 3 || !bytes.Equal(retained.Policy.Document, changedEffectiveBody) {
			t.Fatal("accepted next version did not persist its effective policy")
		}
	}
	if scenario == "unconsumed-start" {
		if err := runner.nri.StartContainer(ctx, &api.StartContainerRequest{Pod: pod, Container: app}); err != nil {
			t.Fatal(err)
		}
		if err := podstart.Consume(ctx, startSocket, consumed); err != nil {
			t.Fatalf("fresh final admission could not authorize the same created task: %v", err)
		}
		if err := podstart.Consume(ctx, startSocket, consumed); err == nil {
			t.Fatal("fresh final admission was consumed twice")
		}
	}
	runner.stop(t)
	if _, err := initialBroker.Snapshot(ctx); err == nil {
		t.Fatal("stopped broker retained issuance authority")
	}
}

// Modify only this fixture's private sandbox. The returned check proves that a
// failed identity assertion did not repair protection and claim continuity.
func changePodRecoveryRules(t *testing.T, pid uint32) func() {
	t.Helper()
	namespace, err := os.Open(sandboxNetNSPath(pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = namespace.Close() })
	connection, err := nftables.New(nftables.WithNetNSFd(int(namespace.Fd())))
	if err != nil {
		t.Fatal(err)
	}
	connection.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "recovery_tamper"})
	if err := connection.Flush(); err != nil {
		t.Fatalf("change owned sandbox rules: %v", err)
	}
	return func() {
		t.Helper()
		tables, err := connection.ListTables()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(tables, func(table *nftables.Table) bool { return table.Name == "recovery_tamper" }) {
			t.Fatal("identity assertion repaired packet protection after custody loss")
		}
	}
}

// Both faults affect only the fixture's owned credential tmpfs. A substituted
// volume has valid custody permissions so inode identity, not chmod, rejects it.
func changePodRecoveryCredentials(t *testing.T, source string, replace bool) func() {
	t.Helper()
	original, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0755)
	if replace {
		mountPodTestRAM(t, source)
		if err := os.Chown(source, 0, int(workloadclaims.MeshUID)); err != nil {
			t.Fatal(err)
		}
		mode = 0750
	}
	if err := os.Chmod(source, mode); err != nil {
		t.Fatal(err)
	}
	changed, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if replace && os.SameFile(original, changed) {
		t.Fatal("credential substitution did not change directory identity")
	}
	return func() {
		t.Helper()
		current, err := os.Stat(source)
		if err != nil || current.Mode().Perm() != mode || !os.SameFile(changed, current) {
			t.Fatalf("credential verification repaired or replaced lost custody: %v", err)
		}
	}
}
