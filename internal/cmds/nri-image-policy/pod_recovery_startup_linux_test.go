//go:build linux

package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
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
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/internal/podstart"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// podRecoveryCase restarts the configured plugin after a bootstrap that
// started the mesh endpoint, a removed job and an application container.
// mutate changes the retained state or the runtime inventory between the
// stop and the restart; a refused case must then end startup without
// resuming issuance, while an accepted case must restore the issuance
// identity unchanged (GB8, OB5, CC2, CC3).
type podRecoveryCase struct {
	// unconsumed leaves the application's start grant unconsumed before the
	// restart.
	unconsumed bool
	// bindIssuer publishes an issuer binding before the restart (CC2).
	bindIssuer bool
	// version is the served policy version the plugin registers under.
	version uint64
	// afterSandbox runs once the sandbox exists, before the endpoint starts.
	afterSandbox func(f *podRecoveryFixture)
	// live replaces the publication that normally precedes the stop.
	live func(f *podRecoveryFixture)
	// mutate runs after the stop and before the restart.
	mutate func(f *podRecoveryFixture)
	// refused names the expected synchronization refusal; "" with refused
	// true accepts any refusal.
	refused bool
	refusal string
	// recovered continues an accepted restart.
	recovered func(f *podRecoveryFixture)
}

func podRecoveryCases() map[string]podRecoveryCase {
	return map[string]podRecoveryCase{
		"completed":                {},
		"creation-refusal-restart": {afterSandbox: (*podRecoveryFixture).restartAfterCreationRefusal},
		"unconsumed-start": {unconsumed: true, recovered: func(f *podRecoveryFixture) {
			f.must(f.runner.nri.StartContainer(f.ctx, &api.StartContainerRequest{Pod: f.pod, Container: f.app}))
			if err := podstart.Consume(f.ctx, f.startSocket, f.consumed); err != nil {
				f.t.Fatalf("fresh final admission could not authorize the same created task: %v", err)
			}
			if err := podstart.Consume(f.ctx, f.startSocket, f.consumed); err == nil {
				f.t.Fatal("fresh final admission was consumed twice")
			}
		}},
		"removed-while-disconnected": {mutate: func(f *podRecoveryFixture) {
			f.killProcess(f.app.Id)
			f.editLive(func() { delete(f.live.containers, f.app.Id) })
		}},
		"stopped-while-disconnected": {mutate: func(f *podRecoveryFixture) {
			f.killProcess(f.app.Id)
			f.editLive(func() { f.live.containers[f.app.Id].State = api.ContainerState_CONTAINER_STOPPED })
		}},
		"changed-issuer": {bindIssuer: true, refused: true, mutate: func(f *podRecoveryFixture) {
			f.must(os.WriteFile(f.issuerPath, []byte(strings.Repeat("b", 64)+"\n"), 0644))
		}},
		"missing-broker-marker": {refused: true, mutate: func(f *podRecoveryFixture) {
			f.must(os.Remove(filepath.Join(f.cfg.WorkloadClaims.SocketDir, podBrokerMarker)))
		}},
		"changed-network": {refused: true, mutate: func(f *podRecoveryFixture) {
			other := sandboxProcess(f.t)
			f.editLive(func() {
				for _, ns := range f.live.pod.Linux.Namespaces {
					if ns.Type == "network" {
						ns.Path = sandboxNetNSPath(other)
					}
				}
			})
		}},
		"changed-rules": {refused: true, mutate: func(f *podRecoveryFixture) { changePodRecoveryRules(f.t, f.pod.Pid) }},
		"changed-selected-image": {refused: true, mutate: func(f *podRecoveryFixture) {
			f.selected.Store(f.app.Id, extractDigest(f.mesh.Annotations[annotationImageName]))
		}},
		"changed-launch": {refused: true, mutate: func(f *podRecoveryFixture) {
			f.editLive(func() { f.live.containers[f.app.Id].Args = []string{"/app/workload", "unrecorded"} })
		}},
		"missing-state":   {refused: true, mutate: func(f *podRecoveryFixture) { f.must(os.Remove(f.statePath())) }},
		"malformed-state": {refused: true, mutate: func(f *podRecoveryFixture) { f.must(os.WriteFile(f.statePath(), []byte(`{"incomplete":`), 0600)) }},
		"pending-state":   {refused: true, mutate: func(f *podRecoveryFixture) { f.must(os.WriteFile(f.pendingPath(), []byte("interrupted"), 0600)) }},
		"missing-journal": {refused: true, mutate: func(f *podRecoveryFixture) { f.must(os.Remove(journalPath(f.cfg))) }},
		"unknown-container": {refused: true, mutate: func(f *podRecoveryFixture) {
			unexpected := proto.Clone(f.app).(*api.Container)
			unexpected.Id = "unrecorded-runtime-container"
			f.editLive(func() { f.live.containers[unexpected.Id] = unexpected })
		}},
		"changed-sandbox":           {refused: true, mutate: func(f *podRecoveryFixture) { f.editLive(func() { f.live.pod.Uid = "replaced-runtime-pod" }) }},
		"changed-process":           {refused: true, mutate: func(f *podRecoveryFixture) { f.editLive(func() { f.live.containers[f.app.Id].Pid = f.pod.Pid }) }},
		"changed-credential-volume": {refused: true, mutate: func(f *podRecoveryFixture) { f.must(os.Chmod(f.credentialSource, 0755)) }},
		"missing-full-history": {refused: true, mutate: func(f *podRecoveryFixture) {
			f.editState(func(state *podRecoveryState) { state.Histories = map[string]json.RawMessage{} })
		}},
		"missing-removed-authorization": {refused: true, mutate: func(f *podRecoveryFixture) {
			f.editState(func(state *podRecoveryState) { delete(state.Processes, f.removed.Id) })
		}},
		"missing-runtime-sandbox": {refused: true, refusal: "requires the original sandbox", mutate: func(f *podRecoveryFixture) {
			f.editLive(func() { f.live.pod = nil })
		}},
		"unknown-container-state": {refused: true, refusal: "container state is unknown", mutate: func(f *podRecoveryFixture) {
			f.editLive(func() { f.live.containers[f.app.Id].State = api.ContainerState_CONTAINER_UNKNOWN })
		}},
		"duplicate-runtime-entry": {refused: true, refusal: "runtime repeated a container", mutate: func(f *podRecoveryFixture) {
			f.editLive(func() { f.live.duplicate = true })
		}},
		"live-issuer-change":           {unconsumed: true, refused: true, refusal: "interrupted transition", live: (*podRecoveryFixture).changeIssuerAfterPublication},
		"live-protection-loss":         {unconsumed: true, recovered: (*podRecoveryFixture).loseProtectionAfterRecovery},
		"live-credential-replacement":  {unconsumed: true, recovered: (*podRecoveryFixture).loseCredentialCustodyAfterRecovery},
		"policy-replay-after-recovery": {version: 2, recovered: (*podRecoveryFixture).replayPolicyAfterRecovery},
	}
}

// These tests run the production configured plugin over NRI RPCs, real kernel
// namespaces and protected RAM state. Containerd metadata, the register and CDS
// issuance are explicit fixtures; actual task execution belongs to the separate
// pod_runtime_integration lane.
func assertPodRecovery(t *testing.T, cfg *config, root string, podKey []byte, digest string) {
	t.Helper()
	cases := podRecoveryCases()
	for _, name := range slices.Sorted(maps.Keys(cases)) {
		t.Run("recovery-"+name, func(t *testing.T) {
			local := *cfg
			runPodRecovery(t, &local, root, podKey, digest, cases[name])
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
	registered <-chan struct{}
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

type podRecoveryFixture struct {
	t                *testing.T
	ctx              context.Context
	cfg              *config
	dir              string
	startSocket      string
	credentialSource string
	issuerPath       string
	pod              *api.PodSandbox
	live             *podRecoveryRuntime
	selected         sync.Map
	processes        map[string]*exec.Cmd
	reg              *fakeRegister
	brokers          chan getcert.GuestConfig
	brokerStopped    chan struct{}
	available        atomic.Bool
	servedMu         sync.RWMutex
	served           []byte
	servedETag       string
	servedRequests   atomic.Uint64
	expectedVersion  uint64
	cds              *httptest.Server
	healthClient     *http.Client
	runner           *podRecoveryRunner
	mesh, app        *api.Container
	removed          *api.Container
	consumed         podstart.Request
	initialBroker    getcert.GuestConfig
	recoveredBroker  getcert.GuestConfig
	before, after    workloadclaims.PodClaims
}

func newPodRecoveryFixture(t *testing.T, cfg *config, root string, podKey []byte, version uint64) *podRecoveryFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "pod-recover-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &podRecoveryFixture{t: t, cfg: cfg, dir: dir, processes: map[string]*exec.Cmd{}, expectedVersion: version}
	cfg.WorkloadClaims.SocketDir = filepath.Join(dir, "journal")
	cfg.Policy.BootMarkerPath = filepath.Join(dir, "registered")
	cfg.Containerd.Socket = filepath.Join(dir, "containerd.sock")
	cfg.Plugin.HealthAddr = "unix://" + filepath.Join(dir, "health.sock")
	cfg.Allowlist.Pull.CDSMeasurementsConfig = filepath.Join(root, cfg.Allowlist.Pull.CDSMeasurementsConfig)
	cfg.Allowlist.Pull.Timeout = time.Second
	cfg.Allowlist.Pull.Interval = 20 * time.Millisecond
	f.pod, f.credentialSource = preparePodBootstrapRuntime(t, cfg, dir)
	// The fake issuer writes only its public binding under the production
	// publication fence. Certificate issuance itself is tested in getcert.
	f.issuerPath = filepath.Join(f.credentialSource, "issuer")
	f.startSocket = filepath.Join(dir, "start.sock")
	originalListen := listenPodStarts
	listenPodStarts = func() (net.Listener, error) { return podstart.Listen(f.startSocket) }
	t.Cleanup(func() { listenPodStarts = originalListen })

	f.live = &podRecoveryRuntime{containers: map[string]*api.Container{}}
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
			actual, exists := f.selected.Load(id)
			if !exists || actual != pin || sandbox != f.pod.Id {
				return errors.New("recovery selected-image mismatch")
			}
			return ctx.Err()
		}}, nil
	}
	t.Cleanup(func() { newContainerdResolver = originalResolver })
	f.reg = &fakeRegister{value: runtimemeasure.Seed(podKey)}
	originalKey, originalRegister, originalRetries := readOperatorKey, openRegister, allowlistApiMaxRetries
	readOperatorKey = func() ([]byte, error) { return podKey, nil }
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return f.reg, nil }
	allowlistApiMaxRetries = 1
	t.Cleanup(func() {
		readOperatorKey, openRegister, allowlistApiMaxRetries = originalKey, originalRegister, originalRetries
	})
	f.brokers = make(chan getcert.GuestConfig, 4)
	f.brokerStopped = make(chan struct{}, 4)
	originalCredentials := runGuestCredentials
	runGuestCredentials = func(ctx context.Context, guest getcert.GuestConfig) error {
		select {
		case f.brokers <- guest:
		case <-ctx.Done():
			return nil
		}
		<-ctx.Done()
		f.brokerStopped <- struct{}{}
		return nil
	}
	t.Cleanup(func() { runGuestCredentials = originalCredentials })
	f.available.Store(true)
	f.served = canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "served"}))
	f.servedETag = `W/"1"`
	if version == 2 {
		f.servedETag = `W/"2"`
	}
	f.cds = testutil.NewARMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !f.available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.servedMu.RLock()
		defer f.servedMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", f.servedETag)
		_, _ = w.Write(f.served)
		f.servedRequests.Add(1)
	}))
	t.Cleanup(f.cds.Close)
	// Both the fresh worker and recovered worker use the authenticated server
	// whose independent SNP launch file is pinned by the prepared policy.
	cfg.Allowlist.Pull.URL = f.cds.URL
	cfg.cdsAddress, err = cmdsutil.CDSURLAddress(f.cds.URL)
	f.must(err)
	verifier := mockapi.New(t)
	verdict := mockapi.PassingVerdict(testutil.TestMeasurement)
	binding := runtimemeasure.HostData([]byte(testutil.CDSLaunchFile))
	verdict.Claims.InitData = binding[:]
	verifier.SetVerdict(verdict)
	cfg.Allowlist.Pull.AttestationApiURL = verifier.URL()
	f.healthClient = unixHealthClient(filepath.Join(dir, "health.sock"))
	t.Cleanup(f.healthClient.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	f.ctx = ctx
	return f
}

func (f *podRecoveryFixture) start() *podRecoveryRunner {
	t := f.t
	registered := make(chan struct{})
	syncResult := make(chan error, 1)
	nri := startPodNRIRuntimeObserved(t, f.dir, registered, func(err error) {
		if err == nil {
			return
		}
		select {
		case syncResult <- err:
		default:
		}
	}, f.live.snapshot)
	child, stop := context.WithCancel(f.ctx)
	r := &podRecoveryRunner{cancel: stop, done: make(chan error, 1), syncResult: syncResult, registered: registered, nri: nri, healthPath: filepath.Join(f.dir, "health.sock")}
	go func() {
		r.done <- runConfigured(child, f.cfg, discardLogger(), healthServerConfig{readTimeout: time.Second, writeTimeout: time.Second})
	}()
	t.Cleanup(func() { r.stop(t) })
	f.runner = r
	return r
}

func (f *podRecoveryFixture) restart() {
	f.runner.stop(f.t)
	f.start()
}

func (f *podRecoveryFixture) waitReady() {
	t := f.t
	t.Helper()
	r := f.runner
	until := time.After(5 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		response, err := f.healthClient.Get("http://unix/healthz")
		if err == nil {
			var state healthResponse
			decodeErr := json.NewDecoder(response.Body).Decode(&state)
			_ = response.Body.Close()
			if decodeErr == nil && response.StatusCode == http.StatusOK && state.PodRegistered && state.PodUID == f.cfg.Pod.UID && state.AllowlistVersion == f.expectedVersion {
				select {
				case <-r.registered:
					return
				default:
				}
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

func (f *podRecoveryFixture) broker() getcert.GuestConfig {
	f.t.Helper()
	select {
	case b := <-f.brokers:
		if b.CDSURL != f.cds.URL || b.HTTPClient == nil {
			f.t.Fatal("recovered broker lost the authenticated resolved CDS client")
		}
		return b
	case <-f.ctx.Done():
		f.t.Fatal("production broker did not start")
		return getcert.GuestConfig{}
	}
}

func (f *podRecoveryFixture) waitRefused(want string) {
	t := f.t
	t.Helper()
	r := f.runner
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
				if _, fenceErr := os.Stat(filepath.Join(f.cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile)); fenceErr != nil {
					t.Fatalf("failed synchronization lost its durable interruption fence: %v", fenceErr)
				}
			case <-time.After(time.Second):
				t.Fatalf("startup refused without expected synchronization error %q: %v", want, err)
			}
		}
	case <-f.brokers:
		t.Fatal("untrustworthy history resumed credential issuance")
	case <-time.After(5 * time.Second):
		t.Fatal("untrustworthy recovery did not refuse startup promptly")
	}
	select {
	case <-f.brokers:
		t.Fatal("refused startup also resumed credential issuance")
	default:
	}
}

func (f *podRecoveryFixture) startContainer(ctr *api.Container, consume bool) podstart.Request {
	t := f.t
	t.Helper()
	// The synthetic runtime supplies genuine distinct process birth identities;
	// actual containerd-selected task PIDs are covered by the runtime lane.
	process := exec.Command("sleep", "600")
	f.must(process.Start())
	f.processes[ctr.Id] = process
	t.Cleanup(func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	})
	ctr.Pid = uint32(process.Process.Pid)
	ctr.State = api.ContainerState_CONTAINER_CREATED
	f.selected.Store(ctr.Id, extractDigest(ctr.Annotations[annotationImageName]))
	if _, err := f.runner.nri.CreateContainer(f.ctx, &api.CreateContainerRequest{Pod: f.pod, Container: ctr}); err != nil {
		t.Fatal(err)
	}
	f.live.mu.Lock()
	f.live.containers[ctr.Id] = proto.Clone(ctr).(*api.Container)
	f.live.mu.Unlock()
	f.must(f.runner.nri.StartContainer(f.ctx, &api.StartContainerRequest{Pod: f.pod, Container: ctr}))
	request := podstart.Request{ContainerID: ctr.Id, SandboxID: f.pod.Id, PID: ctr.Pid}
	if consume {
		f.must(podstart.Consume(f.ctx, f.startSocket, request))
		ctr.State = api.ContainerState_CONTAINER_RUNNING
	}
	f.live.mu.Lock()
	f.live.containers[ctr.Id] = proto.Clone(ctr).(*api.Container)
	f.live.mu.Unlock()
	return request
}

func (f *podRecoveryFixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *podRecoveryFixture) editLive(edit func()) {
	f.live.mu.Lock()
	defer f.live.mu.Unlock()
	edit()
}

// killProcess leaves a container whose process has exited.
func (f *podRecoveryFixture) killProcess(id string) {
	f.t.Helper()
	f.must(f.processes[id].Process.Kill())
	var exited *exec.ExitError
	if err := f.processes[id].Wait(); err != nil && !errors.As(err, &exited) {
		f.t.Fatal(err)
	}
}

func (f *podRecoveryFixture) statePath() string {
	return filepath.Join(f.cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)
}

func (f *podRecoveryFixture) pendingPath() string {
	return filepath.Join(f.cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryPendingFile)
}

func (f *podRecoveryFixture) readState() podRecoveryState {
	f.t.Helper()
	raw, err := os.ReadFile(f.statePath())
	f.must(err)
	var state podRecoveryState
	f.must(json.Unmarshal(raw, &state))
	return state
}

func (f *podRecoveryFixture) editState(edit func(*podRecoveryState)) {
	f.t.Helper()
	state := f.readState()
	edit(&state)
	raw, err := json.Marshal(state)
	f.must(err)
	f.must(os.WriteFile(f.statePath(), raw, 0600))
}

func runPodRecovery(t *testing.T, cfg *config, root string, podKey []byte, digest string, tc podRecoveryCase) {
	t.Helper()
	if tc.version == 0 {
		tc.version = 1
	}
	f := newPodRecoveryFixture(t, cfg, root, podKey, tc.version)
	ctx := f.ctx
	f.start()
	f.waitReady()
	f.live.mu.Lock()
	f.live.pod = proto.Clone(f.pod).(*api.PodSandbox)
	f.live.mu.Unlock()
	f.must(f.runner.nri.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: f.pod}))
	for _, workload := range cfg.Allowlist.Base.Workloads {
		for _, entry := range workload.Containers {
			if entry.Role != meshRole {
				continue
			}
			f.mesh = podBootstrapContainer(f.pod, "recovery-mesh", workloadclaims.MeshContainerName, entry.Digest.String())
			f.mesh.Args = slices.Concat(entry.Command.Argv, entry.Args.Argv)
			f.mesh.User = &api.User{Uid: workloadclaims.MeshUID, Gid: workloadclaims.MeshUID}
			f.mesh.Mounts = append(f.mesh.Mounts, readOnlyBind(f.credentialSource, podmesh.CertDir))
		}
	}
	if f.mesh == nil {
		t.Fatal("prepared policy lacks mesh endpoint")
	}
	if tc.afterSandbox != nil {
		tc.afterSandbox(f)
	}
	f.startContainer(f.mesh, true)
	f.initialBroker = f.broker()
	f.removed = podBootstrapContainer(f.pod, "removed-job", "unknown", digest)
	f.removed.Args = []string{"/app/workload", "completed-init"}
	f.startContainer(f.removed, true)
	f.killProcess(f.removed.Id)
	f.removed.State = api.ContainerState_CONTAINER_STOPPED
	if _, err := f.runner.nri.StopContainer(ctx, &api.StopContainerRequest{Pod: f.pod, Container: f.removed}); err != nil {
		t.Fatal(err)
	}
	f.must(f.runner.nri.RemoveContainer(ctx, &api.RemoveContainerRequest{Pod: f.pod, Container: f.removed}))
	f.live.mu.Lock()
	delete(f.live.containers, f.removed.Id)
	f.live.mu.Unlock()
	f.app = podBootstrapContainer(f.pod, "running-app", "app", digest)
	f.app.Args = []string{"/app/workload", "live-app"}
	f.consumed = f.startContainer(f.app, !tc.unconsumed)
	before, err := f.initialBroker.Snapshot(ctx)
	f.must(err)
	f.before = before
	beforeWire, err := before.Canonical()
	f.must(err)
	if len(before.Containers) != 3 || len(before.RuntimeExtensions) != 2 {
		t.Fatalf("fixture did not retain two distinct admissions for one image: %+v", before)
	}
	if tc.live != nil {
		tc.live(f)
	} else if err := f.initialBroker.Commit(before, func() error {
		if tc.bindIssuer {
			return os.WriteFile(f.issuerPath, []byte(strings.Repeat("a", 64)+"\n"), 0644)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.runner.stop(t)
	journalBefore, err := os.ReadFile(journalPath(cfg))
	f.must(err)
	registerBefore := f.reg.value
	f.available.Store(false) // Recovery must retain the last authoritative policy.
	if tc.mutate != nil {
		tc.mutate(f)
	}
	f.start()
	if tc.refused {
		f.waitRefused(tc.refusal)
		if err := podstart.Consume(ctx, f.startSocket, f.consumed); err == nil {
			t.Fatal("failed recovery restored an old start permission")
		}
		return
	}
	f.waitReady()
	f.recoveredBroker = f.broker()
	after, err := f.recoveredBroker.Snapshot(ctx)
	f.must(err)
	f.after = after
	if after.Revision < before.Revision || f.recoveredBroker.InstanceID != f.initialBroker.InstanceID {
		t.Fatal("recovery rewound admission revision or changed credential identity")
	}
	normalized := after
	normalized.Revision = before.Revision
	afterWire, err := normalized.Canonical()
	f.must(err)
	if !bytes.Equal(beforeWire, afterWire) {
		t.Fatal("recovery lost removed admission observations or changed assignment/boot identity")
	}
	if err := podstart.Consume(ctx, f.startSocket, f.consumed); err == nil {
		t.Fatal("completed restart restored a consumed start permission")
	}
	if err := f.recoveredBroker.Commit(after, func() error { return nil }); err != nil {
		t.Fatalf("restored complete snapshot could not commit: %v", err)
	}
	journalAfter, err := os.ReadFile(journalPath(cfg))
	f.must(err)
	if !bytes.Equal(journalBefore, journalAfter) || registerBefore != f.reg.value {
		t.Fatal("restart remeasured or rewrote executed workload history")
	}
	if tc.recovered != nil {
		tc.recovered(f)
		if f.runner.stopped {
			return
		}
	}
	f.runner.stop(t)
	if _, err := f.initialBroker.Snapshot(ctx); err == nil {
		t.Fatal("stopped broker retained issuance authority")
	}
}

// A restart before any execution keeps the unresolved named creation refusal
// that the broker must keep refusing snapshots for (OB5).
func (f *podRecoveryFixture) restartAfterCreationRefusal() {
	t := f.t
	t.Helper()
	refused := proto.Clone(f.mesh).(*api.Container)
	refused.Args = []string{"unapproved-mesh-command"}
	if _, err := f.runner.nri.CreateContainer(f.ctx, &api.CreateContainerRequest{Pod: f.pod, Container: refused}); err == nil {
		t.Fatal("unapproved creation was accepted")
	}
	f.restart()
	f.waitReady()
	if f.readState().Denials[f.pod.Id].Creations[f.mesh.Name] == "" {
		t.Fatal("restart erased the unresolved named creation refusal")
	}
}

// A valid issuer that differs from the recorded one fails the checkpoint; the
// failed checkpoint leaves its fence, ends issuance and revokes the unconsumed
// grant (CC2, ML1).
func (f *podRecoveryFixture) changeIssuerAfterPublication() {
	t := f.t
	t.Helper()
	if err := f.initialBroker.Commit(f.before, func() error {
		return os.WriteFile(f.issuerPath, []byte(strings.Repeat("a", 64)+"\n"), 0644)
	}); err != nil {
		t.Fatal(err)
	}
	f.must(os.WriteFile(f.issuerPath, []byte(strings.Repeat("b", 64)+"\n"), 0644))
	_, snapshotErr := f.initialBroker.Snapshot(f.ctx)
	if snapshotErr == nil {
		t.Fatal("failed checkpoint returned usable attestation claims")
	}
	if !strings.Contains(snapshotErr.Error(), "issuer binding changed after publication") {
		t.Fatalf("valid issuer replacement did not violate retained identity: %v", snapshotErr)
	}
	if _, err := os.Stat(f.pendingPath()); err != nil {
		t.Fatalf("failed checkpoint lost its durable transition fence: %v", err)
	}
	if err := podstart.Consume(f.ctx, f.startSocket, f.consumed); err == nil {
		t.Fatal("failed checkpoint retained an unconsumed execution grant")
	}
	select {
	case <-f.brokerStopped:
	case <-time.After(time.Second):
		t.Fatal("failed checkpoint retained broker authority")
	}
}

// A fresh admission after recovery leaves an unconsumed grant; the custody
// loss injected by lose must then end the recovered identity, revoke that
// grant and refuse every later snapshot, publication and restart (IN3, CC1,
// CC3, OB5).
func (f *podRecoveryFixture) loseCustodyAfterRecovery(lose func() (stillChanged func(), fence bool, want string)) {
	t := f.t
	t.Helper()
	f.must(f.runner.nri.StartContainer(f.ctx, &api.StartContainerRequest{Pod: f.pod, Container: f.app}))
	// The first broker already joined during restart; its stop receipt must
	// not satisfy the recovered worker's cancellation check.
	select {
	case <-f.brokerStopped:
	default:
		t.Fatal("original credential worker did not report shutdown")
	}
	stillChanged, fence, want := lose()
	_, reason := f.recoveredBroker.Snapshot(f.ctx)
	if reason == nil {
		t.Fatal("live custody loss retained snapshot authority")
	}
	if want != "" && !strings.Contains(reason.Error(), want) {
		t.Fatalf("credential custody loss refused for an unrelated reason: %v", reason)
	}
	stillChanged()
	select {
	case <-f.brokerStopped:
	case <-time.After(time.Second):
		t.Fatal("lost custody retained the credential worker")
	}
	if fence {
		// Custody loss also prevents committing a complete checkpoint. The
		// durable interruption fence must survive every later refusal.
		if _, err := os.Stat(f.pendingPath()); err != nil {
			t.Fatalf("credential custody loss did not retain its fence: %v", err)
		}
	} else {
		until := time.Now().Add(5 * time.Second)
		for {
			if f.readState().Terminal == reason.Error() {
				_, fenceErr := os.Stat(f.pendingPath())
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
		if _, err := os.Stat(f.pendingPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("authority failure left an incomplete terminal checkpoint: %v", err)
		}
	}
	if _, err := f.recoveredBroker.Snapshot(f.ctx); err == nil || (!fence && err.Error() != reason.Error()) {
		t.Fatalf("ended identity retained snapshot authority: %v", err)
	}
	published := false
	if err := f.recoveredBroker.Commit(f.after, func() error { published = true; return nil }); err == nil || published {
		t.Fatal("ended identity retained credential publication authority")
	}
	if err := podstart.Consume(f.ctx, f.startSocket, f.consumed); err == nil {
		t.Fatal("ended identity retained a fresh unconsumed grant")
	}
	refusal := "pod identity previously ended"
	if fence {
		if _, err := os.Stat(f.pendingPath()); err != nil {
			t.Fatalf("credential refusal cleared its interruption fence: %v", err)
		}
		refusal = "interrupted transition"
	}
	f.restart()
	f.waitRefused(refusal)
}

func (f *podRecoveryFixture) loseProtectionAfterRecovery() {
	f.loseCustodyAfterRecovery(func() (func(), bool, string) {
		return changePodRecoveryRules(f.t, f.pod.Pid), false, ""
	})
}

func (f *podRecoveryFixture) loseCredentialCustodyAfterRecovery() {
	f.loseCustodyAfterRecovery(func() (func(), bool, string) {
		return changePodRecoveryCredentials(f.t, f.credentialSource), true, "retained Pod credential volume was replaced"
	})
}

// Replays of the retained version and of an older one change neither the
// retained policy nor the issuance revision; the next version advances both
// and stales the earlier response (GB8, CC2).
func (f *podRecoveryFixture) replayPolicyAfterRecovery() {
	t := f.t
	t.Helper()
	retainedPolicy, err := allowlist.ParseServedJSON(f.served)
	f.must(err)
	retainedBody := canonicalBody(t, retainedPolicy)
	changedBody := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "replacement"}))
	changedPolicy, err := allowlist.ParseServedJSON(changedBody)
	f.must(err)
	changedEffectiveBody := canonicalBody(t, changedPolicy)
	for _, etag := range []string{`W/"1"`, `W/"2"`} {
		f.servedMu.Lock()
		f.served, f.servedETag = changedBody, etag
		requestsBefore := f.servedRequests.Load()
		f.servedMu.Unlock()
		f.available.Store(true)
		until := time.Now().Add(5 * time.Second)
		// Pulls are serialized. The following request proves the previous
		// response reached policy application, rather than merely delivery.
		for f.servedRequests.Load() < requestsBefore+2 {
			if time.Now().After(until) {
				t.Fatalf("recovered policy did not process replay %s", etag)
			}
			time.Sleep(time.Millisecond)
		}
		current, err := f.recoveredBroker.Snapshot(f.ctx)
		if err != nil || current.Revision != f.after.Revision {
			t.Fatalf("refused replay changed issuance revision: %+v %v", current, err)
		}
		if retained := f.readState(); retained.Policy.Version != 2 || !bytes.Equal(retained.Policy.Document, retainedBody) {
			t.Fatalf("replay %s replaced the retained policy", etag)
		}
		if err := f.recoveredBroker.Commit(f.after, func() error { return nil }); err != nil {
			t.Fatalf("refused replay invalidated current issuance: %v", err)
		}
	}
	f.servedMu.Lock()
	f.servedETag = `W/"3"`
	f.servedMu.Unlock()
	f.expectedVersion = 3
	f.waitReady()
	current, err := f.recoveredBroker.Snapshot(f.ctx)
	if err != nil || current.Revision <= f.after.Revision {
		t.Fatalf("newer policy did not advance recovered issuance: %+v %v", current, err)
	}
	published := false
	if err := f.recoveredBroker.Commit(f.after, func() error { published = true; return nil }); err == nil || published {
		t.Fatal("newer policy retained stale issuance authority")
	}
	if err := f.recoveredBroker.Commit(current, func() error { return nil }); err != nil {
		t.Fatalf("newer policy could not authorize current issuance: %v", err)
	}
	if retained := f.readState(); retained.Policy.Version != 3 || !bytes.Equal(retained.Policy.Document, changedEffectiveBody) {
		t.Fatal("accepted next version did not persist its effective policy")
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

// The substitution affects only the fixture's owned credential tmpfs. The
// substituted volume has valid custody permissions so inode identity, not
// chmod, rejects it.
func changePodRecoveryCredentials(t *testing.T, source string) func() {
	t.Helper()
	original, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	mountPodTestRAM(t, source)
	if err := os.Chown(source, 0, int(workloadclaims.MeshUID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0750); err != nil {
		t.Fatal(err)
	}
	changed, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(original, changed) {
		t.Fatal("credential substitution did not change directory identity")
	}
	return func() {
		t.Helper()
		current, err := os.Stat(source)
		if err != nil || current.Mode().Perm() != 0750 || !os.SameFile(changed, current) {
			t.Fatalf("credential verification repaired or replaced lost custody: %v", err)
		}
	}
}
