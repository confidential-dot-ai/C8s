//go:build linux && pod_runtime_integration

package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	imageverifier "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/internal/podstart"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type runtimeFixture struct{ Tag, Pin, Reference string }

type runtimeGateHook struct {
	p        *plugin
	s        stub.Stub
	mode     string
	stopGate context.CancelFunc
	gateDone <-chan error
	done     chan error
	mu       sync.Mutex
	request  podstart.Request
	consumed []podstart.Request
}

func (h *runtimeGateHook) Configure(context.Context, string, string, string) (api.EventMask, error) {
	var mask api.EventMask
	mask.Set(api.Event_START_CONTAINER)
	return mask, nil
}

func (h *runtimeGateHook) Synchronize(context.Context, []*api.PodSandbox, []*api.Container) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

func (h *runtimeGateHook) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (err error) {
	defer func() { h.done <- err }()
	h.p.podBroker.pod = pod
	h.p.inventory.recordSandbox(pod.Id)
	h.mu.Lock()
	h.request = podstart.Request{ContainerID: ctr.Id, SandboxID: pod.Id, PID: ctr.Pid}
	h.mu.Unlock()
	if err = h.p.StartContainer(ctx, pod, ctr); err != nil {
		return err
	}
	switch h.mode {
	case "socket-lost":
		h.stopGate()
		if err = <-h.gateDone; err != nil {
			return err
		}
	case "disconnect":
		h.p.disconnectPodStarts()
		h.s.Stop()
	case "replayed":
		h.mu.Lock()
		request := h.request
		h.mu.Unlock()
		err = h.p.consumePodStart(ctx, request)
	}
	return err
}

type runtimeMeasure struct {
	workloadMeasurer
	fail  bool
	delay time.Duration
}

func (m runtimeMeasure) MeasureOnce(digest string) (bool, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.fail {
		return false, errors.New("simulated register extension failure")
	}
	return m.workloadMeasurer.MeasureOnce(digest)
}

func TestPodRuntimeAdmissionIntegration(t *testing.T) {
	if os.Getenv("C8S_POD_RUNTIME_ISOLATED") != "1" {
		t.Fatal("run this test through test/integration/pod-runtime/run.sh")
	}
	if _, err := os.Stat("/validation/isolated"); err != nil {
		t.Fatal("missing disposable-container marker")
	}
	if os.Geteuid() != 0 {
		t.Fatal("runtime harness requires root in its disposable container")
	}
	var fixture runtimeFixture
	readRuntimeJSON(t, "/validation/fixture.json", &fixture)
	var inputs struct {
		RunID string `json:"runId"`
	}
	readRuntimeJSON(t, "/validation/inputs.json", &inputs)
	if inputs.RunID == "" {
		t.Fatal("missing runtime invocation identity")
	}
	writeRuntimeWrapperPolicy(t, fixture)
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(t.Context(), "k8s.io"), 100*time.Second)
	defer cancel()
	client, err := containerdclient.New("/run/pod-start-test/containerd.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := grpc.NewClient("unix:///run/pod-start-test/containerd.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	runtimeService := cri.NewRuntimeServiceClient(conn)
	img, err := client.ImageService().Get(ctx, fixture.Tag)
	if err != nil {
		t.Fatal(err)
	}
	if img.Target.Digest.String() != fixture.Pin {
		t.Fatal("fixture import does not match the frozen image pin")
	}
	_, err = client.ImageService().Create(ctx, images.Image{Name: fixture.Reference, Target: img.Target, Labels: map[string]string{"io.cri-containerd.image": "managed"}})
	if err != nil && !errdefs.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	imageService := cri.NewImageServiceClient(conn)
	until := time.Now().Add(5 * time.Second)
	for {
		status, err := imageService.ImageStatus(ctx, &cri.ImageStatusRequest{Image: &cri.ImageSpec{Image: fixture.Reference}})
		if err == nil && status.Image != nil {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("CRI fixture registration failed: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	pod := &cri.PodSandboxConfig{Metadata: &cri.PodSandboxMetadata{Name: "start-gate", Namespace: "validation", Uid: "runtime-start-validation"}, Linux: &cri.LinuxPodSandboxConfig{CgroupParent: "/c8s-start-validation", SecurityContext: &cri.LinuxSandboxSecurityContext{NamespaceOptions: &cri.NamespaceOption{Network: cri.NamespaceMode_NODE}}}}
	sandbox, err := runtimeService.RunPodSandbox(ctx, &cri.RunPodSandboxRequest{Config: pod})
	if err != nil {
		t.Fatalf("pause sandbox through production wrapper: %v", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := runtimeService.StopPodSandbox(cleanup, &cri.StopPodSandboxRequest{PodSandboxId: sandbox.PodSandboxId}); err != nil {
			t.Error(err)
		}
		if _, err := runtimeService.RemovePodSandbox(cleanup, &cri.RemovePodSandboxRequest{PodSandboxId: sandbox.PodSandboxId}); err != nil {
			t.Error(err)
		}
	}()
	resolver, err := imageverifier.NewResolver("/run/pod-start-test/containerd.sock", "k8s.io")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	cases := make(map[string]any)
	results := map[string]any{"runId": inputs.RunID, "architecture": runtime.GOARCH, "sandboxId": sandbox.PodSandboxId, "cases": cases, "sandbox-started-without-workload-permission": true, "runtime-scope": "native snapshotter; simulated TEE register and broker; digest-pinned registry release runtime; guest airgap byte equivalence unverified; no mesh/CDS hardware assertion"}
	for _, mode := range []string{"absent", "deny", "failed-extend", "late", "socket-lost", "disconnect", "replayed", "admit"} {
		t.Run(mode, func(t *testing.T) {
			cases[mode] = runRuntimeStartCase(t, ctx, client, runtimeService, resolver, fixture, pod, sandbox.PodSandboxId, mode)
		})
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/validation/artifacts/result.json", append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func runRuntimeStartCase(t *testing.T, ctx context.Context, client *containerdclient.Client, runtime cri.RuntimeServiceClient, resolver *imageverifier.Resolver, fixture runtimeFixture, pod *cri.PodSandboxConfig, sandboxID, mode string) map[string]any {
	t.Helper()
	var hook *runtimeGateHook
	if mode != "absent" {
		hook = startRuntimeHook(t, fixture, resolver, mode)
	}
	container, err := runtime.CreateContainer(ctx, &cri.CreateContainerRequest{PodSandboxId: sandboxID, SandboxConfig: pod, Config: &cri.ContainerConfig{Metadata: &cri.ContainerMetadata{Name: "app"}, Image: &cri.ImageSpec{Image: fixture.Reference}, Command: []string{"/marker-workload", mode}, Linux: &cri.LinuxContainerConfig{SecurityContext: &cri.LinuxContainerSecurityContext{RunAsUser: &cri.Int64Value{Value: 65532}, RunAsGroup: &cri.Int64Value{Value: 65532}, NoNewPrivs: true, Capabilities: &cri.Capability{DropCapabilities: []string{"ALL"}}, NamespaceOptions: &cri.NamespaceOption{Pid: cri.NamespaceMode_CONTAINER}, MaskedPaths: []string{"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware"}, ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}, Seccomp: &cri.SecurityProfile{ProfileType: cri.SecurityProfile_RuntimeDefault}}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = runtime.StopContainer(cleanup, &cri.StopContainerRequest{ContainerId: container.ContainerId})
		if _, err := runtime.RemoveContainer(cleanup, &cri.RemoveContainerRequest{ContainerId: container.ContainerId}); err != nil {
			t.Error(err)
		}
	}()
	info, err := client.ContainerService().Get(ctx, container.ContainerId)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := client.SnapshotService(info.Snapshotter).Mounts(ctx, info.SnapshotKey)
	if err != nil || len(mounts) != 1 {
		t.Fatalf("snapshot mounts: %+v %v", mounts, err)
	}
	marker := filepath.Join(mounts[0].Source, "tmp/pod-start-marker")
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker predates process start: %v", err)
	}
	_, startErr := runtime.StartContainer(ctx, &cri.StartContainerRequest{ContainerId: container.ContainerId})
	if startErr != nil && strings.Contains(startErr.Error(), "failed to create containerd task") {
		t.Fatalf("runtime create fixture failed before the admission gate: %v", startErr)
	}
	if hook != nil {
		select {
		case <-hook.done:
		case <-time.After(5 * time.Second):
			t.Fatal("NRI start callback did not finish")
		}
	}
	if mode == "admit" {
		if startErr != nil {
			t.Fatalf("admitted start failed: %v", startErr)
		}
		until := time.Now().Add(3 * time.Second)
		for {
			data, err := os.ReadFile(marker)
			if err == nil {
				if string(data) != mode {
					t.Fatalf("wrong process marker: %q", data)
				}
				break
			}
			if time.Now().After(until) {
				t.Fatalf("admitted workload never executed: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	} else {
		if startErr == nil {
			t.Fatal("failed permission admitted process execution")
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("refused workload executed: %v", err)
		}
		want := map[string]string{"deny": "image not in allowlist", "failed-extend": "simulated register extension failure", "late": "HTTP 403", "disconnect": "HTTP 403", "replayed": "HTTP 403", "absent": "connect: no such file or directory", "socket-lost": "connect: no such file or directory"}[mode]
		if !strings.Contains(startErr.Error(), want) {
			t.Fatalf("case failed for an unexpected reason: want %q in %v", want, startErr)
		}
	}
	if mode != "deny" && mode != "failed-extend" && mode != "admit" && !strings.Contains(startErr.Error(), "OCI runtime start failed: c8s-runc:") {
		t.Fatalf("start did not reach the production wrapper: %v", startErr)
	}
	result := map[string]any{"containerId": container.ContainerId, "markerExecuted": mode == "admit"}
	if startErr != nil {
		result["refusal"] = startErr.Error()
	}
	if hook != nil {
		hook.mu.Lock()
		defer hook.mu.Unlock()
		if hook.request.PID == 0 || hook.request.ContainerID != container.ContainerId || hook.request.SandboxID != sandboxID {
			t.Fatal("NRI did not provide the created container's exact process identity")
		}
		result["nriRequest"] = hook.request
		result["consumedByWrapper"] = hook.consumed
		if mode == "admit" && (len(hook.consumed) != 1 || hook.consumed[0] != hook.request) {
			t.Fatal("wrapper did not consume the exact created NRI process")
		}
		if mode == "admit" {
			created, err := client.LoadContainer(ctx, container.ContainerId)
			if err != nil {
				t.Fatal(err)
			}
			task, err := created.Task(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if task.Pid() != hook.request.PID {
				t.Fatal("consumed NRI PID does not match the running containerd task")
			}
			result["taskPid"] = task.Pid()
		}
	}
	return result
}

func startRuntimeHook(t *testing.T, fixture runtimeFixture, resolver *imageverifier.Resolver, mode string) *runtimeGateHook {
	t.Helper()
	base := runtimeAllowlist(fixture)
	p := newTestPlugin(&config{Pod: &podConfig{UID: "signed-runtime-uid", Namespace: "validation", Name: "start-gate", Images: map[string]string{"app": fixture.Pin}}, Allowlist: allowlistConfig{Base: base}, Policy: policyConfig{Mode: ModeFailClosed}, Measure: measureConfig{RTMR3: true}})
	p.mesh.policy.ExemptNamespaces = append(p.mesh.policy.ExemptNamespaces, "validation")
	p.containerd = resolver
	p.inventory = newAdmissionInventory("/proc")
	brokerCtx, stopBroker := context.WithCancel(t.Context())
	p.podBroker = &podCredentialBroker{ctx: brokerCtx, cancel: stopBroker}
	p.SetReady()
	measured, err := openMeasurer(measureFixture(t, &fakeRegister{value: launchSeed}), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	measure := runtimeMeasure{workloadMeasurer: measured, fail: mode == "failed-extend"}
	if mode == "late" {
		measure.delay = 1500 * time.Millisecond
	}
	p.measurer = measure
	if mode == "deny" {
		p.policy = newPolicyStore(nil)
	}
	listener, err := podstart.Listen(podstart.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stopGate := context.WithCancel(t.Context())
	gateDone := make(chan error, 1)
	h := &runtimeGateHook{p: p, mode: mode, stopGate: stopGate, gateDone: gateDone, done: make(chan error, 1)}
	go func() {
		gateDone <- podstart.Serve(serveCtx, listener, func(ctx context.Context, r podstart.Request) error {
			err := p.consumePodStart(ctx, r)
			if err == nil {
				h.mu.Lock()
				h.consumed = append(h.consumed, r)
				h.mu.Unlock()
			}
			return err
		})
		close(gateDone)
	}()
	h.s, err = stub.New(h, stub.WithPluginName("pod-start-validation"), stub.WithPluginIdx("95"), stub.WithSocketPath("/run/pod-start-test/nri.sock"), stub.WithOnClose(p.disconnectPodStarts))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.s.Stop()
		p.disconnectPodStarts()
		stopBroker()
		stopGate()
		_ = listener.Close()
		select {
		case <-gateDone:
		case <-time.After(5 * time.Second):
			t.Error("permission server did not stop")
		}
	})
	return h
}

func writeRuntimeWrapperPolicy(t *testing.T, fixture runtimeFixture) {
	t.Helper()
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	base := runtimeAllowlist(fixture)
	for name, w := range cfg.Allowlist.Base.Workloads {
		for _, c := range w.Containers {
			if c.Role == meshRole {
				base.Workloads[name] = w
			}
		}
	}
	cfg.Platform = "tdx"
	cfg.Allowlist.Base = base
	cfg.Allowlist.NodeTCB = false
	cfg.Policy.Sandbox = SandboxEnforce
	cfg.Allowlist.Pull.URL = "https://127.0.0.1:1/allowlist"
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "/validation/pins.json"
	cfg.Allowlist.Pull.CDSMeasurements = nil
	cfg.Allowlist.Pull.CDSRTMRs = nil
	cfg.Allowlist.Pull.MeasurePolicies = false
	cfg.Measure.RTMR3 = true
	cfg.Pod = &podConfig{UID: "signed-runtime-uid", Namespace: "validation", Name: "start-gate", Images: map[string]string{"app": fixture.Pin, workloadclaims.MeshContainerName: meshImageDigest}}
	cfg.Mesh.Pod = &podMeshPolicy{}
	cfg.Mesh.ExemptNamespaces = nil
	cfg.Mesh.CredentialAttestationPort = 0
	cfg.Mesh.Roles = []roleBinding{{Name: meshRole, UID: workloadclaims.MeshUID}}
	cfg.WorkloadClaims.CDSNodePort = 0
	cfg.WorkloadClaims.PublishNodeIP = false
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(DefaultConfigPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(DefaultConfigPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	floor, err := LoadMeshFloor(DefaultConfigPath)
	if err != nil || !floor.PodRole {
		t.Fatalf("prepared wrapper Pod policy: %+v %v", floor, err)
	}
}

func readRuntimeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

// This harness isolates the runtime permission barrier from tenant launch policy.
// The content digest stays pinned; CRI's generated environment and mounts are allowed.
func runtimeAllowlist(fixture runtimeFixture) *allowlist.Allowlist {
	base := anyAllowlist(map[string]string{fixture.Pin: "fixture"})
	for name, workload := range base.Workloads {
		for i := range workload.Containers {
			workload.Containers[i].Env.Policy = allowlist.PolicyAny
			workload.Containers[i].Mounts.Policy = allowlist.PolicyAny
		}
		base.Workloads[name] = workload
	}
	return base
}
