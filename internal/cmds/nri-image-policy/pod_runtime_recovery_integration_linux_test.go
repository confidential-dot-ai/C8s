//go:build linux && pod_runtime_integration

package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/internal/podstart"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const recoveryRuntimeDir = "/validation/recovery"
const recoveryRuntimeSocket = "/run/pod-recovery-runtime/containerd.sock"

// This lane uses the complete production plugin in a separate process. Only
// hardware measurement and CDS transport/issuance are fixtures. No callback,
// resolver, process proof, network protection or recovery method is replaced.
func TestPodRuntimeRecoveryIntegration(t *testing.T) {
	requireRuntimeRecoveryIsolation(t)
	if err := os.MkdirAll(recoveryRuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	var app, mesh runtimeFixture
	readRuntimeJSON(t, "/validation/fixture.json", &app)
	readRuntimeJSON(t, "/validation/mesh-fixture.json", &mesh)
	var inputs struct {
		RunID string `json:"runId"`
	}
	readRuntimeJSON(t, "/validation/inputs.json", &inputs)
	if inputs.RunID == "" || app.Pin == mesh.Pin {
		t.Fatal("missing distinct invocation/image identity")
	}
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(t.Context(), "k8s.io"), 150*time.Second)
	defer cancel()
	cfg := recoveryRuntimeConfig(t, app, mesh)
	mountPodTestRAM(t, cfg.WorkloadClaims.SocketDir)
	seed := runtimemeasure.Seed([]byte("runtime recovery launch key fixture"))
	if err := os.WriteFile(filepath.Join(recoveryRuntimeDir, "register"), seed[:], 0600); err != nil {
		t.Fatal(err)
	}
	configureRecoveryCDS(t, cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configBytes, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(DefaultConfigPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(configBytes)
	daemon := startRecoveryProcess(t, "containerd-1", "/validation/runtime/containerd", "--config", "/validation/recovery-containerd.toml")
	waitRecoveryRuntime(t, ctx)
	client, err := containerdclient.New(recoveryRuntimeSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := grpc.NewClient("unix://"+recoveryRuntimeSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	runtime := cri.NewRuntimeServiceClient(conn)
	for _, fixture := range []runtimeFixture{app, mesh} {
		cmd := exec.CommandContext(ctx, "/validation/runtime/ctr", "--address", recoveryRuntimeSocket, "--namespace", "k8s.io", "images", "import", "--local", "--platform", "linux/"+os.Getenv("C8S_POD_RUNTIME_ARCH"), "--snapshotter", "native", "/validation/fixtures.tar")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("import fixture: %v\n%s", err, output)
		}
		img, err := client.ImageService().Get(ctx, fixture.Tag)
		if err != nil || img.Target.Digest.String() != fixture.Pin {
			t.Fatalf("frozen fixture registration: %+v %v", img, err)
		}
		if _, err := client.ImageService().Create(ctx, images.Image{Name: fixture.Reference, Target: img.Target, Labels: map[string]string{"io.cri-containerd.image": "managed"}}); err != nil && !errdefs.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	plugin := startRecoveryPlugin(t, "plugin-1")
	waitRecoveryPlugin(t, ctx, plugin)
	pod := &cri.PodSandboxConfig{Metadata: &cri.PodSandboxMetadata{Name: cfg.Pod.Name, Namespace: cfg.Pod.Namespace, Uid: "runtime-recovery-pod"}, Linux: &cri.LinuxPodSandboxConfig{CgroupParent: "/c8s-recovery-validation", SecurityContext: &cri.LinuxSandboxSecurityContext{NamespaceOptions: &cri.NamespaceOption{Network: cri.NamespaceMode_POD, Pid: cri.NamespaceMode_CONTAINER}}}}
	sandbox, err := runtime.RunPodSandbox(ctx, &cri.RunPodSandboxRequest{Config: pod})
	if err != nil {
		t.Fatalf("protected sandbox: %v", err)
	}
	sandboxID := sandbox.PodSandboxId
	cleanupDone := false
	cleanup := func() {
		if cleanupDone {
			return
		}
		cleanupDone = true
		clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := runtime.StopPodSandbox(clean, &cri.StopPodSandboxRequest{PodSandboxId: sandboxID}); err != nil {
			t.Error(err)
		}
		if _, err := runtime.RemovePodSandbox(clean, &cri.RemovePodSandboxRequest{PodSandboxId: sandboxID}); err != nil {
			t.Error(err)
		}
	}
	credentialSource := filepath.Join(kubeletRoot, "pods", pod.Metadata.Uid, "volumes", emptyDirPlugin, podmesh.CertVolumeName)
	mountPodTestRAM(t, credentialSource)
	t.Cleanup(cleanup)
	hosts := filepath.Join(kubeletRoot, "pods", pod.Metadata.Uid, "etc-hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	start := func(name, argument string, fixture runtimeFixture, uid int64, credentials bool) string {
		config := recoveryCRIContainer(name, argument, fixture, uid)
		config.Mounts = []*cri.Mount{{HostPath: hosts, ContainerPath: "/etc/hosts", Readonly: true}}
		if credentials {
			config.Mounts = append(config.Mounts, &cri.Mount{HostPath: credentialSource, ContainerPath: podmesh.CertDir, Readonly: true})
		}
		created, err := runtime.CreateContainer(ctx, &cri.CreateContainerRequest{PodSandboxId: sandboxID, SandboxConfig: pod, Config: config})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := runtime.StartContainer(ctx, &cri.StartContainerRequest{ContainerId: created.ContainerId}); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		waitRecoveryMarker(t, ctx, client, created.ContainerId, argument)
		return created.ContainerId
	}
	meshID := start(workloadclaims.MeshContainerName, "mesh", mesh, int64(workloadclaims.MeshUID), true)
	removedID := start("completed-job", "completed-init", app, int64(workloadclaims.CredentialsUID), false)
	if _, err := runtime.StopContainer(ctx, &cri.StopContainerRequest{ContainerId: removedID}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RemoveContainer(ctx, &cri.RemoveContainerRequest{ContainerId: removedID}); err != nil {
		t.Fatal(err)
	}
	appID := start("app", "live-app", app, int64(workloadclaims.CredentialsUID), false)
	before := waitRecoveryClaims(t, ctx, 3)
	if len(before.RuntimeExtensions) != 2 {
		t.Fatalf("measured digests=%v", before.RuntimeExtensions)
	}
	taskPID := recoveryTaskPID(t, ctx, client, appID)
	oldRequest := podstart.Request{ContainerID: appID, SandboxID: sandboxID, PID: taskPID}
	if _, err := readPodProcessIdentity(taskPID, appID); err != nil {
		t.Fatalf("real runtime process binding: %v", err)
	}
	if _, err := readPodProcessIdentity(taskPID, meshID); err == nil {
		t.Fatal("real process cgroup accepted another container identity")
	}
	beforePID := plugin.cmd.Process.Pid
	plugin.stop(t, false)
	journalBefore := readRecoveryFile(t, journalPath(cfg))
	registerBefore := readRecoveryFile(t, filepath.Join(recoveryRuntimeDir, "register"))
	oldDaemonPID := daemon.cmd.Process.Pid
	daemon.stop(t, false)
	daemon = startRecoveryProcess(t, "containerd-2", "/validation/runtime/containerd", "--config", "/validation/recovery-containerd.toml")
	waitRecoveryRuntime(t, ctx)
	plugin = startRecoveryPlugin(t, "plugin-2")
	waitRecoveryPlugin(t, ctx, plugin)
	recoveredPluginPID := plugin.cmd.Process.Pid
	after := waitRecoveryClaims(t, ctx, 3)
	if after.Revision < before.Revision {
		t.Fatal("recovery rewound the admission revision")
	}
	before.Revision = after.Revision
	beforeWire, err := before.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	afterWire, err := after.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeWire, afterWire) {
		t.Fatalf("full historical claims changed across real runtime restart\nbefore=%s\nafter=%s", beforeWire, afterWire)
	}
	if beforePID == plugin.cmd.Process.Pid || oldDaemonPID == daemon.cmd.Process.Pid {
		t.Fatal("runtime or plugin process did not restart")
	}
	if !bytes.Equal(journalBefore, readRecoveryFile(t, journalPath(cfg))) || !bytes.Equal(registerBefore, readRecoveryFile(t, filepath.Join(recoveryRuntimeDir, "register"))) {
		t.Fatal("recovery extended or erased measured history")
	}
	if afterPID := recoveryTaskPID(t, ctx, client, appID); afterPID != taskPID {
		t.Fatalf("restart replaced running task: %d != %d", afterPID, taskPID)
	}
	if err := podstart.Consume(ctx, podstart.SocketPath, oldRequest); err == nil {
		t.Fatal("recovered plugin restored a consumed start grant")
	}
	if !bytes.Equal(configBytes, readRecoveryFile(t, DefaultConfigPath)) {
		t.Fatal("runtime recovery changed assigned policy")
	}
	// A fresh full callback path remains usable after recovery. The same image
	// adds a distinct admission observation without extending its digest again.
	freshID := start("post-recovery-job", "post-recovery", app, int64(workloadclaims.CredentialsUID), false)
	finalClaims := waitRecoveryClaims(t, ctx, 4)
	if finalClaims.InstanceID() != after.InstanceID() || !slices.Equal(finalClaims.RuntimeExtensions, after.RuntimeExtensions) {
		t.Fatal("new post-recovery start changed the assigned credential identity")
	}
	plugin.stop(t, true)
	statePath := filepath.Join(cfg.WorkloadClaims.SocketDir, podRecoveryDirectory, podRecoveryStateFile)
	originalState := readRecoveryFile(t, statePath)
	negative := map[string]bool{}
	for _, scenario := range []string{"missing-history", "tampered-history", "pending-transition"} {
		if err := os.WriteFile(statePath, originalState, 0600); err != nil {
			t.Fatal(err)
		}
		switch scenario {
		case "missing-history":
			if err := os.Remove(statePath); err != nil {
				t.Fatal(err)
			}
		case "tampered-history":
			if err := os.WriteFile(statePath, []byte(`{"version":1,"histories":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
		case "pending-transition":
			if err := os.WriteFile(filepath.Join(filepath.Dir(statePath), podRecoveryPendingFile), []byte("interrupted-authority-transition"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		refused := startRecoveryPlugin(t, "plugin-refused-"+scenario)
		refused.waitFailure(t)
		if err := podstart.Consume(ctx, podstart.SocketPath, oldRequest); err == nil {
			t.Fatal("invalid recovery state retained a start socket")
		}
		if _, err := runtime.CreateContainer(ctx, &cri.CreateContainerRequest{PodSandboxId: sandboxID, SandboxConfig: pod, Config: recoveryCRIContainer("refused", scenario, app, int64(workloadclaims.CredentialsUID))}); err == nil {
			t.Fatal("containerd admitted a create without the required full plugin")
		}
		negative[scenario] = true
	}
	// Restore the exact checkpoint only to let the real plugin observe cleanup.
	if err := os.Remove(filepath.Join(filepath.Dir(statePath), podRecoveryPendingFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, originalState, 0600); err != nil {
		t.Fatal(err)
	}
	plugin = startRecoveryPlugin(t, "plugin-cleanup")
	waitRecoveryPlugin(t, ctx, plugin)
	cleanup()
	listed, err := runtime.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{})
	if err != nil || len(listed.Items) != 0 {
		t.Fatalf("sandbox cleanup incomplete: %+v %v", listed, err)
	}
	plugin.stop(t, false)
	daemon.stop(t, false)
	result := map[string]any{"runId": inputs.RunID, "sandboxId": sandboxID, "meshContainerId": meshID, "appContainerId": appID, "removedContainerId": removedID, "postRecoveryContainerId": freshID, "taskPid": taskPID, "pluginProcessIds": []int{beforePID, recoveredPluginPID}, "containerdProcessIds": []int{oldDaemonPID, daemon.cmd.Process.Pid}, "credentialInstanceId": after.InstanceID(), "assignedPolicySHA256": hex.EncodeToString(configHash[:]), "historicalObservations": len(after.Containers), "measuredDigests": after.RuntimeExtensions, "fullClaimsPreserved": true, "taskPreserved": true, "oldGrantRefused": true, "cgroupIdentityChecked": true, "negative": negative, "sandboxCleanup": true, "scope": "production NRI subprocess and containerd restart, full callbacks, real image/cgroup/namespace proofs; simulated TEE register and CDS transport; credential identity checked without certificate issuance; no kubelet restart claim"}
	wire, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/validation/artifacts/recovery-result.json", append(wire, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func recoveryRuntimeConfig(t *testing.T, app, mesh runtimeFixture) *config {
	t.Helper()
	writeRuntimeWrapperPolicy(t, app)
	data := readRecoveryFile(t, DefaultConfigPath)
	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	base := runtimeAllowlist(app)
	var entry allowlist.Container
	for _, workload := range runtimeAllowlist(mesh).Workloads {
		entry = workload.Containers[0]
	}
	entry.Role = meshRole
	entry.Command = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/marker-workload"}}
	entry.Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"mesh"}}
	base.Workloads["mesh-fixture"] = allowlist.Workload{Containers: []allowlist.Container{entry}}
	cfg.Allowlist.Base = base
	// Match nodeservices Pod preparation: the standalone ruleset has no node service exits.
	cfg.Mesh.Exits = nil
	cfg.Allowlist.Pull.Timeout = time.Second
	cfg.Allowlist.Pull.Interval = time.Second
	cfg.Pod = &podConfig{UID: "signed-recovery-uid", Name: "runtime-recovery", Namespace: "validation", Images: map[string]string{workloadclaims.MeshContainerName: mesh.Pin, "completed-job": app.Pin, "app": app.Pin, "post-recovery-job": app.Pin, "refused": app.Pin}}
	cfg.Plugin.HealthAddr = "unix://" + filepath.Join(recoveryRuntimeDir, "health.sock")
	cfg.Containerd.Socket = recoveryRuntimeSocket
	cfg.Policy.BootMarkerPath = filepath.Join(recoveryRuntimeDir, "registered")
	return &cfg
}

// configureRecoveryCDS keeps the allowlist service and attestation verdict
// under the driver while exercising the production armTLS client in each child.
// The fixture pin and verdict bind the same independent CDS launch file.
func configureRecoveryCDS(t *testing.T, cfg *config) {
	t.Helper()
	served := canonicalBody(t, anyAllowlist(map[string]string{}))
	cds := testutil.NewARMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"1"`)
		_, _ = w.Write(served)
	}))
	verifier := mockapi.New(t)
	verdict := mockapi.PassingVerdict(testutil.TestMeasurement)
	binding := runtimemeasure.HostData([]byte(testutil.CDSLaunchFile))
	verdict.Claims.InitData = binding[:]
	verifier.SetVerdict(verdict)
	cfg.Allowlist.Pull.URL = cds.URL
	cfg.Allowlist.Pull.AttestationApiURL = verifier.URL()
}

func recoveryCRIContainer(name, argument string, fixture runtimeFixture, uid int64) *cri.ContainerConfig {
	return &cri.ContainerConfig{Metadata: &cri.ContainerMetadata{Name: name}, Image: &cri.ImageSpec{Image: fixture.Reference}, Command: []string{"/marker-workload", argument}, Linux: &cri.LinuxContainerConfig{SecurityContext: &cri.LinuxContainerSecurityContext{RunAsUser: &cri.Int64Value{Value: uid}, RunAsGroup: &cri.Int64Value{Value: uid}, NoNewPrivs: true, Capabilities: &cri.Capability{DropCapabilities: []string{"ALL"}}, NamespaceOptions: &cri.NamespaceOption{Pid: cri.NamespaceMode_CONTAINER}, MaskedPaths: []string{"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware"}, ReadonlyPaths: []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}, Seccomp: &cri.SecurityProfile{ProfileType: cri.SecurityProfile_RuntimeDefault}}}}
}

type recoveryProcess struct {
	cmd     *exec.Cmd
	done    chan error
	stopped bool
}

func startRecoveryProcess(t *testing.T, name, binary string, args ...string) *recoveryProcess {
	t.Helper()
	log, err := os.Create(filepath.Join("/validation/artifacts", name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	p := &recoveryProcess{cmd: cmd, done: make(chan error, 1)}
	go func() { err := cmd.Wait(); _ = log.Close(); p.done <- err }()
	t.Cleanup(func() { p.stop(t, true) })
	return p
}
func (p *recoveryProcess) stop(t *testing.T, kill bool) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	if kill {
		_ = p.cmd.Process.Kill()
	} else {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(time.Second):
			t.Error("owned runtime process did not exit")
		}
	}
}
func (p *recoveryProcess) waitFailure(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.done:
		p.stopped = true
		if err == nil {
			t.Fatal("invalid history plugin exited successfully")
		}
	case <-time.After(8 * time.Second):
		p.stop(t, true)
		t.Fatal("invalid history plugin did not refuse startup")
	}
}
func startRecoveryPlugin(t *testing.T, name string) *recoveryProcess {
	t.Helper()
	if err := os.Remove(filepath.Join(recoveryRuntimeDir, "claims.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return startRecoveryProcess(t, name, os.Args[0], "-test.v", "-test.run=^TestPodRuntimeRecoveryPluginProcess$", "-test.timeout=180s")
}
func waitRecoveryRuntime(t *testing.T, ctx context.Context) {
	t.Helper()
	until := time.Now().Add(8 * time.Second)
	for {
		cmd := exec.CommandContext(ctx, "/validation/runtime/ctr", "--address", recoveryRuntimeSocket, "version")
		if cmd.Run() == nil {
			return
		}
		if time.Now().After(until) {
			t.Fatal("owned recovery containerd did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func waitRecoveryPlugin(t *testing.T, ctx context.Context, p *recoveryProcess) {
	t.Helper()
	client := unixHealthClient(filepath.Join(recoveryRuntimeDir, "health.sock"))
	defer client.CloseIdleConnections()
	until := time.Now().Add(8 * time.Second)
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			var body healthResponse
			decode := json.NewDecoder(response.Body).Decode(&body)
			_ = response.Body.Close()
			if decode == nil && response.StatusCode == http.StatusOK && body.PodRegistered {
				return
			}
		}
		select {
		case err := <-p.done:
			p.stopped = true
			t.Fatalf("full plugin exited before readiness: %v", err)
		default:
		}
		if time.Now().After(until) {
			t.Fatal("full production plugin did not become registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func waitRecoveryClaims(t *testing.T, ctx context.Context, count int) workloadclaims.PodClaims {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(recoveryRuntimeDir, "claims.json"))
		if err == nil {
			claims, decodeErr := workloadclaims.DecodePodClaims(data)
			if decodeErr == nil && len(claims.Containers) == count {
				return claims
			}
		}
		if time.Now().After(until) || ctx.Err() != nil {
			t.Fatalf("production snapshot did not retain %d historical observations: %v", count, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func recoveryTaskPID(t *testing.T, ctx context.Context, client *containerdclient.Client, id string) uint32 {
	t.Helper()
	ctr, err := client.LoadContainer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	task, err := ctr.Task(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return task.Pid()
}
func waitRecoveryMarker(t *testing.T, ctx context.Context, client *containerdclient.Client, id, want string) {
	t.Helper()
	info, err := client.ContainerService().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := client.SnapshotService(info.Snapshotter).Mounts(ctx, info.SnapshotKey)
	if err != nil || len(mounts) != 1 {
		t.Fatalf("recovery task snapshot: %+v %v", mounts, err)
	}
	until := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(mounts[0].Source, "tmp/pod-start-marker"))
		if err == nil && string(data) == want {
			return
		}
		if time.Now().After(until) {
			t.Fatalf("admitted task did not execute marker %q: %v", want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func readRecoveryFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func requireRuntimeRecoveryIsolation(t *testing.T) {
	t.Helper()
	if os.Getenv("C8S_POD_RUNTIME_ISOLATED") != "1" || os.Geteuid() != 0 {
		t.Fatal("use disposable runtime runner")
	}
	if _, err := os.Stat("/validation/isolated"); err != nil {
		t.Fatal(err)
	}
}

// The only seams here are the simulated hardware register and issuer. Their
// state survives the real plugin OS process and no start/recovery hook exists.
func TestPodRuntimeRecoveryPluginProcess(t *testing.T) {
	requireRuntimeRecoveryIsolation(t)
	if _, err := os.Stat(filepath.Join(recoveryRuntimeDir, "register")); err != nil {
		t.Fatal("plugin helper may run only inside the recovery driver")
	}
	// Load the same HTTPS configuration as the wrapper, including its CDS
	// address and launch-bound pin; only the fixture attestation API is local.
	cfg, err := loadConfig(DefaultConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	readOperatorKey = func() ([]byte, error) { return []byte("runtime recovery launch key fixture"), nil }
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) {
		return &recoveryFileRegister{path: filepath.Join(recoveryRuntimeDir, "register")}, nil
	}
	allowlistApiMaxRetries = 1
	runGuestCredentials = func(ctx context.Context, guest getcert.GuestConfig) error {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			claims, err := guest.Snapshot(ctx)
			if err == nil {
				if claims.InstanceID() != guest.InstanceID {
					return errors.New("broker and claims identity differ")
				}
				wire, err := claims.Canonical()
				if err != nil {
					return err
				}
				tmp := filepath.Join(recoveryRuntimeDir, "claims.next")
				if err := os.WriteFile(tmp, wire, 0600); err != nil {
					return err
				}
				if err := os.Rename(tmp, filepath.Join(recoveryRuntimeDir, "claims.json")); err != nil {
					return err
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
		}
	}
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := runConfigured(ctx, cfg, discardLogger(), healthServerConfig{readTimeout: time.Second, writeTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
}

type recoveryFileRegister struct {
	mu   sync.Mutex
	path string
}

func (r *recoveryFileRegister) Extension() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(r.path)
	if err == nil && len(data) != runtimemeasure.Size {
		return nil, errors.New("fixture register has invalid width")
	}
	return data, err
}
func (r *recoveryFileRegister) Extend(event []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	if len(old) != runtimemeasure.Size || len(event) != runtimemeasure.Size {
		return errors.New("fixture register has invalid width")
	}
	next := runtimemeasure.Extend([runtimemeasure.Size]byte(old), [runtimemeasure.Size]byte(event))
	return os.WriteFile(r.path, next[:], 0600)
}
