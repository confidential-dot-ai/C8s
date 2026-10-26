//go:build linux

package nriimagepolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/adaptation"
	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// assertPodBootstrap receives nodeservices.Prepare's validated output. Only
// paths and the policy transport are rebased: armTLS authentication is tested
// separately, while this test controls outages and exercises real NRI RPCs.
func assertPodBootstrap(t *testing.T, cfg *config, root string, podKey []byte, baseDigest string) {
	t.Helper()
	for _, scenario := range []string{"workload before endpoint", "wrong endpoint argv", "forged container names", "complete bootstrap"} {
		t.Run(scenario, func(t *testing.T) {
			local := *cfg
			runPodBootstrap(t, &local, root, podKey, baseDigest, scenario)
		})
	}
}

func runPodBootstrap(t *testing.T, cfg *config, root string, podKey []byte, baseDigest, scenario string) {
	t.Helper()
	// Keep Unix socket paths below the kernel limit, including on long CI roots.
	dir, err := os.MkdirTemp("", "pod-nri-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg.WorkloadClaims.SocketDir = filepath.Join(dir, "journal")
	cfg.Policy.BootMarkerPath = filepath.Join(dir, "registered")
	cfg.Containerd.Socket = filepath.Join(dir, "containerd.sock")
	cfg.Plugin.HealthAddr = "unix://" + filepath.Join(dir, "health.sock")
	cfg.Allowlist.Pull.CDSMeasurementsConfig = filepath.Join(root, cfg.Allowlist.Pull.CDSMeasurementsConfig)
	cfg.Allowlist.Pull.Timeout = 5 * time.Second
	cfg.Allowlist.Pull.Interval = 20 * time.Millisecond
	pod, credentialSource := preparePodBootstrapRuntime(t, cfg, dir)
	var selected sync.Map
	oldResolver := newContainerdResolver
	newContainerdResolver = func(socket, namespace string) (containerdConnection, error) {
		if socket != cfg.Containerd.Socket || namespace != cfg.Containerd.Namespace {
			return nil, fmt.Errorf("unexpected containerd resolver %s/%s", socket, namespace)
		}
		return &fakeContainerd{verify: func(ctx context.Context, containerID, sandboxID, digest string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			actual, exists := selected.Load(containerID)
			if sandboxID != pod.Id || !exists || actual != digest {
				return fmt.Errorf("selected image mismatch for %s/%s", sandboxID, containerID)
			}
			return nil
		}}, nil
	}
	t.Cleanup(func() { newContainerdResolver = oldResolver })
	if !cfg.Measure.RTMR3 || cfg.Allowlist.Pull.MeasurePolicies || !cfg.PullEnabled() {
		t.Fatal("prepared policy must measure workloads and poll CDS")
	}

	reg := &fakeRegister{value: runtimemeasure.Seed(podKey)}
	oldKey, oldOpen, oldRetries := readOperatorKey, openRegister, allowlistApiMaxRetries
	readOperatorKey = func() ([]byte, error) { return podKey, nil }
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return reg, nil }
	allowlistApiMaxRetries = 1
	t.Cleanup(func() {
		readOperatorKey, openRegister, allowlistApiMaxRetries = oldKey, oldOpen, oldRetries
	})
	brokerStarted := make(chan getcert.GuestConfig, 1)
	oldGuest := runGuestCredentials
	runGuestCredentials = func(ctx context.Context, guest getcert.GuestConfig) error {
		brokerStarted <- guest
		<-ctx.Done()
		return nil
	}
	t.Cleanup(func() { runGuestCredentials = oldGuest })

	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "served"}))
	firstPull := make(chan struct{})
	releasePull := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releasePull) }) }
	defer release()
	var pulls, failures atomic.Int64
	var available atomic.Bool
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pulls.Add(1) == 1 {
			close(firstPull)
			select {
			case <-releasePull:
			case <-r.Context().Done():
				return
			}
		}
		if !available.Load() {
			failures.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"1"`)
		_, _ = w.Write(body)
	}))
	defer cds.Close()
	// The source config was already validated as HTTPS. Keep TLS identity
	// coverage in the armTLS test and use HTTP here to control pull timing.
	cfg.Allowlist.Pull.URL = cds.URL

	registered := make(chan struct{})
	nri := startPodNRIRuntime(t, dir, registered)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- runConfigured(ctx, cfg, discardLogger(), healthServerConfig{
			readTimeout: time.Second, writeTimeout: time.Second,
		})
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Errorf("stop configured runner: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("configured runner did not stop")
		}
		stopped = true
	}
	defer stop()
	wait := func(label string, condition func() bool) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for !condition() {
			select {
			case err := <-finished:
				stopped = true
				t.Fatalf("runner exited before %s: %v", label, err)
			case <-deadline:
				t.Fatalf("timed out waiting for %s", label)
			case <-tick.C:
			}
		}
	}
	closed := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	wait("NRI synchronization", func() bool { return closed(registered) })
	wait("first CDS pull", func() bool { return closed(firstPull) })

	injectedPod(pod) // Forged injection metadata must not enable node services.
	if err := nri.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod}); err != nil {
		t.Fatal(err)
	}
	// A structural denial ends this guest's issuance authority, so each
	// negative case has its own fresh runtime and boot identity.
	if scenario == "workload before endpoint" {
		if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: podBootstrapContainer(pod, "early", "app", baseDigest)}); err == nil {
			t.Fatal("a workload was admitted before the pod's mesh endpoint")
		}
		return
	}
	start := func(ctr *api.Container) *api.Container {
		t.Helper()
		response, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr})
		if err != nil {
			t.Fatalf("create %s: %v", ctr.Name, err)
		}
		if len(response.GetAdjust().GetMounts()) != 0 {
			t.Fatalf("container %s received guest service mounts: %v", ctr.Name, response.GetAdjust().GetMounts())
		}
		// The NRI runtime fixture commits the selected image before Start.
		// Containerd content/snapshot verification has separate RPC coverage.
		selected.Store(ctr.Id, extractDigest(ctr.Annotations[annotationImageName]))
		if err := nri.StartContainer(ctx, &api.StartContainerRequest{Pod: pod, Container: ctr}); err != nil {
			t.Fatalf("start %s: %v", ctr.Name, err)
		}
		return ctr
	}
	create := func(id, name, digest string) *api.Container {
		return start(podBootstrapContainer(pod, id, name, digest))
	}
	var meshDigest string
	for _, workload := range cfg.Allowlist.Base.Workloads {
		for _, container := range workload.Containers {
			if container.Role != meshRole {
				continue
			}
			meshDigest = container.Digest.String()
			mesh := podBootstrapContainer(pod, "endpoint", workloadclaims.MeshContainerName, meshDigest)
			mesh.Args = slices.Concat(container.Command.Argv, container.Args.Argv)
			mesh.User = &api.User{Uid: workloadclaims.MeshUID, Gid: workloadclaims.MeshUID}
			mesh.Mounts = append(mesh.Mounts, readOnlyBind(credentialSource, podmesh.CertDir))
			if scenario == "wrong endpoint argv" {
				mesh.Args = mesh.Args[:2]
				if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: mesh}); err == nil {
					t.Fatal("the measured image under another argv was admitted as the mesh endpoint")
				}
				return
			}
			start(mesh)
		}
	}
	if meshDigest == "" {
		t.Fatal("prepared policy has no measured mesh endpoint")
	}
	var guest getcert.GuestConfig
	select {
	case guest = <-brokerStarted:
	case <-ctx.Done():
		t.Fatal("guest broker did not start after the measured endpoint")
	}
	first, err := guest.Snapshot(ctx)
	if err != nil || len(first.Containers) != 1 || first.Containers[0].Role != meshRole || !slices.Equal(first.RuntimeExtensions, []string{meshDigest}) {
		t.Fatalf("first broker snapshot = %+v, %v", first, err)
	}
	if err := guest.Commit(first, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if scenario == "forged container names" {
		for i, name := range []string{workloadclaims.CertContainerName, workloadclaims.SecretContainerName, workloadclaims.VolumeContainerName, workloadclaims.AttestContainerName} {
			ctr := podBootstrapContainer(pod, fmt.Sprintf("forged-%d", i), name, baseDigest)
			if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr}); err == nil {
				t.Fatalf("undeclared container %s obtained guest admission", name)
			}
		}
		if _, err := guest.Snapshot(ctx); err == nil {
			t.Fatal("broker asserted identity after an undeclared container request")
		}
		return
	}
	// This start completes while the first pull is still blocked.
	create("base", "app", baseDigest)
	published := false
	if err := guest.Commit(first, func() error { published = true; return nil }); err == nil || published {
		t.Fatal("credential publication accepted the snapshot from before workload admission")
	}
	unknown := podBootstrapContainer(pod, "unknown", "unknown", baseDigest)
	unknown.Mounts = append(unknown.Mounts, readOnlyBind("/unlisted-host-content", "/unlisted"))
	if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: unknown}); err == nil {
		t.Fatal("undeclared host mount admitted during first pull")
	}
	if _, err := guest.Snapshot(ctx); err == nil {
		t.Fatal("bootstrap broker asserted identity with an unresolved pre-ready creation refusal")
	}
	create("unknown-initial-retry", "unknown", baseDigest)
	if _, err := guest.Snapshot(ctx); err != nil {
		t.Fatalf("bootstrap broker did not recover after that same name was admitted: %v", err)
	}
	if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: podBootstrapContainer(pod, "served-before-pull", "served", pushDigestB)}); err == nil {
		t.Fatal("a staged image pin bypassed the allowlist before its first pull")
	}
	release()
	healthClient := unixHealthClient(filepath.Join(dir, "health.sock"))
	defer healthClient.CloseIdleConnections()
	waitHealth := func(version uint64) {
		t.Helper()
		wait(fmt.Sprintf("healthy policy version %d", version), func() bool {
			response, err := healthClient.Get("http://unix/healthz")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			var body healthResponse
			return json.NewDecoder(response.Body).Decode(&body) == nil && response.StatusCode == http.StatusOK && body.AllowlistVersion == version
		})
	}
	waitHealth(0)
	for _, destination := range []string{workloadclaims.SidecarSocketDir, workloadclaims.CDSPinsPath, workloadclaims.CDSAddressPath} {
		ctr := podBootstrapContainer(pod, "forged-mount", "app", baseDigest)
		ctr.Mounts = append(ctr.Mounts, readOnlyBind(cfg.WorkloadClaims.SocketDir, destination))
		if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr}); err == nil {
			t.Fatalf("forged container gained a guest bind at %s", destination)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.WorkloadClaims.SocketDir, workloadclaims.SocketName)); !os.IsNotExist(err) {
		t.Fatalf("Pod journal unexpectedly exposes an inventory socket: %v", err)
	}

	available.Store(true)
	waitHealth(1)
	create("served", "served", pushDigestB)
	before := failures.Load()
	available.Store(false)
	wait("failed refresh", func() bool { return failures.Load() > before })
	waitHealth(1)
	create("cached", "cached", pushDigestB)
	create("base-after-pull", "app", baseDigest)
	// A transient Create refusal is lifted only by admitting that same name.
	create("mount-now-admitted", "app", baseDigest)
	claims, err := guest.Snapshot(ctx)
	if err != nil || len(claims.Containers) < 3 || !slices.Equal(claims.RuntimeExtensions, []string{meshDigest, baseDigest, pushDigestB}) {
		t.Fatalf("complete broker snapshot = %+v, %v", claims, err)
	}
	if err := nri.RemovePodSandbox(ctx, &api.RemovePodSandboxRequest{Pod: pod}); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Snapshot(ctx); err == nil {
		t.Fatal("broker retained identity after losing sandbox history")
	}
	stop()

	data, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(data)); !slices.Equal(got, []string{meshDigest, baseDigest, pushDigestB}) {
		t.Fatalf("journal = %v; want only started workload digests", got)
	}
	want := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(podKey), []string{meshDigest, baseDigest, pushDigestB})
	if reg.value != want {
		t.Fatal("runtime register does not match Pod launch key plus started workloads")
	}
}

func podBootstrapContainer(pod *api.PodSandbox, id, name, digest string) *api.Container {
	ctr := sandboxedContainer()
	ctr.Id, ctr.Name, ctr.PodSandboxId = id, name, pod.Id
	ctr.Args = []string{"/app/workload", name}
	ctr.Env = []string{}
	ctr.User = &api.User{Uid: workloadclaims.CredentialsUID}
	ctr.Annotations = map[string]string{annotationImageName: "image@" + digest}
	ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
		return m.Destination == serviceAccountDestination
	})
	for _, m := range ctr.Mounts {
		m.Source = strings.ReplaceAll(m.Source, testPodUID, pod.Uid)
	}
	ctr.Linux.Namespaces = append(ctr.Linux.Namespaces, &api.LinuxNamespace{Type: "pid"})
	return ctr
}

func startPodNRIRuntime(t *testing.T, dir string, registered chan<- struct{}) *adaptation.Adaptation {
	t.Helper()
	var once sync.Once
	nri, err := adaptation.New("pod-bootstrap-test", "1", func(ctx context.Context, cb adaptation.SyncCB) error {
		_, err := cb(ctx, nil, nil)
		if err == nil {
			once.Do(func() { close(registered) })
		}
		return err
	}, func(context.Context, []*api.ContainerUpdate) ([]*api.ContainerUpdate, error) {
		return nil, nil
	}, adaptation.WithPluginPath(filepath.Join(dir, "plugins")), adaptation.WithPluginConfigPath(filepath.Join(dir, "config")), adaptation.WithSocketPath(filepath.Join(dir, "nri.sock")))
	if err != nil {
		t.Fatal(err)
	}
	if err := nri.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nri.Stop)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "nri.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	file, err := conn.File()
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	// The stub takes ownership and closes this descriptor on adoption.
	t.Setenv("NRI_PLUGIN_NAME", "")
	t.Setenv(api.PluginSocketEnvVar, strconv.Itoa(fd))
	return nri
}
