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
	"runtime"
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
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// assertPodBootstrap receives nodeservices.Prepare's validated output. Only
// paths and the policy transport are rebased: armTLS authentication is tested
// separately, while this test controls outages and exercises real NRI RPCs.
func assertPodBootstrap(t *testing.T, cfg *config, root string, podKey []byte, baseDigest string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("NRI adaptation uses Linux peer credentials")
	}
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

	pod := sandboxedPod()
	injectedPod(pod) // Forged injection metadata must not enable node services.
	if err := nri.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod}); err != nil {
		t.Fatal(err)
	}
	create := func(id, name, digest string) *api.Container {
		t.Helper()
		ctr := podBootstrapContainer(pod, id, name, digest)
		response, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if len(response.GetAdjust().GetMounts()) != 0 {
			t.Fatalf("container %s received guest service mounts: %v", name, response.GetAdjust().GetMounts())
		}
		if err := nri.StartContainer(ctx, &api.StartContainerRequest{Pod: pod, Container: ctr}); err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		return ctr
	}
	// This start completes while the first pull is still blocked.
	create("base", "app", baseDigest)
	unknown := podBootstrapContainer(pod, "unknown", "unknown", pushDigestC)
	if _, err := nri.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: unknown}); err == nil {
		t.Fatal("unlisted workload admitted during first pull")
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
	for i, name := range []string{workloadclaims.CertContainerName, workloadclaims.SecretContainerName, workloadclaims.VolumeContainerName, workloadclaims.AttestContainerName} {
		create(fmt.Sprintf("forged-%d", i), name, baseDigest)
	}
	for _, destination := range []string{workloadclaims.SidecarSocketDir, workloadclaims.CDSPinsPath, workloadclaims.CDSAddressPath} {
		ctr := podBootstrapContainer(pod, "forged-mount", workloadclaims.CertContainerName, baseDigest)
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
	stop()

	data, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(data)); !slices.Equal(got, []string{baseDigest, pushDigestB}) {
		t.Fatalf("journal = %v; want only started workload digests", got)
	}
	want := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(podKey), []string{baseDigest, pushDigestB})
	if reg.value != want {
		t.Fatal("runtime register does not match Pod launch key plus started workloads")
	}
}

func podBootstrapContainer(pod *api.PodSandbox, id, name, digest string) *api.Container {
	ctr := sandboxedContainer()
	ctr.Id, ctr.Name, ctr.PodSandboxId = id, name, pod.Id
	ctr.User = &api.User{Uid: workloadclaims.CredentialsUID}
	ctr.Annotations = map[string]string{annotationImageName: "image@" + digest}
	ctr.Mounts = slices.DeleteFunc(ctr.Mounts, func(m *api.Mount) bool {
		return m.Destination == serviceAccountDestination
	})
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
