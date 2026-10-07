package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

// bindDeadResolver points the plugin at a real *ctrdresolver.Resolver on a socket
// nobody listens on: construction is lazy, every RPC fails fast with a connection
// error.
func bindDeadResolver(t *testing.T, p *plugin) {
	t.Helper()
	r, err := ctrdresolver.NewResolver(filepath.Join(t.TempDir(), "ctr.sock"), "k8s.io")
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	p.containerd = r
}

// --- plugin.Run via a fake stub ---

// fakeStub embeds the Stub interface so only the methods plugin.Run touches
// need real implementations.
type fakeStub struct {
	stub.Stub
	stopped atomic.Bool
}

func (f *fakeStub) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeStub) Stop() { f.stopped.Store(true) }

func TestPluginRun_StopsOnContextCancel(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	fs := &fakeStub{}
	p.stub = fs

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Run(ctx) }()

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !fs.stopped.Load() {
		if time.Now().After(deadline) {
			t.Fatal("stub.Stop was not called on context cancellation")
		}
		time.Sleep(time.Millisecond)
	}
}

// --- RemoveContainer / Configure with inventory ---

func TestRemoveContainer_EvictsFromInventory(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.record(cidApp1, "sandbox-1", "app", digestApp, nil, nil)

	ctr := &api.Container{Id: cidApp1, PodSandboxId: "sandbox-1", Name: "app"}
	if err := p.RemoveContainer(context.Background(), &api.PodSandbox{Id: "sandbox-1"}, ctr); err != nil {
		t.Fatalf("RemoveContainer: %v", err)
	}
	if _, ok := p.inventory.containers[cidApp1]; ok {
		t.Fatal("container not evicted from the inventory")
	}
}

func TestConfigure_InventoryAddsRemoveContainerMask(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.inventory = newAdmissionInventory(t.TempDir())

	mask, err := p.Configure(context.Background(), "", "containerd", "1.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var want api.EventMask
	want.Set(api.Event_CREATE_CONTAINER)
	want.Set(api.Event_START_CONTAINER)
	want.Set(api.Event_VALIDATE_CONTAINER_ADJUSTMENT)
	want.Set(api.Event_REMOVE_CONTAINER)
	// The inventory also needs the pod-sandbox lifecycle for its sandbox set.
	want.Set(api.Event_RUN_POD_SANDBOX)
	want.Set(api.Event_REMOVE_POD_SANDBOX)
	if mask != want {
		t.Fatalf("mask = %v, want %v", mask, want)
	}
}

// --- resolver-error paths (containerd socket nobody listens on) ---

func TestCheckImage_ResolveFails_Denies(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	bindDeadResolver(t, p)

	// The containerd RPC blocks until the dial deadline; bound it so the
	// failure path is exercised without a multi-second wait.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	verdict, reason := p.checkImagePhase(ctx, p.cfg, imageCheck{
		Namespace: "default",
		PodName:   "pod",
		Container: "ctr",
		ImageRef:  "registry/repo:latest",
		Mounts:    []allowlist.ObservedMount{},
	}, launchFinal)
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny when digest resolution fails, got %d", verdict)
	}
	if !strings.Contains(reason, "cannot resolve digest") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestRecordForInventory_ResolveFails_RecordsEmptyDigest(t *testing.T) {
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}},
		anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	bindDeadResolver(t, p)
	p.inventory = newAdmissionInventory(t.TempDir())

	ctr := &api.Container{Id: "ctr-id", PodSandboxId: "sandbox-1", Name: "app"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.recordForInventory(ctx, nil, ctr, "registry/repo:latest")

	rec, ok := p.inventory.containers["ctr-id"]
	if !ok {
		t.Fatal("container not recorded for the inventory")
	}
	if rec.digest != "" {
		t.Fatalf("recorded digest = %q, want empty (fail-closed at query time)", rec.digest)
	}
}

// writeConfigYAML writes a config file and returns its path.
func writeConfigYAML(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWithDeadline runs Run in a goroutine and fails the test if it does not
// return within timeout.
func runWithDeadline(t *testing.T, timeout time.Duration, args []string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Run(args) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatal("Run did not return within the deadline")
		return nil
	}
}

// baseConfigYAML is a minimal valid config: a static base allowlist only, a containerd
// socket nobody listens on (resolution is lazy), and a health server on a
// private unix socket. In the test environment the NRI socket does not exist,
// so a full Run always ends with the plugin failing to register.
func baseConfigYAML(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      image-a-000000000000:
        label: image-a
        containers:
          - digest: "%s"
            image: image-a
            command: {policy: any}
            args: {policy: any}
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, dir, pushDigestA)
}

// --- Run: startup plumbing --------------------------------------------------

func TestRun_MissingConfigFileErrors(t *testing.T) {
	err := runWithDeadline(t, 10*time.Second, []string{
		"-config", filepath.Join(t.TempDir(), "absent.yaml"),
	})
	if err == nil || !strings.Contains(err.Error(), "load config") {
		t.Fatalf("err = %v, want a load-config failure", err)
	}
}

// A valid config carries Run all the way to the NRI registration, whose
// failure (no NRI socket here) must surface as the plugin error, proving no
// earlier startup step misreported success as failure.
func TestRun_NRIConnectFailureSurfacesAsPluginError(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	err := runWithDeadline(t, 15*time.Second, []string{
		"-config", writeConfigYAML(t, baseConfigYAML(t)),
	})
	if err == nil || !strings.HasPrefix(err.Error(), "plugin: ") {
		t.Fatalf("err = %v, want the NRI plugin run failure", err)
	}
}

// The config file's health_addr must win over the flag default: an invalid
// config address has to fail the health server start rather than being
// silently ignored in favor of the flag.
func TestRun_ConfigHealthAddrOverridesFlagDefault(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: "###not-an-addr###"
containerd:
  socket: %s/ctr.sock
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      image-a-000000000000:
        label: image-a
        containers:
          - digest: "%s"
            image: image-a
            command: {policy: any}
            args: {policy: any}
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, pushDigestA)
	err := runWithDeadline(t, 10*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if err == nil || !strings.Contains(err.Error(), "start health server") {
		t.Fatalf("err = %v, want a health server start failure on the config address", err)
	}
}

// With workload_claims configured, a broker that cannot listen must fail Run:
// continuing without it would leave every get-cert fetch unanswered.
func TestRun_WorkloadClaimsListenFailureSurfaces(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      image-a-000000000000:
        label: image-a
        containers:
          - digest: "%s"
            image: image-a
            command: {policy: any}
            args: {policy: any}
policy:
  mode: fail-closed
  enforce_existing: false
workload_claims:
  socket_dir: %s/absent/deeper
logging:
  level: error
`, dir, dir, pushDigestA, dir)
	err := runWithDeadline(t, 10*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if err == nil || !strings.Contains(err.Error(), "start admission inventory") {
		t.Fatalf("err = %v, want an admission-inventory start failure", err)
	}
}

// A plugin death during the initial pull is fatal (errPluginDied), not a
// degrade-to-base condition.
func TestRun_PluginDeathDuringInitialPullIsFatal(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	origDelay, origRetries := allowlistApiInitialDelay, allowlistApiMaxRetries
	allowlistApiInitialDelay = 5 * time.Millisecond
	// Keep retrying until the plugin death is observed; each fetch attempt
	// fails instantly against the closed port.
	allowlistApiMaxRetries = 1000
	defer func() {
		allowlistApiInitialDelay, allowlistApiMaxRetries = origDelay, origRetries
	}()

	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      image-a-000000000000:
        label: image-a
        containers:
          - digest: "%s"
            image: image-a
            command: {policy: any}
            args: {policy: any}
  pull:
    url: https://127.0.0.1:1/
    attestation_api_url: http://127.0.0.1:1
    cds_measurements: ["%s"]
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, dir, pushDigestA, strings.Repeat("ab", 48))
	err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("err = %v, want errPluginDied", err)
	}
}

// A CDS that is merely slow must not be read as a shutdown request. Every
// initial-pull attempt carries its own deadline, so exhausting the retries
// against an unresponsive endpoint returns an error wrapping
// context.DeadlineExceeded while the process context is still live. Treating
// that as SIGTERM parked the process on the plugin error channel: never ready,
// never pulling again, and only a containerd restart cleared it. Run must take
// the fail-soft path instead and surface the plugin's own failure.
func TestRun_SlowCDSDuringInitialPullIsNotShutdown(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	origDelay, origRetries := allowlistApiInitialDelay, allowlistApiMaxRetries
	allowlistApiInitialDelay = 5 * time.Millisecond
	allowlistApiMaxRetries = 1
	defer func() {
		allowlistApiInitialDelay, allowlistApiMaxRetries = origDelay, origRetries
	}()

	// Both endpoints accept and then hang, so an attempt expires on its own
	// deadline instead of being refused: connection-refused is a plain error
	// and would never have reached the branch under test.
	blocked := make(chan struct{})
	defer close(blocked)
	stalledAttestation := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	defer stalledAttestation.Close()
	stalledCDS := stalledListener(t, blocked)

	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      image-a-000000000000:
        label: image-a
        containers:
          - digest: "%s"
            image: image-a
            command: {policy: any}
            args: {policy: any}
  pull:
    url: https://%s/
    attestation_api_url: %s
    cds_measurements: ["%s"]
    interval: 30s
    timeout: 300ms
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, dir, pushDigestA, stalledCDS, stalledAttestation.URL, strings.Repeat("ab", 48))

	// Hand the stub a connected socket so the plugin cannot die while the pull
	// is running: without it the NRI dial fails instantly, pullInitial's first
	// select sees the error, and the run ends as errPluginDied having never
	// reached the branch under test. Registration then stalls for its own 5s
	// timeout — far longer than the 300ms pull — so the pull deterministically
	// exhausts its retries first and the plugin failure is what Run reports.
	holdNRISocket(t)

	err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if err == nil {
		t.Fatal("Run returned nil: a stalled initial pull was misread as shutdown")
	}
	if errors.Is(err, errPluginDied) {
		t.Fatalf("plugin died during the pull, so the stalled-pull branch never ran: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "plugin: ") {
		t.Fatalf("err = %v, want the NRI plugin run failure", err)
	}
}

// holdNRISocket points the NRI stub at one end of a socketpair via
// NRI_PLUGIN_SOCKET, which stub.connect adopts instead of dialing. Nothing
// serves the peer end, so registration blocks until its timeout rather than
// failing on connect. The socket stays up for the whole test: the stub holds a
// dup of the adopted end, and closing the peer end would make registration fail
// immediately and restore the race.
func holdNRISocket(t *testing.T) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	// nri's NewFdConn dups the adopted descriptor and closes the original, so
	// fds[0] belongs to the stub from here on and its number is recycled: the
	// test owns only the peer end.
	t.Cleanup(func() { _ = syscall.Close(fds[1]) })
	t.Setenv(api.PluginSocketEnvVar, strconv.Itoa(fds[0]))
}

// --- allowlistPullHTTPClient ------------------------------------------------

func TestAllowlistPullHTTPClient_ValidMeasurements(t *testing.T) {
	timeout := 7 * time.Second
	client, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{strings.Repeat("ab", 48)},
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           timeout,
	}, "sev-snp")
	if err != nil {
		t.Fatalf("allowlistPullHTTPClient: %v", err)
	}
	if client == nil || client.Timeout != timeout {
		t.Fatalf("client = %+v, want non-nil with Timeout %v", client, timeout)
	}
}

// The accept-any-measurement warning is a security signal: it must fire
// exactly when no measurement is pinned.
func TestAllowlistPullHTTPClient_WarnsOnlyWithoutPins(t *testing.T) {
	const warning = "accepts any armTLS-attested CDS measurement"
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(orig)

	if _, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{strings.Repeat("ab", 48)},
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           time.Second,
	}, "sev-snp"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), warning) {
		t.Fatal("pinned measurements must not warn about accepting any measurement")
	}

	buf.Reset()
	if _, err := allowlistPullHTTPClient(pullConfig{
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           time.Second,
	}, "sev-snp"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), warning) {
		t.Fatal("missing warning when no measurements are pinned")
	}
}

// --- pullInitial backoff ----------------------------------------------------

// Failed attempts must be separated by the configured startup backoff; a zero
// gap would hammer CDS on every cold boot across the fleet.
func TestPullInitial_BacksOffBetweenAttempts(t *testing.T) {
	origRetries := allowlistApiMaxRetries
	allowlistApiMaxRetries = 2
	defer func() { allowlistApiMaxRetries = origRetries }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: time.Second})
	store := newPolicyStore(nil)

	start := time.Now()
	_, err := pullInitial(context.Background(), pullArgs{
		client:      client,
		store:       store,
		timeout:     time.Second,
		pluginErrCh: make(chan error, 1),
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected failure from a 5xx CDS")
	}
	// One inter-attempt gap at the default 2s backoff (with slack).
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("attempts not separated by the startup backoff: elapsed %v", elapsed)
	}
}

// --- newPlugin: workload-claims wiring ---------------------------------------

func TestNewPlugin_WorkloadClaimsWiring(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	store := newPolicyStore(nil)
	for _, tc := range []struct {
		name         string
		socketDir    string
		procRoot     string
		wantBroker   bool
		wantProcRoot string
	}{
		{"broker disabled without socket dir", "", "", false, ""},
		{"default proc root", "/run/c8s", "", true, "/proc"},
		{"explicit proc root", "/run/c8s", "/hostproc", true, "/hostproc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config{
				Policy:         policyConfig{Mode: ModeFailClosed},
				WorkloadClaims: workloadClaimsConfig{SocketDir: tc.socketDir, ProcRoot: tc.procRoot},
			}
			p, err := newPlugin(cfg, &fakeContainerd{}, store, audit.NewLogger(), discardLogger())
			if err != nil {
				t.Fatalf("newPlugin: %v", err)
			}
			if (p.inventory != nil) != tc.wantBroker {
				t.Fatalf("inventory configured = %v, want %v", p.inventory != nil, tc.wantBroker)
			}
			if tc.wantBroker && p.inventory.procRoot != tc.wantProcRoot {
				t.Fatalf("procRoot = %q, want %q", p.inventory.procRoot, tc.wantProcRoot)
			}
		})
	}
}

// --- checkExisting: enforcement accounting -----------------------------------

// The completion summary is the operator's record of startup enforcement:
// a kill that could not be delivered must count as failed, not killed.
func TestCheckExisting_CountsFailedKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	bindDeadResolver(t, p)
	var buf bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	p.SetReady()

	pod := makePod("default", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{denied}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	type summaryRecord struct {
		Msg    string `json:"msg"`
		Killed int    `json:"killed"`
		Failed int    `json:"failed"`
	}
	var summary *summaryRecord
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec summaryRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec.Msg == "existing-container check complete" {
			summary = &rec
		}
	}
	if summary == nil {
		t.Fatal("completion summary not logged")
	}
	if summary.Killed != 0 || summary.Failed != 1 {
		t.Fatalf("killed=%d failed=%d, want killed=0 failed=1 for an undeliverable kill",
			summary.Killed, summary.Failed)
	}
}

// --- healthListener / startHealthServer ---

func TestHealthListener_TCP(t *testing.T) {
	l, err := healthListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()
	if l.Addr().Network() != "tcp" {
		t.Fatalf("expected tcp listener, got %q", l.Addr().Network())
	}
}

func TestHealthListener_TCPInvalidAddr(t *testing.T) {
	if _, err := healthListener("not-a-valid-addr"); err == nil {
		t.Fatal("expected error for invalid TCP address")
	}
}

func TestHealthListener_Unix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	l, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()
	if l.Addr().Network() != "unix" {
		t.Fatalf("expected unix listener, got %q", l.Addr().Network())
	}
}

func TestHealthListener_UnixRemovesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	// Bind once and close to leave a stale socket file behind.
	l1, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	l1.Close()
	// Re-bind must succeed (stale file removed before listen).
	l2, err := healthListener("unix://" + sock)
	if err != nil {
		t.Fatalf("rebind over stale socket: %v", err)
	}
	l2.Close()
}

func TestStartHealthServer_HealthzReflectsReadiness(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	addr := "unix://" + sock

	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startHealthServer(ctx, healthServerConfig{
		logger:       discardLogger(),
		plugin:       p,
		addr:         addr,
		readTimeout:  time.Second,
		writeTimeout: time.Second,
	}); err != nil {
		t.Fatalf("startHealthServer: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	// Not ready yet → 503.
	resp, err := httpClient.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET /healthz (not ready): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, want 503", resp.StatusCode)
	}

	p.SetReady()
	resp2, err := httpClient.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET /healthz (ready): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d, want 200", resp2.StatusCode)
	}

	cancel()
}

func TestStartHealthServer_InvalidAddr(t *testing.T) {
	ctx := t.Context()
	err := startHealthServer(ctx, healthServerConfig{
		logger:       discardLogger(),
		plugin:       &plugin{},
		addr:         "not-a-valid-addr",
		readTimeout:  time.Second,
		writeTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestAllowlistPullHTTPClient_InvalidMeasurements(t *testing.T) {
	_, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{"not-hex"},
		AttestationApiURL: "http://localhost:30840",
		Timeout:           time.Second,
	}, "sev-snp")
	if err == nil {
		t.Fatal("expected error for invalid CDS measurements")
	}
}

// stalledListener accepts TCP connections and holds them open without ever
// speaking, so a client dialing it hangs until its own deadline fires. It
// returns the host:port to dial.
func stalledListener(t *testing.T, done <-chan struct{}) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}
