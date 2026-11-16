package nriimagepolicy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func podBrokerPlugin(t *testing.T) *plugin {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &plugin{
		cfg:       &config{Pod: &podConfig{UID: "assigned"}},
		inventory: newAdmissionInventory(t.TempDir()),
		logger:    discardLogger(),
		podBroker: &podCredentialBroker{ctx: ctx, cancel: cancel, bootID: "boot", changes: make(chan struct{}, 1)},
	}
}

func openTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestPreparePodBrokerRefusals(t *testing.T) {
	if err := (&plugin{cfg: &config{}}).preparePodBroker(t.Context(), nil, nil); err != nil {
		t.Fatalf("node role: %v", err)
	}
	for _, tc := range []struct {
		name   string
		client *http.Client
		pull   pullConfig
		state  string
		want   string
	}{
		{name: "no client", want: "no authenticated CDS client"},
		{name: "conflicting CDS source", client: http.DefaultClient,
			pull: pullConfig{URL: "https://cds.example", CDSAddressFile: "/run/cds-address"}, want: "pod broker CDS pins"},
		{name: "missing state", client: http.DefaultClient, state: "missing", want: "open Pod broker state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pull == (pullConfig{}) {
				tc.pull.CDSMeasurementsConfig = testCDSPinFile(t)
			}
			cfg := &config{Pod: &podConfig{}, Allowlist: allowlistConfig{Pull: tc.pull}}
			cfg.WorkloadClaims.SocketDir = filepath.Join(t.TempDir(), tc.state)
			p := &plugin{cfg: cfg}
			if err := p.preparePodBroker(t.Context(), tc.client, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if p.podBroker != nil {
				t.Fatal("a refused broker was installed")
			}
		})
	}
}

// The broker's state must live in memory; a disk-backed directory is refused
// and a RAM-backed one yields a fresh boot identity.
func TestPreparePodBrokerRequiresRAMBackedState(t *testing.T) {
	cfg := &config{Pod: &podConfig{}, Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}}}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	p := &plugin{cfg: cfg}
	err := p.preparePodBroker(t.Context(), http.DefaultClient, nil)
	if err != nil {
		if !strings.Contains(err.Error(), "RAM-backed") || p.podBroker != nil {
			t.Fatalf("disk-backed state: %v, broker %v", err, p.podBroker)
		}
		return
	}
	defer p.closePodBroker()
	if b := p.podBroker; b == nil || len(b.bootID) != 64 || b.client != http.DefaultClient || b.ctx.Err() != nil {
		t.Fatalf("prepared broker: %+v", b)
	}
}

func TestClosePodBrokerStopsTheWorkerAndReleasesItsRoots(t *testing.T) {
	(&plugin{}).closePodBroker()
	p := podBrokerPlugin(t)
	b := p.podBroker
	b.runtime, b.root = openTestRoot(t), openTestRoot(t)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		<-b.ctx.Done()
	}()
	p.closePodBroker()
	if b.ctx.Err() == nil {
		t.Fatal("the broker context outlived close")
	}
	if _, err := b.runtime.Stat("."); err == nil {
		t.Fatal("the runtime root stayed open")
	}
	if _, err := b.root.Stat("."); err == nil {
		t.Fatal("the credential root stayed open")
	}
}

func TestStartPodCredentialsRefusals(t *testing.T) {
	pod := sandboxedPod()
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *plugin)
		want   string
	}{
		{"no broker", func(_ *testing.T, p *plugin) { p.podBroker = nil }, "not initialized"},
		{"ended identity", func(_ *testing.T, p *plugin) { p.podBroker.terminal = errors.New("identity ended") }, "identity ended"},
		{"other sandbox", func(_ *testing.T, p *plugin) {
			p.podBroker.pod = &api.PodSandbox{Id: "other", Uid: pod.Uid}
		}, "pod sandbox changed"},
		{"other UID", func(_ *testing.T, p *plugin) {
			p.podBroker.pod = &api.PodSandbox{Id: pod.Id, Uid: "other"}
		}, "pod sandbox changed"},
		{"reconstructed history", func(_ *testing.T, p *plugin) { p.bootRestart.Store(true) }, "new guest boot is required"},
		{"unopenable volume", func(t *testing.T, p *plugin) { p.podBroker.runtime = openTestRoot(t) }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := podBrokerPlugin(t)
			tc.change(t, p)
			err := p.startPodCredentials(pod, missing)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if b := p.podBroker; b != nil && b.runtime != nil {
				if _, err := b.runtime.Stat(podBrokerMarker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a refused start claimed the boot identity: %v", err)
				}
			}
		})
	}
}

// Once claimed, a later start must still find the same protected volume.
func TestStartPodCredentialsRechecksTheClaimedVolume(t *testing.T) {
	pod := sandboxedPod()
	p := podBrokerPlugin(t)
	p.podBroker.pod = pod
	p.podBroker.root = openTestRoot(t)
	if err := p.startPodCredentials(pod, filepath.Join(t.TempDir(), "volume")); err == nil {
		t.Fatal("an unprotected credential volume was accepted")
	}
}

func TestAfterPodStartRefusalEndsThePodIdentity(t *testing.T) {
	pod := sandboxedPod()
	p := podBrokerPlugin(t)
	p.podBroker = nil
	if err := (podCVM{p: p}).afterStart(pod, "/credentials"); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("got %v", err)
	}
	if !p.podEnded.Load() {
		t.Fatal("a failed credential start left the identity live")
	}
	if err := p.inventory.denial(pod.Id); err == nil {
		t.Fatal("the refusal was not recorded against the sandbox")
	}
}

func TestEndPodIdentitySurvivesAnUnwritableMarker(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := podBrokerPlugin(t)
	p.cfg.Policy.BootMarkerPath = filepath.Join(blocker, "dir", "registered")
	reason := errors.New("revoked")
	p.endPodIdentity(reason)
	if !p.podEnded.Load() || p.podBroker.terminal != reason || p.podBroker.ctx.Err() == nil {
		t.Fatal("an unwritable marker kept the identity alive")
	}
}

func TestPodCredentialWorkerFailureEndsThePodIdentity(t *testing.T) {
	failure := errors.New("issuance failed")
	got := make(chan getcert.GuestConfig, 1)
	oldRun := runGuestCredentials
	runGuestCredentials = func(_ context.Context, guest getcert.GuestConfig) error {
		got <- guest
		return failure
	}
	t.Cleanup(func() { runGuestCredentials = oldRun })

	pod := sandboxedPod()
	p := podBrokerPlugin(t)
	b := p.podBroker
	b.pod, b.client = pod, http.DefaultClient
	p.runPodCredentialWorker()
	b.wg.Wait()

	guest := <-got
	want := workloadclaims.PodClaims{BootID: b.bootID, RuntimePodUID: pod.Uid, SandboxID: pod.Id}.InstanceID()
	if guest.InstanceID != want || guest.HTTPClient != http.DefaultClient || guest.Changes != b.changes {
		t.Fatalf("worker config: %+v", guest)
	}
	if b.terminal != failure || !p.podEnded.Load() || b.ctx.Err() == nil {
		t.Fatalf("terminal %v, ended %v", b.terminal, p.podEnded.Load())
	}
}

func TestPodSnapshotRefusals(t *testing.T) {
	pod := sandboxedPod()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		change func(*testing.T, *plugin)
		want   string
		ends   bool
	}{
		{name: "canceled request", ctx: canceled, want: context.Canceled.Error()},
		{name: "runtime disconnected", change: func(_ *testing.T, p *plugin) { p.podStartDisconnected.Store(true) }, want: "connection ended"},
		{name: "no broker", change: func(_ *testing.T, p *plugin) { p.podBroker = nil }, want: "no measured Pod endpoint"},
		{name: "unclaimed", change: func(_ *testing.T, p *plugin) { p.podBroker.pod = nil }, want: "no measured Pod endpoint"},
		{name: "ended", change: func(_ *testing.T, p *plugin) { p.podBroker.terminal = errors.New("ended earlier") }, want: "ended earlier"},
		{name: "stopped broker", change: func(_ *testing.T, p *plugin) { p.podBroker.cancel() }, want: context.Canceled.Error()},
		{name: "denied", change: func(_ *testing.T, p *plugin) {
			p.inventory.recordDenial(pod.Id, errors.New("denied start"))
		}, want: "denied start"},
		{name: "volume lost", change: func(t *testing.T, p *plugin) {
			p.podBroker.root = openTestRoot(t)
			p.podBroker.source = filepath.Join(t.TempDir(), "volume")
		}, ends: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := podBrokerPlugin(t)
			p.podBroker.pod = pod
			if tc.change != nil {
				tc.change(t, p)
			}
			ctx := tc.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			claims, err := p.podSnapshot(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) || claims.BootID != "" {
				t.Fatalf("got %+v, %v, want %q", claims, err, tc.want)
			}
			if p.podEnded.Load() != tc.ends {
				t.Fatalf("identity ended: %v, want %v", p.podEnded.Load(), tc.ends)
			}
		})
	}
}

func TestCommitPodCredentialsRefusesADisconnectedRuntime(t *testing.T) {
	p := podBrokerPlugin(t)
	p.podStartDisconnected.Store(true)
	published := false
	err := p.commitPodCredentials(workloadclaims.PodClaims{}, func() error { published = true; return nil })
	if err == nil || published {
		t.Fatalf("publication after the runtime connection ended: %v", err)
	}
}

func TestPodCredentialSourceIsUnusedOutsideThePodRole(t *testing.T) {
	p := &plugin{cfg: &config{}}
	ctr := &api.Container{Mounts: []*api.Mount{readOnlyBind("/var/lib/kubelet/pods/x", "/certs")}}
	if source, err := p.podCredentialSource(sandboxedPod(), ctr, meshRole, nil); source != "" || err != nil {
		t.Fatalf("node role: %q, %v", source, err)
	}
}
