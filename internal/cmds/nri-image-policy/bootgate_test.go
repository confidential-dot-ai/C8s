package nriimagepolicy

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
)

// fatalRecorder stands in for powering the node off.
type fatalRecorder struct {
	powerOffs int
	exits     []int
	fail      error
}

func (f *fatalRecorder) powerOff() error {
	f.powerOffs++
	return f.fail
}

func (f *fatalRecorder) exit(code int) { f.exits = append(f.exits, code) }

// gatedPlugin returns a plugin with the boot gate armed against a marker in a
// temp dir, plus the recorder its fatal action writes to.
func gatedPlugin(t *testing.T, marker string) (*plugin, *fatalRecorder) {
	t.Helper()
	cfg := gatedConfig(marker)
	p, _ := newCachedPlugin(cfg, cfg.Allowlist.Base)
	rec := &fatalRecorder{}
	p.boot = newBootGate(cfg, slog.Default())
	p.boot.powerOff = rec.powerOff
	p.boot.exit = rec.exit
	return p, rec
}

// gatedConfig is the node image's enforcing shape: fail-closed, a base of one
// digest, and the boot gate armed.
func gatedConfig(marker string) *config {
	return &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
			FatalExisting:         true,
			BootMarkerPath:        marker,
		},
	}
}

// unpulledPlugin is a gated plugin whose allowlist is still the boot base:
// the store is at version 0 because no pull has applied a snapshot.
func unpulledPlugin(cfg *config) *plugin {
	p := &plugin{
		cfg:        cfg,
		policy:     newPolicyStore(cfg.Allowlist.Base),
		audit:      audit.NewLogger(),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		containerd: &fakeContainerd{},
		mesh:       newMeshGate(nil, discardLogger()),
	}
	p.boot = newBootGate(cfg, p.logger)
	return p
}

// deniedContainer is a running container whose image the allowlist does not
// carry.
func deniedContainer(podID, name string) *api.Container {
	ctr := makeCtr(podID, name)
	ctr.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestB}
	return ctr
}

// In a valid static boot no container exists when the plugin registers. One
// that does has already run, so the node stops.
func TestBootGatePowersOffOnContainersAtFirstRegistration(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	p, rec := gatedPlugin(t, marker)
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		return "", errors.New("no store")
	}}

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{makeCtr(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	if rec.powerOffs != 1 {
		t.Errorf("power offs = %d, want 1", rec.powerOffs)
	}
}

// A boot with nothing running is the normal case, and it claims the marker so
// the next registration reads as a restart.
func TestBootGateAcceptsAnEmptyFirstRegistration(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	p, rec := gatedPlugin(t, marker)

	if _, err := p.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}
	if rec.powerOffs != 0 {
		t.Fatalf("an empty first registration powered the node off")
	}
	if p.bootRestart.Load() {
		t.Error("the first registration since boot reported itself as a restart")
	}

	restarted, _ := gatedPlugin(t, marker)
	if _, err := restarted.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize after a restart = %v", err)
	}
	if !restarted.bootRestart.Load() {
		t.Error("a second registration against the same boot marker is a restart")
	}
}

// Containers legitimately outlive a plugin restart: containerd stays up and
// the node is healthy, so the gate must not stop it.
func TestBootGateTreatsARestartAsNonFatal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	first, _ := gatedPlugin(t, marker)
	if _, err := first.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	p, rec := gatedPlugin(t, marker)
	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{makeCtr(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	if rec.powerOffs != 0 {
		t.Errorf("a plugin restart powered a healthy node off")
	}
	if !p.bootRestart.Load() {
		t.Error("a restart did not arm the startup check's escalation")
	}
}

// On a restart the running containers are re-checked, and one the allowlist no
// longer admits is fatal — it has already run, so stopping it proves nothing.
func TestBootGateEscalatesADeniedContainerOnRestart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	first, _ := gatedPlugin(t, marker)
	if _, err := first.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	p, rec := gatedPlugin(t, marker)
	// The fatal action returns here; the real one halts the node before
	// checkExisting could fall through to StopContainer.
	p.containerd = &fakeContainerd{
		resolve: func(context.Context, string) (string, error) { return "", errors.New("no store") },
		stop:    func(context.Context, string) error { return nil },
	}
	p.SetReady()

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{deniedContainer(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	if rec.powerOffs != 1 {
		t.Errorf("power offs = %d, want the denied running container to be fatal", rec.powerOffs)
	}
}

// A restart whose first pull has not landed yet judges against the boot floor
// alone, so a workload CDS admitted earlier looks unknown. That must stop the
// container, as an ungated plugin does — not the node.
func TestBootGateDoesNotEscalateBeforeTheFirstPull(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	cfg := gatedConfig(marker)
	cfg.Allowlist.Pull = pullConfig{URL: "https://127.0.0.1:30808", Interval: time.Second, Timeout: time.Second}

	first := unpulledPlugin(cfg)
	if _, err := first.Synchronize(context.Background(), nil, nil); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}

	// No pull has applied a snapshot, so the store is at version 0.
	p := unpulledPlugin(cfg)
	rec := &fatalRecorder{}
	p.boot.powerOff, p.boot.exit = rec.powerOff, rec.exit
	stopped := 0
	p.containerd = &fakeContainerd{
		resolve: func(context.Context, string) (string, error) { return "", errors.New("no store") },
		stop:    func(context.Context, string) error { stopped++; return nil },
	}
	p.SetReady()

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{deniedContainer(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}
	if rec.powerOffs != 0 {
		t.Errorf("a restart before the first pull powered the node off")
	}
	if stopped != 1 {
		t.Errorf("stopped %d containers, want the denied one stopped", stopped)
	}
}

// Without the setting the gate is absent, so the chart's containerised plugin
// keeps stopping violations instead of stopping nodes.
func TestBootGateOffByDefault(t *testing.T) {
	cfg := gatedConfig("")
	cfg.Policy.FatalExisting = false
	if g := newBootGate(cfg, slog.Default()); g != nil {
		t.Fatalf("newBootGate = %+v, want nil without policy.fatal_existing", g)
	}
	p, _ := newCachedPlugin(cfg, cfg.Allowlist.Base)
	stopped := 0
	p.containerd = &fakeContainerd{
		resolve: func(context.Context, string) (string, error) { return "", errors.New("no store") },
		stop:    func(context.Context, string) error { stopped++; return nil },
	}
	p.SetReady()

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{deniedContainer(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}
	if stopped != 1 {
		t.Errorf("stopped %d containers, want the ungated plugin to stop the denied one", stopped)
	}
}

// A node whose marker cannot be written is not one to trust with the lenient
// path: an unwritable /run reads as a first boot.
func TestBootGateFailsClosedOnAnUnwritableMarker(t *testing.T) {
	// A regular file where the marker's directory should be: the gate can
	// neither create nor read the marker.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p, rec := gatedPlugin(t, filepath.Join(blocker, "registered"))
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		return "", errors.New("no store")
	}}

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	if _, err := p.Synchronize(context.Background(), pods, []*api.Container{makeCtr(pods[0].Id, "ctr1")}); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}
	if rec.powerOffs != 1 {
		t.Errorf("power offs = %d, want an unwritable marker to fail closed", rec.powerOffs)
	}
}

// Powering off can be refused (no CAP_SYS_BOOT); the plugin must still stop
// serving, because containerd's required_plugins then blocks every create. The
// marker stays absent, so the plugin containerd relaunches finds the same
// containers fatal again rather than re-checking them as a restart's.
func TestBootGateExitsWhenPowerOffFails(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	p, rec := gatedPlugin(t, marker)
	rec.fail = errors.New("operation not permitted")
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		return "", errors.New("no store")
	}}

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}
	if _, err := p.Synchronize(context.Background(), pods, ctrs); err != nil {
		t.Fatalf("Synchronize = %v", err)
	}
	if rec.powerOffs != 1 {
		t.Errorf("power offs = %d, want the gate to try first", rec.powerOffs)
	}
	if len(rec.exits) != 1 || rec.exits[0] != 1 {
		t.Errorf("exits = %v, want a single exit(1) once the power-off is refused", rec.exits)
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(marker) = %v, want the marker absent after a fatal first registration", err)
	}

	relaunched, rec := gatedPlugin(t, marker)
	relaunched.containerd = p.containerd
	if _, err := relaunched.Synchronize(context.Background(), pods, ctrs); err != nil {
		t.Fatalf("Synchronize after relaunch = %v", err)
	}
	if rec.powerOffs != 1 {
		t.Errorf("power offs = %d, want the relaunched plugin to find the same containers fatal", rec.powerOffs)
	}
	if relaunched.bootRestart.Load() {
		t.Error("a relaunch after a fatal first registration reported itself as a restart")
	}
}

// The setting only means something alongside fail-closed enforcement and a
// tmpfs marker.
func TestFatalExistingConfigCouplings(t *testing.T) {
	base := func() *config { return gatedConfig("/run/nri-image-policy/registered") }
	tests := []struct {
		name    string
		mutate  func(*config)
		wantErr string
	}{
		{"valid", func(*config) {}, ""},
		{"audit mode", func(c *config) { c.Policy.Mode = ModeAudit }, "policy.mode"},
		{"without enforce_existing", func(c *config) { c.Policy.EnforceExisting = false }, "enforce_existing"},
		{"relative marker", func(c *config) { c.Policy.BootMarkerPath = "registered" }, "boot_marker_path"},
		{"no marker", func(c *config) { c.Policy.BootMarkerPath = "" }, "boot_marker_path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(cfg)
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error mentioning %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("Validate() = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
