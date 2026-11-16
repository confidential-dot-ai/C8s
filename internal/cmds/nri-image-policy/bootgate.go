package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/containerd/nri/pkg/api"
)

// On a measured node image nothing proves that no container ran before
// admission existed.
//
// The node image lists this plugin in containerd's required_plugins, so
// containerd refuses to create a container while it is not registered, and
// systemd runs it (nri-image-policy.service). A container already running at
// the first Synchronize since boot means that did not hold, and by then it has
// already executed: stopping it is too late, so the node powers off instead.
//
// A plugin restart is a different event. containerd stays up, its containers
// legitimately keep running, and powering a healthy node off on every restart
// would be an availability hole with no security gain. The gate separates the
// two with a boot-scoped marker on tmpfs: absent means first registration
// since boot, present means restart. On a restart the existing containers are
// re-checked against the allowlist by the ordinary startup check, and a
// container that no longer passes is fatal there.

// fatalAction powers the node off. Replaced in tests.
type fatalAction func() error

// bootGate is the per-plugin state of the check above. A nil *bootGate is a
// disabled gate.
type bootGate struct {
	markerPath string
	logger     *slog.Logger
	powerOff   fatalAction
	// exit ends the process when powering off is not available; a plugin that
	// stays connected would keep admitting containers.
	exit func(code int)
}

// newBootGate returns nil unless the configuration asks for the check.
func newBootGate(cfg *config, logger *slog.Logger) *bootGate {
	if !cfg.Policy.FatalExisting {
		return nil
	}
	return &bootGate{
		markerPath: cfg.Policy.BootMarkerPath,
		logger:     logger,
		powerOff:   powerOff,
		exit:       os.Exit,
	}
}

// check runs at Synchronize. It reports whether this is a plugin restart, in
// which case the caller escalates a denied running container to fatal instead
// of stopping it. On a first registration with containers it does not return.
//
// The marker is written last, once the registration is known to be clean. A
// refused power-off exits the plugin with the marker absent, so a containerd
// restart that relaunches it finds the same containers fatal again instead of
// re-checking them as a restart's.
func (g *bootGate) check(ctx context.Context, p *plugin, pods []*api.PodSandbox, ctrs []*api.Container) (restart bool) {
	if g == nil {
		return false
	}
	first, err := g.firstBoot()
	if err != nil {
		// Unknown which case this is, so take the stricter one: a node whose
		// /run cannot be read is not a node to trust with a lenient path.
		g.logger.Error("cannot read the plugin's first-registration marker; treating this as a first boot",
			"path", g.markerPath, "error", err)
		first = true
	}
	if !first {
		g.logger.Warn("plugin restart: re-checking the containers containerd already runs against the allowlist",
			"containers", len(ctrs))
		return true
	}
	if len(ctrs) > 0 {
		// Not stopped: each has already run on a node whose measurement claims
		// nothing ran before admission, so stopping it would prove nothing. Only
		// the node image sets policy.fatal_existing; a hosted cluster re-checks
		// what it finds against the allowlist and stops what fails
		// (existingcontainers.go).
		for _, attrs := range containerAttrs(ctx, p, pods, ctrs) {
			g.logger.LogAttrs(ctx, slog.LevelError, "container running before admission was in place", attrs...)
		}
		g.fatal("containers were running when the image-policy plugin first registered")
		return false
	}
	if err := g.claimBoot(); err != nil {
		// Without the marker the next registration reads as a first boot and,
		// with containers by then running, powers the node off. A node whose
		// /run cannot be written is not one to keep serving.
		g.logger.Error("cannot record the plugin's first registration", "path", g.markerPath, "error", err)
		g.fatal("cannot record the plugin's first registration")
		return false
	}
	g.logger.Info("first registration since boot: no container exists yet, as a static boot requires")
	return false
}

// fatal powers the node off. In production it does not return: the power-off
// syscall halts the machine. If it is refused — no CAP_SYS_BOOT — the plugin
// exits instead, which leaves containerd's required_plugins blocking every new
// container. That is weaker (what already runs keeps running) but it is the
// strongest action left.
func (g *bootGate) fatal(reason string) {
	g.logger.Error("powering the node off", "reason", reason)
	if err := g.powerOff(); err != nil {
		g.logger.Error("cannot power the node off", "error", err)
	}
	g.exit(1)
}

// firstBoot reports whether the marker is absent. The marker lives on tmpfs,
// so a reboot clears it and a plugin restart does not.
func (g *bootGate) firstBoot() (bool, error) {
	if g.markerPath == "" {
		return false, errors.New("policy.boot_marker_path is empty")
	}
	_, err := os.Stat(g.markerPath)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	return false, err
}

// claimBoot creates the marker exclusively, so a marker that appeared since
// firstBoot is an error rather than a silent overwrite.
func (g *bootGate) claimBoot() error {
	if err := os.MkdirAll(filepath.Dir(g.markerPath), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(g.markerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// containerAttrs describes every running container, one log record each, for
// the operator's post-mortem: what ran is the whole value of the log, since
// the node is about to stop.
func containerAttrs(ctx context.Context, p *plugin, pods []*api.PodSandbox, ctrs []*api.Container) [][]slog.Attr {
	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}
	records := make([][]slog.Attr, 0, len(ctrs))
	for _, ctr := range ctrs {
		imageRef := ctr.GetAnnotations()[annotationImageName]
		attrs := []slog.Attr{
			slog.String("container", ctr.GetName()),
			slog.String("image", imageRef),
			slog.String("digest", p.resolveDigest(ctx, imageRef)),
		}
		if pod := podByID[ctr.GetPodSandboxId()]; pod != nil {
			attrs = append(attrs, slog.String("namespace", pod.GetNamespace()), slog.String("pod", pod.GetName()))
		}
		records = append(records, attrs)
	}
	return records
}

// escalateOnRestart reports whether the startup check's denial should stop the
// node instead of the container.
//
// Only with an authoritative allowlist. After a restart the plugin is Ready on
// the boot floor alone while the first pull is outstanding, and every workload
// admitted from a CDS allowlist is then unknown to it. Powering the node off
// on that would turn a transient CDS outage into a dead node; stopping the
// container, which is what an ungated plugin does, stays the answer until the
// allowlist is the real one. With no pull configured the floor is the real one.
func (p *plugin) escalateOnRestart() bool {
	if p.boot == nil || !p.bootRestart.Load() {
		return false
	}
	if p.cfg.PullEnabled() {
		return false
	}
	return p.policy.current().version > 0
}

// fatalExisting is what checkExisting calls when it denies a container that is
// already running and the gate is on: the container ran, so stopping it would
// only hide the evidence.
func (g *bootGate) fatalExisting(pod *api.PodSandbox, ctr *api.Container) {
	if g == nil {
		return
	}
	g.fatal(fmt.Sprintf("running container %s/%s/%s is not in the allowlist",
		pod.GetNamespace(), pod.GetName(), ctr.GetName()))
}
