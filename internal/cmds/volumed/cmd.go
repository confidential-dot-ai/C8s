package volumed

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// SocketName is the daemon's socket, created inside the same directory the
// admission inventory uses. That directory is the one the inventory's NRI
// plugin mounts into cw-pod sidecars, so a socket in a second directory would
// be unreachable from every pod that needs it.
const SocketName = "volumed.sock"

type config struct {
	socketDir   string
	kubeletRoot string
	cgroupRoot  string
	// socketGID group-owns the socket so the non-root fetcher sidecar can
	// connect. Not a flag: it must match what the webhook injects as a
	// supplemental group, which is the same compiled constant.
	socketGID    int
	reapInterval time.Duration
	maxMounts    int
}

// NewCmd returns the `c8s volumed` command.
func NewCmd() *cobra.Command {
	cfg := config{socketGID: workloadclaims.InventorySocketGID}
	cmd := &cobra.Command{
		Use:   "volumed",
		Short: "Agent that opens encrypted volumes for entitled pods",
		Long: `volumed opens an encrypted volume for a pod.

An injected sidecar fetches the volume's key from CDS over the attested secrets
flow and hands it to this daemon, which opens the device and mounts the result
into that pod and no other — read-only under dm-verity for an immutable volume,
read-write ext4 for a mutable one.

It runs as a privileged node daemon, resolves the calling pod from kernel peer
credentials, and mounts into its kubelet directory. It runs privileged — opening a device and mounting into a pod's
directory needs it — and where a volume is mounted is never driven by what a
caller says about itself.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, _ []string) error { return runDaemon(cmd.Context(), cfg) },
	}
	f := cmd.Flags()
	// No default: the inventory's socket directory is a chart value, and the
	// in-pod path a sidecar sees it at is not where this daemon serves.
	f.StringVar(&cfg.socketDir, "socket-dir", "",
		"host directory holding the admission inventory's socket, where this daemon creates its own (required)")
	f.StringVar(&cfg.kubeletRoot, "kubelet-root", "/var/lib/kubelet", "kubelet's root directory, holding per-pod volume directories")
	f.StringVar(&cfg.cgroupRoot, "cgroup-root", DefaultCgroupRoot, "cgroup mount, where a pod's slice going away is what triggers teardown")
	f.DurationVar(&cfg.reapInterval, "reap-interval", DefaultReapInterval, "how often to tear down volumes whose pod has gone")
	f.IntVar(&cfg.maxMounts, "max-mounts", DefaultMaxMounts, "maximum volumes open on this node at once")
	return cmd
}

func runDaemon(ctx context.Context, cfg config) error {
	if err := validate(cfg); err != nil {
		return err
	}
	return runNode(ctx, cfg)
}

func runNode(ctx context.Context, cfg config) error {
	// A running kubelet creates <root>/pods before it starts any pod, so its
	// absence means the flag does not name this node's kubelet root dir.
	podsDir := filepath.Join(cfg.kubeletRoot, "pods")
	fi, err := os.Stat(podsDir)
	if err == nil && !fi.IsDir() {
		err = fmt.Errorf("%s is not a directory", podsDir)
	}
	if err != nil {
		return fmt.Errorf("--kubelet-root %q is not the kubelet's root dir on this node: %v", cfg.kubeletRoot, err)
	}

	opener := &Opener{Ops: SystemOps{}, Targets: KubeletTargets{Root: cfg.kubeletRoot}, MaxMounts: cfg.maxMounts}
	srv := &Server{
		Identity: PeerIdentity{},
		Opener:   opener,
		Devices:  SerialDevices{},
		Logger:   slog.Default(),
	}

	l, err := listen(cfg.socketDir, cfg.socketGID)
	if err != nil {
		return err
	}
	defer l.Close()

	// Mappings an earlier volumed left behind hold the backing disk open, so a
	// volume they cover cannot be reopened until they go. Sweep before serving.
	if closed, stuck := opener.SweepStale(ctx); closed > 0 || len(stuck) > 0 {
		slog.Info("swept mappings left by an earlier volumed", "closed", closed, "still_in_use", stuck)
	}

	reaper := &Reaper{
		Opener:   opener,
		Liveness: CgroupLiveness{Root: cfg.cgroupRoot},
		Interval: cfg.reapInterval,
		Logger:   slog.Default(),
	}
	go reaper.Run(ctx)

	slog.Info("serving volume opens", "socket", filepath.Join(cfg.socketDir, SocketName), "kubelet_root", cfg.kubeletRoot)
	return srv.Serve(ctx, l)
}

// listen creates the socket, replacing a stale one left by a previous run and
// group-owning it to gid so the non-root fetcher sidecar can connect.
//
// The directory is the inventory's, and this daemon must not disturb what is
// already there: only its own socket name is touched.
func listen(dir string, gid int) (net.Listener, error) {
	return workloadclaims.ListenUnix(filepath.Join(dir, SocketName), gid)
}

func validate(cfg config) error {
	if cfg.maxMounts <= 0 {
		return fmt.Errorf("--max-mounts must be positive")
	}
	switch {
	case cfg.socketDir == "":
		return fmt.Errorf("--socket-dir is required")
	case cfg.kubeletRoot == "":
		return fmt.Errorf("--kubelet-root is required")
	case cfg.cgroupRoot == "":
		return fmt.Errorf("--cgroup-root is required")
	case cfg.reapInterval <= 0:
		return fmt.Errorf("--reap-interval must be positive")
	}
	return nil
}
