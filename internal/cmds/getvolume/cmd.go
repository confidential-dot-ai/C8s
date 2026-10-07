package getvolume

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// NewCmd returns the cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command {
	var (
		cfg   config
		specs []string
	)
	cmd := &cobra.Command{
		Use:   "get-volume",
		Short: "Fetch this pod's volume keys from CDS and have the node open them",
		Long: `get-volume fetches the key for each encrypted volume a workload is granted
and hands it to the node agent, which opens the device and mounts it into this
pod — read-only for an immutable volume, read-write for a mutable one.

It authenticates with the pod's CDS-issued certificate and a sandbox token
redeemed from the node's admission inventory, and CDS releases only when the
containers running in the sandbox match a workload entry holding a grant for
the requested path. That is only true once every main container is running, so
early attempts are refused and get-volume retries — the volume appears shortly
after the workload starts, and a consumer must wait for it.

The key must already be in the store, put there by ` + "`c8s volume create`" + `.
Nothing here creates one.`,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := cfg.ResolveCDSEndpoint(); err != nil {
				return err
			}
			for _, spec := range specs {
				v, err := parseVolumeSpec(spec)
				if err != nil {
					return err
				}
				cfg.Volumes = append(cfg.Volumes, v)
			}
			return run(cfg)
		},
	}
	f := cmd.Flags()
	sidecar.BindFlags(f, &cfg.Config)
	// This command's timeout also covers the node agent.
	f.Lookup("request-timeout").Usage = "per-request timeout against CDS and the node agent"
	f.StringSliceVar(&specs, "volume", nil, "NAME=/store/path to open; NAME selects the device by serial (repeatable)")
	f.StringVar(&cfg.SocketDir, "socket-dir", workloadclaims.SidecarSocketDir, "directory holding the node agent's socket, as this pod sees it")
	return cmd
}
