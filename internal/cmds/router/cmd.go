// Package router implements the c8s-router image entrypoint (`c8s router`):
// it renders the nginx configuration of the confidential front door from
// typed flags using the template baked into this binary, tests it, starts
// nginx, and reloads it when the credentials nginx serves change. A credential
// that disappears is a withdrawn generation, so the entrypoint exits instead
// of serving on.
package router

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const (
	// configPath is where nginx reads the rendered configuration, on the
	// pod's scratch volume: the image root filesystem is read-only.
	configPath = "/tmp/nginx.conf"
	// A renewal reaches the front door within one tick.
	reloadInterval = 5 * time.Second
)

// NewCmd returns the router subcommand.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "router",
		Short: "Run the confidential front door (renders the nginx configuration and supervises nginx)",
		Long: `router is the c8s-router image entrypoint. It renders the nginx
configuration from the flags below, tests it with nginx -t, starts nginx as its
child, and reloads it when a credential file nginx loads changes. Only typed
values cross this boundary: no flag carries an nginx directive.

A credential file that becomes unreadable is a withdrawn generation: the
process exits so the front door stops serving a certificate C8s took back.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&cfg.SANs, "san", nil, "public hostname the front door answers on, repeatable (empty accepts any name)")
	f.StringVar(&cfg.PublicCertFile, "public-cert", "", "certificate presented to internet clients")
	f.StringVar(&cfg.PublicKeyFile, "public-key", "", "private key for --public-cert")
	f.StringVar(&cfg.CertFile, "cert", "", "member certificate presented to https backends")
	f.StringVar(&cfg.KeyFile, "key", "", "private key for --cert")
	f.StringVar(&cfg.MeshCAFile, "mesh-ca", "", "CA bundle https backends are verified against")
	f.StringVar(&cfg.Backend.Address, "backend", "", "host:port of the catch-all backend (empty publishes no catch-all)")
	f.StringVar(&cfg.Backend.Protocol, "backend-protocol", "http", "protocol for --backend: http for an adopted workload's Service, https otherwise")
	f.StringVar(&cfg.Backend.ServerName, "backend-server-name", "", "SNI and verification name for an https --backend (empty uses its address host)")
	f.StringVar(&cfg.ReadTimeout, "backend-read-timeout", "3600s", "how long nginx waits for --backend between reads and writes, as an nginx time")
	f.StringVar(&cfg.Resolver, "resolver", "", "DNS name or address nginx re-resolves every backend at, per record TTL")
	f.BoolVar(&cfg.ACME, "acme", false, "publish the :80 server whose HTTP-01 location reaches the acme sidecar")

	for _, required := range []string{"public-cert", "public-key", "cert", "key", "mesh-ca", "resolver"} {
		if err := cmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}

	return cmd
}

func run(ctx context.Context, cfg Config) error {
	validated, err := cfg.Validate()
	if err != nil {
		return err
	}
	conf, err := Render(validated)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("write the rendered configuration (the pod mounts a writable volume at /tmp): %w", err)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return supervise(ctx, nginxBinary, configPath, validated.WatchedFiles(), reloadInterval)
}
