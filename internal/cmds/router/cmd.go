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
	"strconv"
	"strings"
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
	var routes []string
	cmd := &cobra.Command{
		Use:   "router",
		Short: "Run the confidential front door (renders the nginx configuration and supervises nginx)",
		Long: `router is the c8s-router image entrypoint. It renders the nginx
configuration from the flags below, tests it with nginx -t, starts nginx as its
child, and reloads it when a credential file nginx loads changes. Only typed
values cross this boundary: no flag carries an nginx directive.

Each --route takes comma-separated fields: path (required), backend
(host:port, required), match (exact or prefix, default prefix), server-name
(default the backend address host), cors (default true). A route reaches its
backend over https, inside the cluster.

A credential file that becomes unreadable is a withdrawn generation: the
process exits so the front door stops serving a certificate C8s took back.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			parsed, err := parseRoutes(routes)
			if err != nil {
				return err
			}
			cfg.Routes = parsed
			if err := requireOriginsForCORS(cmd); err != nil {
				return err
			}
			return run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&cfg.SANs, "san", nil, "public hostname the front door answers on, repeatable (empty accepts any name)")
	f.StringVar(&cfg.PublicCertFile, "public-cert", "", "certificate presented to internet clients")
	f.StringVar(&cfg.PublicKeyFile, "public-key", "", "private key for --public-cert")
	f.StringVar(&cfg.CertFile, "cert", "", "member certificate served at the discovery certificate path and presented to https backends")
	f.StringVar(&cfg.KeyFile, "key", "", "private key for --cert")
	f.StringVar(&cfg.MeshCAFile, "mesh-ca", "", "CA bundle https backends are verified against, and served at --discovery-mesh-ca-path")
	f.StringVar(&cfg.Backend.Address, "backend", "", "host:port of the catch-all backend (empty publishes no catch-all)")
	f.StringVar(&cfg.Backend.Protocol, "backend-protocol", "http", "protocol for --backend: http for an adopted workload's Service, https otherwise")
	f.StringVar(&cfg.Backend.ServerName, "backend-server-name", "", "SNI and verification name for an https --backend (empty uses its address host)")
	f.StringVar(&cfg.ReadTimeout, "backend-read-timeout", "3600s", "how long nginx waits for --backend between reads and writes, as an nginx time")
	f.StringVar(&cfg.Resolver, "resolver", "", "DNS name or address nginx re-resolves every backend at, per record TTL (required with a backend or a route)")
	f.StringArrayVar(&routes, "route", nil, "path published ahead of the catch-all, repeatable (see above)")
	f.IntVar(&cfg.AttestPort, "attest-port", 0, "loopback port of the attestation sidecar serving /readyz and /.well-known/c8s/ (0 publishes neither)")
	f.IntVar(&cfg.Allowlist.ProxyPort, "allowlist-proxy-port", 0, "loopback port of the allowlist proxy behind /allowlist (0 publishes no allowlist route)")
	f.IntVar(&cfg.Allowlist.WriteRate, "allowlist-write-rate", 1, "allowlist mutations per second per client")
	f.IntVar(&cfg.Allowlist.WriteBurst, "allowlist-write-burst", 5, "allowlist mutation burst per client")
	f.IntVar(&cfg.Allowlist.WriteTotalRate, "allowlist-write-total-rate", 8, "allowlist mutations per second across all clients")
	f.IntVar(&cfg.Allowlist.WriteTotalBurst, "allowlist-write-total-burst", 15, "allowlist mutation burst across all clients")
	f.IntVar(&cfg.Allowlist.ReadRate, "allowlist-read-rate", 20, "allowlist reads per second per client")
	f.IntVar(&cfg.Allowlist.ReadBurst, "allowlist-read-burst", 40, "allowlist read burst per client")
	f.StringVar(&cfg.Discovery.Path, "discovery-path", "", "URI path serving the discovery document (empty publishes no discovery)")
	f.StringVar(&cfg.Discovery.File, "discovery-file", "", "file served at --discovery-path")
	f.StringVar(&cfg.Discovery.CDSCertPath, "discovery-cds-cert-path", "", "URI path serving --cert, which the discovery document chains to")
	f.StringVar(&cfg.Discovery.MeshCAPath, "discovery-mesh-ca-path", "", "URI path serving --mesh-ca")
	f.StringSliceVar(&cfg.CORS.AllowOrigins, "cors-allow-origin", nil, `origin the proxied locations allow, or "*", repeatable (empty states no CORS policy)`)
	f.StringSliceVar(&cfg.CORS.AllowMethods, "cors-allow-method", []string{"GET", "POST", "OPTIONS"}, "method the proxied locations allow, repeatable")
	f.StringSliceVar(&cfg.CORS.AllowHeaders, "cors-allow-header", []string{"Authorization", "Content-Type", "X-C8s-Session"}, "request header the proxied locations allow, repeatable")
	f.StringSliceVar(&cfg.CORS.ExposeHeaders, "cors-expose-header", nil, "response header browsers may read, repeatable")
	f.BoolVar(&cfg.CORS.AllowCredentials, "cors-allow-credentials", false, "allow credentialed cross-origin requests")
	f.IntVar(&cfg.CORS.MaxAge, "cors-max-age", 600, "seconds browsers may cache a preflight response")
	f.BoolVar(&cfg.ACME, "acme", false, "publish the :80 server whose HTTP-01 location reaches the acme sidecar")

	for _, required := range []string{"public-cert", "public-key", "cert", "key", "mesh-ca"} {
		if err := cmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}

	return cmd
}

// parseRoutes turns each --route field list into a typed route.
func parseRoutes(specs []string) ([]Route, error) {
	routes := make([]Route, 0, len(specs))
	for _, spec := range specs {
		route := Route{
			Match: "prefix",
			CORS:  true,
			Backend: Backend{
				Protocol: "https",
			},
		}
		seen := make(map[string]struct{})
		for field := range strings.SplitSeq(spec, ",") {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				return nil, fmt.Errorf("--route %q: field %q must be key=value", spec, field)
			}
			// A repeated key is refused rather than resolved: a second
			// protocol= would otherwise decide the hop's protocol after the
			// first one was admitted.
			if _, repeated := seen[key]; repeated {
				return nil, fmt.Errorf("--route %q: field %q is set twice", spec, key)
			}
			seen[key] = struct{}{}
			if err := setRouteField(&route, key, value); err != nil {
				return nil, fmt.Errorf("--route %q: %w", spec, err)
			}
		}
		if route.Path == "" || route.Backend.Address == "" {
			return nil, fmt.Errorf("--route %q: path and backend are required", spec)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func setRouteField(route *Route, key, value string) error {
	switch key {
	case "path":
		route.Path = value
	case "match":
		route.Match = value
	case "backend":
		route.Backend.Address = value
	case "protocol":
		route.Backend.Protocol = value
	case "server-name":
		route.Backend.ServerName = value
	case "cors":
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("cors must be a boolean, got %q", value)
		}
		route.CORS = enabled
	default:
		return fmt.Errorf("unknown field %q", key)
	}
	return nil
}

// requireOriginsForCORS refuses a policy nothing can apply: without an allowed
// origin the proxied locations carry no CORS headers at all. --cors-max-age is
// not among them; the C8s-owned endpoints answer any origin and use it.
func requireOriginsForCORS(cmd *cobra.Command) error {
	if cmd.Flags().Changed("cors-allow-origin") {
		return nil
	}
	for _, flag := range []string{"cors-allow-method", "cors-allow-header", "cors-expose-header", "cors-allow-credentials"} {
		if cmd.Flags().Changed(flag) {
			return fmt.Errorf("--%s needs --cors-allow-origin, which is what turns the CORS policy on", flag)
		}
	}
	return nil
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
