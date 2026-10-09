// Package nriimagepolicy is an NRI plugin that validates container images
// against a digest allowlist. Every plugin polls a remote CDS service (pull
// mode) for the allowlist, with a base allowlist baked into its boot config
// (allowlist.base) as the cold-boot baseline.
package nriimagepolicy

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pull-startup retry parameters. Declared as vars so tests can shrink
// the backoff without exposing test-only knobs on the public surface.
var (
	allowlistApiMaxRetries   = 5
	allowlistApiInitialDelay = 2 * time.Second
)

var (
	errInitialAllowlistNotModified = errors.New("initial allowlist fetch returned not modified without a cached CDS allowlist")
	errInitialAllowlistNil         = errors.New("initial allowlist fetch returned nil allowlist")
	errPluginDied                  = errors.New("NRI plugin died during allowlist init")
)

func startupSourceMode(cfg *config) string {
	if cfg.PullEnabled() {
		return "pull"
	}

	sources := make([]string, 0, 2)
	if cfg.baseEnabled() {
		sources = append(sources, "base")
	}
	if len(cfg.Policy.LabelRules) > 0 {
		sources = append(sources, "label_rules")
	}
	if len(sources) == 0 {
		return "none"
	}
	return strings.Join(sources, "+")
}

// Run executes the nri-image-policy binary. args is the slice of CLI args
// after the program name.
func Run(args []string) error {
	if len(args) > 0 && args[0] == setCDSPinsVerb {
		return runSetCDSPins(os.Stdout, args[1:])
	}
	fs := flag.NewFlagSet("nri-image-policy", flag.ContinueOnError)
	configPath := fs.String("config", DefaultConfigPath, "path to config file")
	healthAddr := fs.String("health-addr", ":8080", "health check listen address")
	readTimeout := fs.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout := fs.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}

	logger, err := certutil.NewJSONLogger(cfg.Logging.Level)
	if err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	slog.SetDefault(logger)

	logger.Info("starting nri-image-policy",
		"version", version.Version,
		"config", *configPath,
		"mode", startupSourceMode(cfg),
	)

	logger.Debug("initializing containerd resolver",
		"socket", cfg.Containerd.Socket,
		"namespace", cfg.Containerd.Namespace,
	)
	resolver, err := ctrdresolver.NewResolver(cfg.Containerd.Socket, cfg.Containerd.Namespace)
	if err != nil {
		return fmt.Errorf("create containerd resolver: %w", err)
	}
	defer resolver.Close()

	auditLogger := audit.NewLogger()

	store := newPolicyStore(cfg.Allowlist.Base)

	var wlClient allowlistclient.Client
	if cfg.PullEnabled() {
		logger.Info("initializing allowlist client", "url", cfg.Allowlist.Pull.URL)
		httpClient, err := allowlistPullHTTPClient(cfg.Allowlist.Pull, cfg.NormalizedPlatform())
		if err != nil {
			return fmt.Errorf("create allowlist client: %w", err)
		}
		wlClient = allowlistclient.NewClientWithHTTP(cfg.Allowlist.Pull.URL, httpClient)
	}

	plugin, err := newPlugin(cfg, resolver, store, auditLogger, logger)
	if err != nil {
		return fmt.Errorf("create plugin: %w", err)
	}
	// Before the plugin serves a single container creation: a pod admitted
	// without this mount would read no pins at all.
	if err := plugin.prepareCDSPins(); err != nil {
		return fmt.Errorf("prepare the CDS pins handed to injected clients: %w", err)
	}
	logger.Info("CDS pins for injected clients", "path", plugin.cdsPins)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	logger.Info("policy store seeded", "base_entries", store.base.Size())

	addr := *healthAddr
	if cfg.Plugin.HealthAddr != "" {
		addr = cfg.Plugin.HealthAddr
	}
	if err := startHealthServer(ctx, healthServerConfig{
		logger:       logger,
		plugin:       plugin,
		addr:         addr,
		readTimeout:  *readTimeout,
		writeTimeout: *writeTimeout,
	}); err != nil {
		return fmt.Errorf("start health server on %q: %w", addr, err)
	}

	pluginErrCh := make(chan error, 1)
	go func() {
		pluginErrCh <- plugin.Run(ctx)
	}()

	if plugin.inventory != nil {
		signer, err := sandboxTokenSigner(cfg, logger)
		if err != nil {
			return err
		}
		socketPath := filepath.Join(cfg.WorkloadClaims.SocketDir, workloadclaims.SocketName)
		if err := startAdmissionInventory(ctx, logger, plugin, socketPath, signer); err != nil {
			return fmt.Errorf("start admission inventory: %w", err)
		}
		// Fail-soft, like the allowlist pull below: containerd requires this
		// plugin (required_plugins), so exiting takes container creation down
		// node-wide. A missing digests endpoint only degrades issuance — CDS
		// refuses tokens it cannot check — which is the cheaper failure.
		if signer != nil {
			if err := startSandboxDigests(ctx, logger, cfg, plugin, signer); err != nil {
				logger.Error("sandbox-digests endpoint disabled; CDS will refuse requests carrying a sandbox token", "error", err)
			}
		}
	}

	var initialETag string
	if cfg.PullEnabled() {
		initialETag, err = pullInitial(ctx, pullArgs{
			client:      wlClient,
			store:       store,
			timeout:     cfg.Allowlist.Pull.Timeout,
			pluginErrCh: pluginErrCh,
			logger:      logger,
		})
		if err != nil {
			switch {
			// INVARIANT: shutdown is read off the parent context, never off
			// the error chain. pullInitial gives every attempt its own
			// deadline, so a merely slow CDS returns an error wrapping
			// context.DeadlineExceeded that is indistinguishable from a
			// SIGTERM by inspection — and taking that branch parks the
			// process on pluginErrCh forever, never ready and never pulling.
			case ctx.Err() != nil:
				logger.Info("shutdown before plugin became ready")
				if perr := <-pluginErrCh; perr != nil {
					logger.Error("plugin error during shutdown", "error", perr)
				}
				return nil
			case errors.Is(err, errPluginDied):
				return err
			default:
				// The cache already holds the base allowlist, so stay up
				// serving it rather than crash-loop the plugin and block
				// container creation node-wide. runPullLoop keeps retrying.
				logger.Warn("initial allowlist pull failed; serving the base allowlist and retrying in background", "error", err)
			}
		}
	}

	plugin.SetReady()
	logger.Info("plugin ready")

	if cfg.PullEnabled() {
		go runPullLoop(ctx, pullLoopArgs{
			client:   wlClient,
			store:    store,
			interval: cfg.Allowlist.Pull.Interval,
			timeout:  cfg.Allowlist.Pull.Timeout,
			etag:     initialETag,
			logger:   logger,
		})
	}

	plugin.RunDeferredCheck(ctx)

	select {
	case err := <-pluginErrCh:
		if err != nil {
			return fmt.Errorf("plugin: %w", err)
		}
	case <-ctx.Done():
		if err := <-pluginErrCh; err != nil {
			logger.Error("plugin error during shutdown", "error", err)
		}
	}
	logger.Info("nri-image-policy stopped")
	return nil
}

// allowlistPullHTTPClient builds the armTLS client for the CDS pull. The pull
// URL is always https (enforced by config.Validate), so this always verifies
// the CDS attestation handshake.
func allowlistPullHTTPClient(cfg pullConfig, platform string) (*http.Client, error) {
	set, err := cfg.policySet(platform)
	if err != nil {
		return nil, err
	}
	if set.Empty() {
		slog.Warn("allowlist.pull.cds_measurements not set; nri-image-policy accepts any armTLS-attested CDS measurement")
	}
	client, err := armtls.NewVerifyingHTTPClient(armtls.Pins(set.Policy()), cfg.AttestationApiURL)
	if err != nil {
		return nil, fmt.Errorf("CDS armTLS client: %w", err)
	}
	client.Timeout = cfg.Timeout
	return client, nil
}

type pullArgs struct {
	client      allowlistclient.Client
	store       *policyStore
	timeout     time.Duration
	pluginErrCh <-chan error
	logger      *slog.Logger
}

// pullInitial fetches the startup allowlist with bounded retries and
// returns the response ETag for the steady-state poll loop.
//
// INVARIANT: a nil error return means args.store holds the pulled document.
// Context cancellation surfaces as ctx.Err(); callers must not mark the
// plugin ready on that path.
func pullInitial(ctx context.Context, args pullArgs) (string, error) {
	delay := allowlistApiInitialDelay
	for attempt := 1; attempt <= allowlistApiMaxRetries; attempt++ {
		select {
		case err := <-args.pluginErrCh:
			return "", fmt.Errorf("%w: %w", errPluginDied, err)
		case <-ctx.Done():
			args.logger.Info("shutdown requested during allowlist init")
			return "", ctx.Err()
		default:
		}

		reqCtx, reqCancel := context.WithTimeout(ctx, args.timeout)
		args.logger.Info("fetching initial allowlist from CDS", "attempt", attempt)
		wl, etag, notModified, err := args.client.Fetch(reqCtx, "")
		reqCancel()
		if err == nil {
			if notModified {
				err = errInitialAllowlistNotModified
			} else if wl == nil {
				err = errInitialAllowlistNil
			} else {
				version := parseVersion(etag)
				args.store.apply(wl, version)
				args.logger.Info("initial allowlist pulled from CDS",
					"workloads", len(wl.Workloads),
					"version", version,
					"etag", etag,
				)
				return etag, nil
			}
		}

		args.logger.Error("allowlist fetch failed", "attempt", attempt, "error", err)
		if attempt >= allowlistApiMaxRetries {
			return "", fmt.Errorf("allowlist fetch failed after %d attempts: %w", allowlistApiMaxRetries, err)
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			args.logger.Info("shutdown requested during allowlist init")
			return "", ctx.Err()
		}
		delay *= 2
	}
	return "", nil
}

type pullLoopArgs struct {
	client   allowlistclient.Client
	store    *policyStore
	interval time.Duration
	timeout  time.Duration
	etag     string
	logger   *slog.Logger
}

// runPullLoop polls CDS with If-None-Match. 200 rebuilds the index from the
// pulled document and advances the ETag — unless the pulled version is below the applied
// one (epoch rollback), which is ignored so the ETag keeps re-fetching until a
// forward version arrives. 304 and errors leave the index untouched.
func runPullLoop(ctx context.Context, args pullLoopArgs) {
	ticker := time.NewTicker(args.interval)
	defer ticker.Stop()

	etag := args.etag
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		reqCtx, cancel := context.WithTimeout(ctx, args.timeout)
		wl, newETag, notModified, err := args.client.Fetch(reqCtx, etag)
		cancel()
		if err != nil {
			args.logger.Warn("pull loop fetch failed", "error", err)
			continue
		}
		if notModified {
			args.logger.Debug("pull loop: not modified", "etag", etag)
			continue
		}
		if wl == nil {
			args.logger.Warn("pull loop fetch returned nil allowlist")
			continue
		}
		version := parseVersion(newETag)
		if !args.store.apply(wl, version) {
			args.logger.Warn("pull loop: ignoring rolled-back allowlist; keeping current index",
				"pulled_version", version, "etag", newETag)
			continue
		}
		etag = newETag
		args.logger.Info("pull loop: allowlist refreshed",
			"workloads", len(wl.Workloads),
			"version", version,
			"etag", etag,
		)
	}
}

// parseVersion extracts the monotone counter N from a weak ETag W/"N" — the CDS
// mutation counter used for epoch anti-rollback. An unparseable ETag yields 0,
// which can only be rejected as a rollback once a real version has been applied.
func parseVersion(etag string) uint64 {
	n, err := strconv.ParseUint(allowlistclient.VersionFromETag(etag), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

type healthServerConfig struct {
	logger       *slog.Logger
	plugin       *plugin
	addr         string
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// startHealthServer starts an HTTP server for readiness/liveness probes.
// addr accepts plain `host:port` for TCP or `unix:///path/to.sock` for a
// Unix socket. Shuts down gracefully when ctx is cancelled.
func startHealthServer(ctx context.Context, cfg healthServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.plugin.Ready() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
		}
	})

	listener, err := healthListener(cfg.addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: mux, ReadTimeout: cfg.readTimeout, WriteTimeout: cfg.writeTimeout}
	go func() {
		cfg.logger.Info("starting health server", "addr", cfg.addr)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			cfg.logger.Error("health server error", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			cfg.logger.Error("health server shutdown error", "error", err)
		}
	}()
	return nil
}

// sandboxTokenSigner builds the inventory's sandbox-token signer. The key needs
// no credential of its own: CDS reads it from this inventory's digests endpoint
// on a privileged port, which is what establishes whose key it is. Without pull
// config there is no CDS in the picture at all, so tokens are disabled and
// get-cert issues without a sandbox ID.
func sandboxTokenSigner(cfg *config, logger *slog.Logger) (*workloadclaims.SandboxTokenSigner, error) {
	if !cfg.PullEnabled() {
		logger.Warn("admission inventory has no CDS pull config; sandbox tokens disabled")
		return nil, nil
	}
	host, err := digestsAdvertiseHost(cfg)
	if err != nil {
		return nil, err
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		return nil, fmt.Errorf("create sandbox-token signer: %w", err)
	}
	logger.Info("sandbox tokens enabled", "digests_host", host, "digests_port", workloadclaims.DigestsPort)
	return signer, nil
}

// digestsAdvertiseHost is the node IP every sandbox token names for CDS's
// digests callback: the configured override, else the address the installer
// wrote from its own status.hostIP. Route inference is the last resort and
// usually wrong here — the chart points the plugin at the CDS NodePort on
// loopback, whose route source is loopback.
func digestsAdvertiseHost(cfg *config) (string, error) {
	// Config first, then the file the chart's installer writes, then the
	// environment — the node image bakes the plugin without an installer, so
	// nri-node-ip.service writes it there. None of these needs to be trustworthy: a
	// wrong host makes CDS fetch a key the token signature fails under, so it
	// can only fail closed, never redirect.
	host := cfg.WorkloadClaims.AdvertiseHost
	if host == "" {
		if b, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)); err == nil {
			host = strings.TrimSpace(string(b))
		}
	}
	if host == "" {
		host = strings.TrimSpace(os.Getenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST"))
	}
	// Bounds the resolver; runs once at startup with no caller ctx to inherit.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return workloadclaims.ResolveAdvertiseHost(ctx, host, cfg.Allowlist.Pull.URL)
}

// startSandboxDigests serves the CDS-facing digests endpoint over
// mutually-attested armTLS (docs/armtls.md, "Sandbox identity").
func startSandboxDigests(ctx context.Context, logger *slog.Logger, cfg *config, resolver workloadclaims.SandboxResolver, signer *workloadclaims.SandboxTokenSigner) error {
	set, err := cfg.Allowlist.Pull.policySet(cfg.NormalizedPlatform())
	if err != nil {
		return err
	}
	if set.Empty() {
		logger.Warn("allowlist.pull.cds_measurements not set: the sandbox-digests endpoint answers ANY armTLS-attested caller, so any TEE on the network can read what this node runs. UNSAFE outside development.")
	}
	attestationApiURL := cfg.Allowlist.Pull.AttestationApiURL
	// The attest func is platform-agnostic despite its name (see its doc
	// comment); the platform string is the only thing that follows the hardware.
	return workloadclaims.StartDigestsEndpoint(ctx, logger, resolver, signer.PublicKeyDER(),
		cfg.NormalizedPlatform(),
		attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), attestationApiURL),
		attestationApiURL, armtls.Pins(set.Policy()))
}

// startAdmissionInventory serves the node-CVM token socket (docs/armtls.md).
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, resolver workloadclaims.SandboxResolver, socketPath string, signer *workloadclaims.SandboxTokenSigner) error {
	l, err := workloadclaims.ListenUnix(socketPath, workloadclaims.InventorySocketGID)
	if err != nil {
		return err
	}
	// The node's signer is resolved before this point: a nil one means
	// this deployment issues no tokens at all, not that one is still coming.
	go func() {
		logger.Info("starting admission inventory", "socket", socketPath, "sandbox_tokens", signer != nil)
		if err := workloadclaims.ServeTokens(ctx, l, resolver, signer); err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}()
	return nil
}

// healthListener returns a TCP listener for `host:port` or a Unix socket
// listener for `unix:///abs/path`. Stale socket files are removed before
// bind so plugin restarts don't fail with EADDRINUSE; the file is chmod'd
// to 0660.
func healthListener(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("listen unix %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o660); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("chmod unix socket %s: %w", path, err)
		}
		return l, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	return l, nil
}
