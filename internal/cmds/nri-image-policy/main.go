// Package nriimagepolicy is an NRI plugin that validates container images
// against a digest allowlist. Every plugin polls a remote CDS service (pull
// mode) for the allowlist, with a base allowlist baked into its boot config
// (allowlist.base) as the cold-boot baseline.
package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
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
	if len(args) > 0 && args[0] == pluginReadyVerb {
		return runPluginReady(args[1:])
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

	logOut, err := logWriter(cfg.Logging)
	if err != nil {
		return err
	}
	logger, err := certutil.NewJSONLoggerTo(logOut, cfg.Logging.Level)
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

	logNodeRoot(logger, cfg.AllowlistEnabled(), nodeRootUnavailable)
	plugin, err := newPlugin(cfg, resolver, store, auditLogger, logger)
	if err != nil {
		return fmt.Errorf("create plugin: %w", err)
	}
	// Before the plugin serves a single container creation: a pod admitted
	// without this mount would read no pins at all.
	if err := plugin.prepareCDSPins(); err != nil {
		return fmt.Errorf("prepare the CDS pins handed to injected clients: %w", err)
	}
	if err := plugin.prepareCDSAddress(); err != nil {
		return fmt.Errorf("prepare the CDS address handed to injected clients: %w", err)
	}
	logger.Info("CDS policy for injected clients", "pins", plugin.cdsPins, "address", plugin.cdsAddress)

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

	if cfg.WorkloadClaims.PublishNodeIP {
		// Fail-soft: exiting would block container creation node-wide, while
		// a missing file only fails closed the components that read it. The
		// first attempt runs here so the signer below reads a file this
		// process resolved, unless only the default route named another
		// address (see nodeIPPublisher.write).
		publisher := &nodeIPPublisher{cfg: cfg, logger: logger}
		go publisher.run(ctx, publisher.publish())
	}

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
		socketPath := filepath.Join(cfg.WorkloadClaims.SocketDir, workloadclaims.SocketName)
		if err := startAdmissionInventory(ctx, logger, cfg, plugin, socketPath); err != nil {
			return fmt.Errorf("start admission inventory: %w", err)
		}
	}

	measure := policyMeasurer(cfg, logger)
	var initialETag string
	if cfg.PullEnabled() {
		initialETag, err = pullInitial(ctx, pullArgs{
			client:      wlClient,
			store:       store,
			measure:     measure,
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
			measure:  measure,
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
	measure     func(digest string) error // nil measures nothing
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
		served, notModified, err := args.client.FetchServed(reqCtx, "")
		wl, etag := served.Allowlist, served.ETag
		reqCancel()
		if err == nil {
			if notModified {
				err = errInitialAllowlistNotModified
			} else if wl == nil {
				err = errInitialAllowlistNil
			} else if err = measureWith(args.measure, served.Digest); err == nil {
				version := parseVersion(etag)
				args.store.apply(wl, version)
				args.logger.Info("initial allowlist pulled from CDS",
					"workloads", len(wl.Workloads),
					"version", version,
					"etag", etag,
					"digest", served.Digest,
				)
				return etag, nil
			}
		}

		args.logger.Error("allowlist fetch failed", "attempt", attempt, "error", err)
		if errors.Is(err, errPolicyRefused) {
			return "", err // retrying cannot succeed
		}
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
	measure  func(digest string) error // nil measures nothing
	interval time.Duration
	timeout  time.Duration
	etag     string
	logger   *slog.Logger
}

// runPullLoop polls CDS with If-None-Match. 200 rebuilds the index from the
// pulled document and advances the ETag — unless the pulled version is below the applied
// one (epoch rollback), which is ignored so the ETag keeps re-fetching until a
// forward version arrives. 304 and errors leave the index untouched. A
// version the measurer refuses for good also advances the ETag and is logged
// once per digest.
func runPullLoop(ctx context.Context, args pullLoopArgs) {
	ticker := time.NewTicker(args.interval)
	defer ticker.Stop()

	etag := args.etag
	var refused, failing string // digests last logged as refused or unmeasured
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		reqCtx, cancel := context.WithTimeout(ctx, args.timeout)
		served, notModified, err := args.client.FetchServed(reqCtx, etag)
		wl, newETag := served.Allowlist, served.ETag
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
		// A rolled-back document is never enforced, so it is not measured.
		if args.store.rolledBack(version) {
			args.logger.Warn("pull loop: ignoring rolled-back allowlist; keeping current index",
				"pulled_version", version, "etag", newETag)
			continue
		}
		if err := measureWith(args.measure, served.Digest); err != nil {
			if !errors.Is(err, errPolicyRefused) {
				// Retried every tick; logged at Error once per digest.
				level := slog.LevelError
				if served.Digest == failing {
					level = slog.LevelDebug
				}
				failing = served.Digest
				args.logger.Log(ctx, level, "pull loop: not applying an allowlist this node could not measure",
					"digest", served.Digest, "error", err)
				continue
			}
			// Advance past the refused version so later ticks get 304
			// instead of downloading it again.
			etag = newETag
			failing = "" // a later failure is news again
			if served.Digest != refused {
				refused = served.Digest
				args.logger.Error("pull loop: allowlist refused; keeping current policy",
					"digest", served.Digest, "etag", etag, "error", err)
			}
			continue
		}
		args.store.apply(wl, version)
		etag, failing = newETag, ""
		args.logger.Info("pull loop: allowlist refreshed",
			"workloads", len(wl.Workloads),
			"version", version,
			"etag", etag,
			"digest", served.Digest,
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

// healthResponse is the body of GET /healthz. Probes and the installer read
// only the status code; the body says which allowlist version admission
// decides with, so a writer can watch an entry take effect.
type healthResponse struct {
	Status           string `json:"status"`
	AllowlistVersion uint64 `json:"allowlist_version"` // plugin.AppliedAllowlistVersion
}

// startHealthServer starts an HTTP server for readiness/liveness probes.
// addr accepts plain `host:port` for TCP or `unix:///path/to.sock` for a
// Unix socket. Shuts down gracefully when ctx is cancelled.
func startHealthServer(ctx context.Context, cfg healthServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		body := healthResponse{Status: "ok", AllowlistVersion: cfg.plugin.AppliedAllowlistVersion()}
		code := http.StatusOK
		if !cfg.plugin.Ready() {
			body.Status = "not ready"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(body)
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

// Node-side retry timing; vars so tests can shrink them.
var (
	nodeRetryMinDelay     = time.Second
	nodeRetryMaxDelay     = time.Minute
	nodeIPRecheckInterval = time.Minute
)

// chooseHostInterface and writeNodeIPFile are package vars so tests can fake
// the host's routes and a failed write.
var (
	chooseHostInterface = utilnet.ChooseHostInterface
	writeNodeIPFile     = writeInPlace
)

// nodeIPPublisher keeps NodeIPFile current: a DHCP node may have no default
// route when containerd starts, and its address may change later. Components
// restart when the file names another address, and a restarted CDS that
// reads it regenerates the mesh CA, so a transient failure never touches the
// file and a change is published only once it held for two rechecks. A
// resolver that alternates between two addresses therefore never publishes.
type nodeIPPublisher struct {
	cfg    *config
	logger *slog.Logger
	delay  time.Duration // current failure backoff, 0 after a success

	kubelet string // the last address a host kubelet's --node-ip supplied
	pending string // a changed address seen once, published if it holds
	settled bool   // the file holds an address this process resolved
}

// publish makes one attempt and returns the wait before the next: the recheck
// interval after a success, a doubling backoff after a failure.
func (p *nodeIPPublisher) publish() time.Duration {
	path := filepath.Join(p.cfg.WorkloadClaims.SocketDir, NodeIPFile)
	host, source, err := p.resolve()
	if err == nil && !usableNodeIP(net.ParseIP(host)) {
		// Not transient: advertise_host names an address no pod can dial.
		p.pending = ""
		p.delay = min(max(2*p.delay, nodeRetryMinDelay), nodeRetryMaxDelay)
		p.logger.Error("node-ip emptied: the node address is not a unicast address other pods can dial; running components keep the address they read, and components that start will not until an address is published",
			"address", host, "source", source, "error", emptyIfExists(path), "retry_in", p.delay)
		return p.delay
	}
	if err == nil {
		err = p.write(path, host, source)
	}
	if err != nil {
		p.delay = min(max(2*p.delay, nodeRetryMinDelay), nodeRetryMaxDelay)
		p.logger.Error("node-ip not updated; it keeps its last address, and components that read none will not start until it is published", "error", err, "retry_in", p.delay)
		return p.delay
	}
	p.delay = 0
	return nodeIPRecheckInterval
}

// write publishes host unless the file holds it already. A file naming
// another address keeps it until a second recheck resolves host again. The
// first write of a process skips that wait unless host came from the default
// route: the file then predates this process, while a default route seen
// before the kubelet is back from a node restart may name another interface.
func (p *nodeIPPublisher) write(path, host, source string) error {
	current := ""
	if b, err := os.ReadFile(path); err == nil {
		current = strings.TrimSpace(string(b))
	}
	if current == host {
		p.pending = ""
		p.settled = true
		return nil
	}
	debounce := p.settled || source == "default_route"
	if current != "" && debounce && p.pending != host {
		p.pending = host
		p.logger.Warn("node address changed; publishing it if the next recheck agrees", "address", host, "source", source, "published", current, "recheck_in", nodeIPRecheckInterval)
		return nil
	}
	if err := writeNodeIP(p.cfg.WorkloadClaims.SocketDir, path, host); err != nil {
		return err
	}
	p.pending = ""
	p.settled = true
	p.logger.Info("node-ip published", "address", host, "source", source)
	return nil
}

// resolve returns the node's address and the source that supplied it:
// advertise_host when it is an IP, else the --node-ip of a kubelet in the
// host's mount namespace, which is the Node's registered InternalIP and its
// pods' status.hostIP, else the default-route interface's address, which a
// kubelet without --node-ip usually registers. Once a kubelet supplied an
// address, a recheck that finds no kubelet keeps it rather than fall back to
// the default route: the kubelet is restarting, and its address has not
// changed. k3s runs its kubelet inside the k3s process, so a k3s node with
// several interfaces needs advertise_host. A pod could otherwise pick the
// attestation verifier components dial.
func (p *nodeIPPublisher) resolve() (host, source string, err error) {
	if host := p.cfg.WorkloadClaims.AdvertiseHost; net.ParseIP(host) != nil {
		return host, "advertise_host", nil
	}
	host, running := kubeletNodeIP(p.cfg.WorkloadClaims.ProcRoot)
	switch {
	case host != "":
		p.kubelet = host
		return host, "kubelet", nil
	case running:
		// A kubelet that runs without a usable --node-ip picks its address
		// as the default route does.
		p.kubelet = ""
	case p.kubelet != "":
		return p.kubelet, "kubelet_last_seen", nil
	}
	ip, err := chooseHostInterface()
	if err != nil {
		return "", "", fmt.Errorf("resolve node address: %w", err)
	}
	if !usableNodeIP(ip) {
		// Likely a link-local address before DHCP completes: retry.
		return "", "", fmt.Errorf("resolve node address: default route address %s is not one other pods can dial", ip)
	}
	return ip.String(), "default_route", nil
}

// run repeats publish until ctx is done, waiting wait before the first attempt.
func (p *nodeIPPublisher) run(ctx context.Context, wait time.Duration) {
	for sleepCtx(ctx, wait) {
		wait = p.publish()
	}
}

// kubeletNodeIP is the first address of a host kubelet's --node-ip flag, read
// from procRoot (default /proc), or "" when no host kubelet passes a usable
// one; running reports whether a host kubelet runs at all. A pod's processes
// show up in procRoot too and can name themselves kubelet, but cannot join
// the host's mount namespace, which is init's. --node-ip=:: or 0.0.0.0
// selects an address family, not an address.
func kubeletNodeIP(procRoot string) (host string, running bool) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	hostMounts, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "mnt"))
	if err != nil {
		return "", false
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "kubelet" {
			continue
		}
		if mounts, err := os.Readlink(filepath.Join(dir, "ns", "mnt")); err != nil || mounts != hostMounts {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		running = true
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		for i, arg := range args {
			value, ok := strings.CutPrefix(arg, "--node-ip=")
			if !ok && arg == "--node-ip" && i+1 < len(args) {
				value, ok = args[i+1], true
			}
			if !ok {
				continue
			}
			first, _, _ := strings.Cut(value, ",")
			if ip := net.ParseIP(first); usableNodeIP(ip) {
				return ip.String(), true
			}
		}
	}
	return "", running
}

// usableNodeIP reports whether components can dial ip as the node: an
// unspecified or loopback address reaches the dialing pod's own network
// namespace instead.
func usableNodeIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast()
}

// writeNodeIP writes host to path in place: components bind-mount the file
// itself, so a renamed replacement would leave their mount on the old inode.
// A write can fail after it changed the file, so a failed one puts the
// previous content back, or empties a file that held none.
func writeNodeIP(dir, path, host string) error {
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return err
	}
	previous, readErr := os.ReadFile(path)
	// World-readable: non-root components read it.
	err := writeNodeIPFile(path, []byte(host+"\n"), 0o644)
	if err == nil {
		return nil
	}
	err = fmt.Errorf("write %s: %w", path, err)
	if readErr != nil {
		return errors.Join(err, emptyIfExists(path))
	}
	if restoreErr := writeNodeIPFile(path, previous, 0o644); restoreErr != nil {
		return errors.Join(err, fmt.Errorf("restore %s: %w", path, restoreErr))
	}
	return err
}

// writeInPlace replaces path's content without replacing its inode, so a bind
// mount of the file sees the change. A reader may see a partial write;
// cmdsutil.WatchNodeIP acts only on a value it reads twice.
func writeInPlace(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, err = f.WriteAt(data, 0)
	if err == nil {
		err = f.Truncate(int64(len(data)))
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	return errors.Join(err, f.Close())
}

func emptyIfExists(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(f.Truncate(0), f.Close())
}

// sleepCtx waits d and reports whether ctx is still live.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// newSandboxTokenSigner is a package var so tests can count attempts.
var newSandboxTokenSigner = sandboxTokenSigner

// sandboxTokenSigner builds the inventory's sandbox-token signer. The key needs
// no credential of its own: CDS reads it from this inventory's digests endpoint
// on a privileged port, which is what establishes whose key it is.
// followSandboxHost keeps the signed host current.
func sandboxTokenSigner(cfg *config, logger *slog.Logger) (*workloadclaims.SandboxTokenSigner, error) {
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
// digests callback: the configured override, else the node-ip file. Route inference is the last resort and
// usually wrong here — the chart points the plugin at the CDS NodePort on
// loopback, whose route source is loopback.
func digestsAdvertiseHost(cfg *config) (string, error) {
	// This node's configured address, then the environment. None of these
	// needs to be trustworthy: a wrong host makes CDS fetch a key the token
	// signature fails under, so it can only fail closed, never redirect.
	host := nodeConfiguredHost(cfg)
	if host == "" {
		host = strings.TrimSpace(os.Getenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST"))
	}
	// Bounds the resolver: it runs at startup and on every node address
	// recheck, with no caller ctx to inherit.
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
	var journal string
	if cfg.WorkloadClaims.SocketDir != "" {
		journal = filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal)
	}
	// The attest func is platform-agnostic despite its name (see its doc
	// comment); the platform string is the only thing that follows the hardware.
	return workloadclaims.StartDigestsEndpoint(ctx, logger, resolver, signer.PublicKeyDER(),
		cfg.NormalizedPlatform(),
		attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), attestationApiURL),
		attestationApiURL, armtls.Pins(set.Policy()), journal)
}

// startAdmissionInventory serves the node-CVM token socket (docs/armtls.md).
// Without pull config there is no CDS in the picture at all, so tokens are
// disabled and get-cert issues without a sandbox ID. Otherwise the signer
// initializes in the background and the socket answers 503 until it does.
func startAdmissionInventory(ctx context.Context, logger *slog.Logger, cfg *config, resolver workloadclaims.SandboxResolver, socketPath string) error {
	l, err := workloadclaims.ListenUnix(socketPath, workloadclaims.InventorySocketGID)
	if err != nil {
		return err
	}
	logger.Info("starting admission inventory", "socket", socketPath, "sandbox_tokens", cfg.PullEnabled())
	serve := func(err error) {
		if err != nil {
			logger.Error("admission inventory error", "error", err)
		}
	}
	if !cfg.PullEnabled() {
		logger.Warn("admission inventory has no CDS pull config; sandbox tokens disabled")
		go func() { serve(workloadclaims.ServeTokens(ctx, l, resolver, nil)) }()
		return nil
	}
	var signer atomic.Pointer[workloadclaims.SandboxTokenSigner]
	go func() { serve(workloadclaims.ServePendingTokens(ctx, l, resolver, &signer)) }()
	go initSandboxTokens(ctx, logger, cfg, &signer, func(s *workloadclaims.SandboxTokenSigner) error {
		return startSandboxDigests(ctx, logger, cfg, resolver, s)
	})
	return nil
}

// initSandboxTokens retries the signer with backoff until it initializes or
// ctx is done, then starts the digests endpoint, enables issuance and follows
// the node address until ctx is done. Enforcement never waits on it:
// containerd requires this plugin (required_plugins), so exiting takes
// container creation down node-wide.
func initSandboxTokens(ctx context.Context, logger *slog.Logger, cfg *config, signer *atomic.Pointer[workloadclaims.SandboxTokenSigner], serveDigests func(*workloadclaims.SandboxTokenSigner) error) {
	delay := nodeRetryMinDelay
	for {
		s, err := newSandboxTokenSigner(cfg, logger)
		if err == nil {
			// A missing digests endpoint only degrades issuance — CDS refuses
			// tokens it cannot check — so issuance is enabled regardless.
			if err := serveDigests(s); err != nil {
				logger.Error("sandbox-digests endpoint disabled; CDS will refuse requests carrying a sandbox token", "error", err)
			}
			signer.Store(s)
			ok := true
			for sleepCtx(ctx, nodeIPRecheckInterval) {
				ok = followSandboxHost(cfg, logger, signer, ok)
			}
			return
		}
		logger.Error("sandbox tokens disabled until the signer initializes", "error", err, "retry_in", delay)
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(2*delay, nodeRetryMaxDelay)
	}
}

// followSandboxHost re-signs with the current node address when it changed,
// keeping the key the digests endpoint serves. Tokens naming a stale address
// would send CDS to a dead or foreign digests endpoint. When the address
// cannot be resolved it keeps the last one: CDS then fails closed on it. It
// reports whether the address resolved, and warns only when wasOK was true,
// so an address that stays unresolved logs once rather than every recheck.
func followSandboxHost(cfg *config, logger *slog.Logger, signer *atomic.Pointer[workloadclaims.SandboxTokenSigner], wasOK bool) bool {
	current := signer.Load()
	host, err := digestsAdvertiseHost(cfg)
	if err == nil && host != current.Host() {
		var next *workloadclaims.SandboxTokenSigner
		if next, err = current.WithHost(host); err == nil {
			signer.Store(next)
			logger.Info("sandbox tokens follow the node address", "digests_host", host, "previous", current.Host())
		}
	}
	if err != nil && wasOK {
		logger.Warn("node address unresolved; sandbox tokens keep naming the last one", "error", err, "digests_host", current.Host())
	}
	return err == nil
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

// logNodeRoot reports a missing measured root at Info: most nodes have none and
// only policies that require node-root provenance depend on it. A node whose
// boot command line declares a roothash= yet fails the proof is misbuilt, so
// that is a warning. Without an allowlist no rule can require it, so nothing
// is probed.
func logNodeRoot(logger *slog.Logger, allowlistEnabled bool, unavailable func() (reason string, declared bool)) {
	if !allowlistEnabled {
		return
	}
	reason, declared := unavailable()
	switch {
	case reason == "":
	case declared:
		logger.Warn("node-root provenance unavailable on a node declaring a measured root", "reason", reason)
	default:
		logger.Info("node-root provenance unavailable", "reason", reason)
	}
}

// measureWith runs measure, when set, on digest.
func measureWith(measure func(string) error, digest string) error {
	if measure == nil {
		return nil
	}
	return measure(digest)
}

// readOperatorKey reads the launch operator key that seeded RTMR[3], and
// openPolicyJournal opens the journal over the hardware register. Vars so tests
// can supply a key and a register.
var (
	readOperatorKey   = credrelease.ReadOperatorPubkey
	openPolicyJournal = openJournal
)

// policyMeasurer returns the hook that extends RTMR[3] with each pulled policy
// before the node applies it, so the register records every policy the node
// enforced since boot. It returns nil, measuring nothing, unless
// allowlist.pull.measure_policies is set on a platform with a runtime
// register. The hook fails every call while measuring cannot work, so the node
// keeps its current policy rather than enforce unmeasured ones. A missing
// operator key refuses for good; any other open failure is retried on the next
// call.
func policyMeasurer(cfg *config, logger *slog.Logger) func(digest string) error {
	if !cfg.Allowlist.Pull.MeasurePolicies {
		return nil
	}
	platform := teetypes.PlatformType(cfg.NormalizedPlatform())
	if !platform.HasRegisters() {
		logger.Info("allowlist policies are not measured: no runtime register", "platform", platform)
		return nil
	}
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal)
	var journal *runtimemeasure.Journal
	open := func() error {
		anchor, err := readOperatorKey()
		if err == nil {
			journal, err = openPolicyJournal(cfg.WorkloadClaims.SocketDir, platform, anchor)
		}
		if journal == nil {
			if errors.Is(err, credrelease.ErrNoOperatorKey) || errors.Is(err, runtimemeasure.ErrNoRegister) {
				err = fmt.Errorf("%w: %w", errPolicyRefused, err)
			}
			return fmt.Errorf("allowlist policy measurement unavailable: %w", err)
		}
		if err != nil {
			// A diverged journal refuses every extend, so policy updates stop.
			logger.Error("allowlist policy measurement journal", "error", err)
		}
		// Created readable up front: the journal's first append would create it
		// 0600, and certificate producers would fail to read it until the chmod.
		if err := createReadable(path); err != nil {
			logger.Error("measured-policy journal stays unreadable to the router", "error", err)
		}
		return nil
	}
	openErr := open()
	if openErr != nil {
		logger.Error("allowlist policies cannot be measured; pulled allowlists are not applied", "error", openErr)
	}
	return func(digest string) error {
		if journal == nil {
			if errors.Is(openErr, errPolicyRefused) {
				return openErr
			}
			if openErr = open(); openErr != nil {
				return openErr
			}
		}
		if err := checkJournalRoom(journal, digest); err != nil {
			return err
		}
		_, err := journal.MeasureOnce(digest)
		if errors.Is(err, runtimemeasure.ErrRegisterDiverged) {
			err = fmt.Errorf("%w: %w", errPolicyRefused, err)
		}
		// Also after a failed extend, which rewrites the file: the router
		// reads it as a non-root user, and it lists only public digests.
		if cerr := os.Chmod(path, 0o644); cerr != nil && !errors.Is(cerr, fs.ErrNotExist) {
			logger.Error("measured-policy journal stays unreadable to the router", "error", cerr)
		}
		return err
	}
}

// checkJournalRoom refuses a digest the journal does not hold once it holds
// armtls.MaxRuntimeExtensions: certificates cannot carry a longer list, so
// measuring it would cost the node its armTLS identity. The node keeps its
// current policy until it reboots.
func checkJournalRoom(journal *runtimemeasure.Journal, digest string) error {
	measured := journal.Digests()
	if len(measured) < armtls.MaxRuntimeExtensions {
		return nil
	}
	if d, err := runtimemeasure.CanonicalDigest(digest); err == nil && slices.Contains(measured, d) {
		return nil
	}
	return fmt.Errorf("%w: allowlist policy %s not applied: the node measured %d policies since boot, the most its certificates can carry; reboot to take further updates", errPolicyRefused, digest, len(measured))
}

// errPolicyRefused marks a measure failure that persists until the plugin
// restarts, so retrying the same policy cannot succeed.
var errPolicyRefused = errors.New("policy refused")

// createReadable creates path empty and world-readable unless it exists.
func createReadable(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

// openJournal opens the measured-policy journal in dir over this node's
// RTMR[3], whose launch seeded it from anchor.
func openJournal(dir string, platform teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
	reg, err := runtimemeasure.Open(platform)
	if err != nil {
		return nil, err
	}
	return runtimemeasure.OpenJournalSeeded(filepath.Join(dir, armtls.MeasuredPoliciesJournal), reg, runtimemeasure.Seed(anchor))
}
