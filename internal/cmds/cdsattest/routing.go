package cdsattest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// nodeOperatorKeysFile is where a baked node's signed launch configuration
// publishes the operator keys (W6, Allowlist O9).
const nodeOperatorKeysFile = nodeservices.PublicDir + "/operator-pubkey"

// defaultReservedPaths are the router's protocol endpoints and built-in routes
// at the chart's defaults. nginx serves them ahead of the routing listener;
// the tunnel must not route them either (M6).
var defaultReservedPaths = []string{
	"/allowlist",
	"/.well-known/c8s/",
	"/.well-known/cds-cert.pem",
	"/.well-known/mesh-ca.pem",
	"/.well-known/acme-challenge/",
	"/v1/discovery",
	"/readyz",
	"/healthz",
}

type routingConfig struct {
	cdsURL              string
	cdsMeasurements     []string
	cdsRTMRs            []string
	imagePolicyFile     string
	operatorKeysFile    string
	operatorKeysFileSet bool
	allowUnpinnedCDS    bool
	pollInterval        time.Duration
	host                string
	port                int
	backendTimeout      time.Duration
	reservedPaths       []string
	tunnelBudget        quantityFlag
	publish             bool
}

func bindRoutingFlags(f *pflag.FlagSet, cfg *routingConfig) {
	f.StringVar(&cfg.cdsURL, "cds-url", "", "REQUIRED: CDS base URL (https, armTLS-verified) to poll the signed route manifest from")
	f.StringSliceVar(&cfg.cdsMeasurements, "cds-measurements", nil, "allowed CDS SHA-384 launch measurement(s), repeatable/comma-separated; empty accepts any attested CDS (unsafe)")
	f.StringSliceVar(&cfg.cdsRTMRs, "cds-rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy, repeatable/comma-separated")
	cmdsutil.BindImagePolicyFlags(f, &cfg.imagePolicyFile, nil, "", "pins the CDS endpoint; excludes --cds-measurements and --cds-rtmrs")
	f.StringVar(&cfg.operatorKeysFile, "operator-keys-file", nodeOperatorKeysFile, "PEM operator public keys a route manifest must be signed under; when the default path is absent, the keys come from the verified CDS's GET /operator-keys")
	f.BoolVar(&cfg.allowUnpinnedCDS, "allow-unpinned-cds", false, "development only: route with no CDS pin and the operator keys from that CDS, so any attested CDS chooses both the keys and the manifest")
	f.DurationVar(&cfg.pollInterval, "routes-poll-interval", 30*time.Second, "how often to poll the CDS for the route manifest")
	f.StringVar(&cfg.host, "routing-host", "127.0.0.1", "routing listener host (loopback: nginx proxies application requests to it)")
	f.IntVar(&cfg.port, "routing-port", 0, "routing listener port; 0 disables the listener (the tunnel still routes by the applied manifest)")
	f.DurationVar(&cfg.backendTimeout, "backend-timeout", time.Hour, "how long a request or upgraded connection on the routing listener may go with no data moving either way; a tunnelled request, whose response is buffered whole, gets this long in total")
	f.StringSliceVar(&cfg.reservedPaths, "reserved-paths", defaultReservedPaths, "reserved paths the router serves itself; a request under one matches no manifest route")
	f.Var(&cfg.tunnelBudget, "tunnel-budget", "bytes tunnelled requests in flight in this replica may buffer, as a quantity such as 32Gi; each reserves three copies of its record and four of the largest response (32 MiB), one client (by X-Real-IP) holds at most a quarter, and a request over either gets 503 tunnel_busy; unset means 75% of the container memory limit, or 32Gi without one")
	f.BoolVar(&cfg.publish, "publish-routes", false, "serve the applied signed route manifest at /.well-known/c8s/routes, for clients that verify it under pinned operator keys; off, the path answers 404")
}

func checkRoutingFlags(cfg config) error {
	r := cfg.routing
	switch {
	case r.publish && r.cdsURL == "":
		return errors.New("--publish-routes requires --cds-url: it publishes the manifest polled from CDS")
	case r.publish && cfg.attestOff:
		return errors.New("--publish-routes requires --attest-endpoints=true: the route publication is served beside the attestation endpoints")
	}
	if r.cdsURL == "" {
		return errors.New("--cds-url is required: the router routes only by the route manifest it polls from CDS")
	}
	if cfg.attestOff && r.port == 0 {
		return errors.New("--attest-endpoints=false requires --routing-port: without it the process serves nothing")
	}
	// routes.Compile requires normalized reserved paths.
	for _, p := range r.reservedPaths {
		if n, ok := routes.NormalizePath(p); !ok || n != p {
			return fmt.Errorf("--reserved-paths entry %q is not a normalized path", p)
		}
	}
	if cfg.attestationAPIURL == "" {
		return errors.New("--cds-url requires --attestation-api-url to verify the CDS")
	}
	if cfg.meshIdentityCertFile == "" || cfg.meshIdentityKeyFile == "" || cfg.meshIdentityCAFile == "" {
		return errors.New("--cds-url requires --mesh-identity-cert-file, --mesh-identity-key-file and --mesh-identity-ca-file")
	}
	if r.pollInterval <= 0 {
		return errors.New("--routes-poll-interval must be positive")
	}
	if r.backendTimeout <= 0 {
		return errors.New("--backend-timeout must be positive")
	}
	if full := routing.TunnelReservation(tunnelBodyLimit); r.tunnelBudget.set && r.tunnelBudget.bytes < full {
		return fmt.Errorf("--tunnel-budget must cover one full-size request, %d bytes", full)
	}
	if r.port < 0 || r.port > 65535 {
		return fmt.Errorf("--routing-port must be between 0 and 65535, got %d", r.port)
	}
	if ip := net.ParseIP(r.host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--routing-host must be a loopback IP, got %q", r.host)
	}
	return nil
}

// routingEngine is the manifest routing a cds-attest process runs: the poller,
// the proxy the tunnel shares, and the optional routing listener.
type routingEngine struct {
	cfg    routingConfig
	log    *slog.Logger
	proxy  *routing.Proxy
	poller *routing.Poller
}

func newRoutingEngine(cfg config, logger *slog.Logger) (*routingEngine, error) {
	r := cfg.routing
	policy, err := (cmdsutil.ImagePolicySource{File: r.imagePolicyFile}).Load(
		cmdsutil.MeasurementPins{Measurements: r.cdsMeasurements, Registers: r.cdsRTMRs, Prefix: "cds-"})
	if err != nil {
		return nil, err
	}
	cdsPinned := len(policy.Measurements) > 0 || len(policy.Images) > 0
	if !cdsPinned {
		logger.Warn("no CDS measurements pinned; accepting any armTLS-attested CDS as the route manifest source (unsafe outside development)")
	}
	httpClient, err := armtls.NewVerifyingHTTPClient(armtls.Pins(policy), cfg.attestationAPIURL) // A1
	if err != nil {
		return nil, fmt.Errorf("CDS armTLS client: %w", err)
	}
	cds, err := routing.NewCDSClient(r.cdsURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("--cds-url: %w", err)
	}
	keys, err := operatorKeySource(r, cdsPinned, cds, logger)
	if err != nil {
		return nil, err
	}
	clientCert, err := routing.NewClientCert(cfg.meshIdentityCertFile, cfg.meshIdentityKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load mesh identity for backends: %w", err)
	}
	meshCAs := routing.CAFile(cfg.meshIdentityCAFile)
	state := routing.NewState(routing.StateConfig{Reserved: r.reservedPaths, MeshCAs: meshCAs})
	transports := routing.NewTransports(routing.TransportConfig{MeshCAs: meshCAs, ClientCertificate: clientCert.GetClientCertificate})
	return &routingEngine{
		cfg: r,
		log: logger,
		proxy: routing.NewProxy(routing.ProxyConfig{
			State: state, Transports: transports, Timeout: r.backendTimeout, TunnelBudget: tunnelBudget(r.tunnelBudget, cgroupMemoryMax, logger), Logger: logger,
		}),
		poller: routing.NewPoller(routing.PollerConfig{
			State: state, Fetcher: cds, Keys: keys, Transports: transports, Interval: r.pollInterval, Logger: logger,
		}),
	}, nil
}

// operatorKeySource implements W6: the node's signed launch configuration
// when it carries the keys, else the verified CDS. An explicit
// --operator-keys-file must exist. Keys from an unpinned CDS need
// --allow-unpinned-cds: that CDS could be any attested TEE.
func operatorKeySource(r routingConfig, cdsPinned bool, cds *routing.CDSClient, logger *slog.Logger) (routing.KeySource, error) {
	_, statErr := os.Stat(r.operatorKeysFile)
	switch {
	case statErr == nil:
		logger.Info("route manifest operator keys from file", "path", r.operatorKeysFile)
		return routing.KeyFile(r.operatorKeysFile), nil
	case r.operatorKeysFileSet || !errors.Is(statErr, os.ErrNotExist):
		return nil, fmt.Errorf("--operator-keys-file: %w", statErr)
	case !cdsPinned && !r.allowUnpinnedCDS:
		return nil, fmt.Errorf("refusing to route: no CDS pin and no operator keys at %s, so any attested CDS would supply both the manifest and its keys; pin CDS with --cds-measurements or --image-policy-file, provide --operator-keys-file, or pass --allow-unpinned-cds in development", r.operatorKeysFile)
	}
	logger.Warn("route manifest operator keys from the CDS (GET /operator-keys): control-plane configuration, so clients detect a substituted key but the router does not prevent it",
		"absent", r.operatorKeysFile)
	return cds, nil
}

// start runs the poller and, when a port is set, the routing listener. Errors
// from the listener arrive on errc.
func (e *routingEngine) start(ctx context.Context, readHeaderTimeout time.Duration, errc chan<- error) error {
	go e.poller.Run(ctx)
	if e.cfg.port == 0 {
		return nil
	}
	addr := net.JoinHostPort(e.cfg.host, strconv.Itoa(e.cfg.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("routing listener: %w", err)
	}
	srv := &http.Server{Handler: e.proxy, ReadHeaderTimeout: readHeaderTimeout}
	go cmdsutil.ShutdownOnDone(ctx, srv, shutdownGrace)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("routing listener: %w", err)
			return
		}
		errc <- nil
	}()
	e.log.Info("routing listener listening", "addr", addr)
	return nil
}
