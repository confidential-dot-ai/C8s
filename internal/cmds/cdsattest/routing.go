package cdsattest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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
	cdsURL           string
	cdsMeasurements  []string
	cdsRTMRs         []string
	imagePolicyFile  string
	launchKeysFile   string // empty means nodeOperatorKeysFile; tests point it elsewhere
	operatorKeysFile string
	allowUnpinnedCDS bool
	pollInterval     time.Duration
	host             string
	port             int
	backendTimeout   time.Duration
	reservedPaths    []string
	tunnelBudget     quantityFlag
	publish          bool
}

func bindRoutingFlags(f *pflag.FlagSet, cfg *routingConfig) {
	f.StringVar(&cfg.cdsURL, "cds-url", "", "CDS base URL (https, armTLS-verified) to poll the signed route manifest from; required unless this node's enforcer mounts the endpoint")
	f.StringSliceVar(&cfg.cdsMeasurements, "cds-measurements", nil, "allowed CDS SHA-384 launch measurement(s), repeatable/comma-separated; empty accepts any attested CDS (unsafe)")
	f.StringSliceVar(&cfg.cdsRTMRs, "cds-rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy, repeatable/comma-separated")
	cmdsutil.BindImagePolicyFlags(f, &cfg.imagePolicyFile, nil, "pins the CDS endpoint; excludes --cds-measurements and --cds-rtmrs")
	f.StringVar(&cfg.operatorKeysFile, "operator-keys-file", "", "PEM operator public keys a route manifest must be signed under, used when the node's launch configuration carries none; unset, the keys come from the verified CDS's GET /operator-keys")
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
	case cfg.measuredPolicies != "" && cfg.attestOff:
		return errors.New("--measured-policies-file requires --attest-endpoints=true: only the attestation bundles carry the list")
	}
	if r.cdsURL == "" {
		return errors.New("--cds-url is required: no node hands this router a CDS endpoint, and it routes only by the route manifest it polls from one")
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
	if !cfg.attestOff && (cfg.meshIdentityCertFile == "" || cfg.meshIdentityKeyFile == "" || cfg.meshIdentityCAFile == "") {
		return errors.New("--attest-endpoints=true requires --mesh-identity-cert-file, --mesh-identity-key-file and --mesh-identity-ca-file: the attestation endpoints bind their evidence to that leaf")
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
	httpClient, cdsPinned, err := routeSourceClient(r, cfg.attestationAPIURL, logger)
	if err != nil {
		return nil, err
	}
	cds, err := routing.NewCDSClient(r.cdsURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("--cds-url: %w", err)
	}
	fetcher := clusterWorkloadRoutes{routes: cds}
	keys, err := operatorKeySource(r, cdsPinned, cds, logger)
	if err != nil {
		return nil, err
	}
	identity, err := memberCredentials()
	if err != nil {
		return nil, err
	}
	state := routing.NewState(routing.StateConfig{Reserved: r.reservedPaths, MeshCAs: identity.MeshCAs})
	transports := routing.NewTransports(routing.TransportConfig{MeshIdentity: identity.Credential})
	return &routingEngine{
		cfg: r,
		log: logger,
		proxy: routing.NewProxy(routing.ProxyConfig{
			State: state, Transports: transports, Timeout: r.backendTimeout, TunnelBudget: tunnelBudget(r.tunnelBudget, cgroupMemoryMax, logger), Logger: logger,
		}),
		poller: routing.NewPoller(routing.PollerConfig{
			State: state, Fetcher: fetcher, Keys: keys, Transports: transports, Interval: r.pollInterval, Logger: logger,
		}),
	}, nil
}

// followedRouterPins is where the enforcer mounts the node's CDS pins as it
// follows the operator's pin decrees (a var so tests can point elsewhere).
var followedRouterPins = workloadclaims.RouterCDSPinsPath

// routeSourceClient is the armTLS client the poller fetches the route
// manifest with, and whether it pins CDS. On a node whose enforcer mounts the
// pins it follows, the client holds CDS to those and re-reads them on a pin
// miss, so the router keeps its routes across a CDS image rollout; they are
// the node's own policy, the one --image-policy-file names on a baked node,
// as it stands after the operator's decrees. Elsewhere the flags decide.
func routeSourceClient(r routingConfig, attestationAPIURL string, logger *slog.Logger) (*http.Client, bool, error) {
	if r.imagePolicyFile != "" {
		node, err := cmdsutil.FollowNodePins(followedRouterPins)
		if err != nil {
			return nil, false, fmt.Errorf("the node's followed CDS pins: %w", err)
		}
		if node != nil {
			hc, err := armtls.NewRefreshingHTTPClient(node, attestationAPIURL)
			if err != nil {
				return nil, false, fmt.Errorf("CDS armTLS client: %w", err)
			}
			logger.Info("route manifest source pinned to the node's followed CDS pins", "path", followedRouterPins)
			return hc, true, nil
		}
	}
	policy, err := (cmdsutil.ImagePolicySource{File: r.imagePolicyFile}).Load(
		cmdsutil.MeasurementPins{Measurements: r.cdsMeasurements, Registers: r.cdsRTMRs, Prefix: "cds-"})
	if err != nil {
		return nil, false, err
	}
	cdsPinned := len(policy.Measurements) > 0 || len(policy.Images) > 0
	if !cdsPinned {
		logger.Warn("no CDS measurements pinned; accepting any armTLS-attested CDS as the route manifest source (unsafe outside development)")
	}
	hc, err := armtls.NewVerifyingHTTPClient(armtls.Pins(policy), attestationAPIURL) // A1
	if err != nil {
		return nil, false, fmt.Errorf("CDS armTLS client: %w", err)
	}
	return hc, cdsPinned, nil
}

// checkNodeVerifier binds this router to the verifier its node chose, as
// every credential client is bound, and refuses one it would reach in the
// clear at an address of its own: the upstream identity's connections into
// the cluster are uncaptured, so a plaintext verifier an argument named
// could be a member pod rather than the node's own attestation-api.
//
// resolved is the URL this process dials, after ExpandHostIP replaced a node
// address reference with the address the enforcer published.
func checkNodeVerifier(resolved string) error {
	if err := cmdsutil.RequireNodeVerifier(workloadclaims.CDSPinsPath, workloadclaims.AttestationAPISocket, resolved); err != nil {
		return err
	}
	return checkVerifierEndpoint(resolved, cmdsutil.NodeIPPath)
}

// checkVerifierEndpoint admits the node's own attestation-api socket, an
// https endpoint, and plaintext only where it crosses no pod boundary: this
// pod's loopback, or the node's own address as nodeIPPath holds it. The
// decision is made on the parsed URL after expansion and compares addresses,
// so a host that merely carries the node's address — in userinfo, or as the
// head of a longer name — is another host and is refused, and no name is
// resolved: DNS is the control plane's.
func checkVerifierEndpoint(resolved, nodeIPPath string) error {
	endpoint, err := url.Parse(resolved)
	if err != nil {
		return fmt.Errorf("--attestation-api-url %q: %w", resolved, err)
	}
	switch endpoint.Scheme {
	case "unix", "https":
		return nil
	case "http":
		return checkPlaintextVerifier(resolved, endpoint, nodeIPPath)
	}
	return fmt.Errorf("--attestation-api-url %q names the scheme %q: the verifier is this node's attestation-api socket, an https endpoint, or http at this node's own address",
		resolved, endpoint.Scheme)
}

func checkPlaintextVerifier(resolved string, endpoint *url.URL, nodeIPPath string) error {
	// The port is the node's to serve on and the pod ruleset's to admit; the
	// host, and nothing else in the URL, is what this check decides.
	refusal := fmt.Errorf("--attestation-api-url %q is plaintext at an address this pod named: give this node's attestation-api socket, an https endpoint, or http://%s:<port>",
		resolved, cmdsutil.NodeIPReference)
	if endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return refusal
	}
	host, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil {
		return refusal
	}
	if host.Unmap().IsLoopback() {
		return nil
	}
	node, err := nodeAddress(nodeIPPath)
	if err != nil {
		return errors.Join(refusal, err)
	}
	if host.Unmap() != node {
		return refusal
	}
	return nil
}

// nodeAddress is the node's own address, as the enforcer publishes it for the
// components that reach its attestation-api by address.
func nodeAddress(nodeIPPath string) (netip.Addr, error) {
	published, err := os.ReadFile(nodeIPPath)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read the node address: %w", err)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(published)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("the node address in %s: %w", nodeIPPath, err)
	}
	return address.Unmap(), nil
}

// The leaf and the key of the credential generation get-cert publishes on a
// member pod's volume, beside workloadclaims.MemberCAPath.
const (
	memberCertPath = workloadclaims.MemberCertDir + "/tls.crt"
	memberKeyPath  = workloadclaims.MemberCertDir + "/tls.key"
)

// memberCredentials is the identity of the hop to a member backend and its
// trust root in one: the credential generation get-cert published on this
// pod's own volume, re-resolved per handshake so a rotation takes effect
// without a restart. The volume is compiled and no argument reaches it — a CA
// an argument named would be one the control plane chose, and its holder could
// stamp any workload name on a leaf this router then accepted.
func memberCredentials() (*routing.MeshIdentity, error) {
	identity, err := routing.NewMeshIdentity(memberCertPath, memberKeyPath, workloadclaims.MemberCAPath)
	if err != nil {
		return nil, fmt.Errorf("mesh identity for backends: %w", err)
	}
	return identity, nil
}

// clusterWorkloadRoutes refuses a fetched manifest this router cannot serve,
// so the refusal arrives with the manifest that names it rather than at dial
// time. Every route must name a cluster workload: this pod reaches a backend
// as the mesh client of the workload its route names, and its ruleset leaves
// it nothing else to reach. Nothing is applied either way, so reading the
// manifest here, before Accept verifies its signature, decides nothing but
// the diagnostic.
type clusterWorkloadRoutes struct {
	routes routing.Fetcher
}

func (c clusterWorkloadRoutes) Routes(ctx context.Context) (routes.Envelope, error) {
	env, err := c.routes.Routes(ctx)
	if err != nil {
		return routes.Envelope{}, err
	}
	manifest, err := routes.Parse(env.Manifest)
	if err != nil {
		return routes.Envelope{}, err
	}
	for _, host := range slices.Sorted(maps.Keys(manifest.Hosts)) {
		for _, route := range manifest.Hosts[host].Routes {
			if route.Backend.Workload == "" {
				return routes.Envelope{}, fmt.Errorf("host %q route %q names the address backend %s: the router serves cluster workloads only", host, route.Path, route.Backend.Address)
			}
		}
	}
	return env, nil
}

// operatorKeySource implements W6: the node's signed launch configuration
// when it carries the keys, else --operator-keys-file, else the verified CDS.
// A set --operator-keys-file must exist. Keys from an unpinned CDS need
// --allow-unpinned-cds: that CDS could be any attested TEE.
func operatorKeySource(r routingConfig, cdsPinned bool, cds *routing.CDSClient, logger *slog.Logger) (routing.KeySource, error) {
	if r.launchKeysFile == "" {
		r.launchKeysFile = nodeOperatorKeysFile
	}
	switch err := loadKeys(r.launchKeysFile); {
	case err == nil:
		if r.operatorKeysFile != "" && r.operatorKeysFile != r.launchKeysFile {
			logger.Warn("ignoring --operator-keys-file: the launch configuration carries operator keys", "path", r.launchKeysFile)
		}
		logger.Info("route manifest operator keys from the launch configuration", "path", r.launchKeysFile)
		return routing.KeyFile(r.launchKeysFile), nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("launch configuration operator keys: %w", err)
	}
	if r.operatorKeysFile != "" {
		if err := loadKeys(r.operatorKeysFile); err != nil {
			return nil, fmt.Errorf("--operator-keys-file: %w", err)
		}
		logger.Info("route manifest operator keys from file", "path", r.operatorKeysFile)
		return routing.KeyFile(r.operatorKeysFile), nil
	}
	if !cdsPinned && !r.allowUnpinnedCDS {
		return nil, fmt.Errorf("refusing to route: no CDS pin and no operator keys in the launch configuration (%s) or --operator-keys-file, so any attested CDS would supply both the manifest and its keys; pin CDS with --cds-measurements or --image-policy-file, provide --operator-keys-file, or pass --allow-unpinned-cds in development", r.launchKeysFile)
	}
	logger.Warn("route manifest operator keys from the CDS (GET /operator-keys): control-plane configuration, so clients detect a substituted key but the router does not prevent it")
	return cds, nil
}

// loadKeys checks at startup that path holds at least one operator key;
// KeyFile re-reads it at each fetch.
func loadKeys(path string) error {
	_, err := routing.KeyFile(path).OperatorKeys(context.Background())
	return err
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
