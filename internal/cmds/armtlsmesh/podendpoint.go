//go:build linux

// The per-pod mesh endpoint: a capability-less sidecar that carries one pod's
// captured TCP over armTLS. The pod's packet rules are the node enforcer's and
// outlive this process, so a refusal here costs the connection, never the seal.

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	// podDialTimeout bounds one dial, handshake included.
	podDialTimeout  = 10 * time.Second
	podDrainTimeout = 30 * time.Second
	// probeShutdownTimeout bounds the probe server's own shutdown, which only
	// has to finish the probe requests in flight.
	probeShutdownTimeout = 5 * time.Second
	podKeepAlive         = 30 * time.Second
	probeTimeout         = 5 * time.Second
)

// The ports the endpoint binds: the two the pod's ruleset redirects to, plus
// the one the probes answer on.
const (
	podOutboundPort = int(workloadclaims.MeshOutboundPort)
	podInboundPort  = int(workloadclaims.MeshInboundPort)
	podHealthPort   = int(workloadclaims.MeshHealthPort)
)

// origDstFunc recovers the address a connection was captured for.
type origDstFunc func(net.Conn) (string, error)

type podEndpointConfig struct {
	chainPath, keyPath, caPath string
	// probes are the health-port paths the injector rewrote the pod's
	// application probes onto, from MeshProbesEnv.
	probes []string
}

func newArmtlsMeshCommand() *cobra.Command {
	var cfg podEndpointConfig
	cmd := &cobra.Command{
		Use:   "armtls-mesh",
		Short: "Carry one pod's captured TCP over armTLS",
		Args:  cobra.NoArgs,
		Long: `armtls-mesh is the mesh endpoint of a single member pod. It dials each
captured outbound connection to its original destination over armTLS with the
pod's published credentials, and delivers each inbound armTLS connection to the
original destination on one of the pod's own addresses.

Each application probe the injector moved onto the health port is named in
${C8S_MESH_PROBES}. The endpoint forwards those paths, and no others, to the
pod's own loopback, and answers with the application's status code alone.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.probes = workloadclaims.SplitMeshProbePaths(os.Getenv(workloadclaims.MeshProbesEnv))
			return runPodEndpoint(cmd.Context(), &cfg, podOutboundPort, podInboundPort, podHealthPort)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&cfg.chainPath, "cert-path", "", "path get-cert publishes the certificate chain PEM at")
	flags.StringVar(&cfg.keyPath, "key-path", "", "path get-cert publishes the private key PEM at")
	flags.StringVar(&cfg.caPath, "ca-path", "", "path get-cert publishes the mesh CA PEM at")
	for _, name := range []string{"cert-path", "key-path", "ca-path"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func runPodEndpoint(ctx context.Context, c *podEndpointConfig, outbound, inbound, health int) error {
	logger, err := certutil.NewJSONLogger("info")
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	endpoint, err := newPodEndpoint(c, logger)
	if err != nil {
		return err
	}
	listeners, err := endpoint.bind(ctx, outbound, inbound, health)
	if err != nil {
		return err
	}
	logger.Info("starting the pod mesh endpoint", "outbound_port", outbound, "inbound_port", inbound, "health_port", health, "pod_addresses", endpoint.own)
	return endpoint.serve(ctx, listeners)
}

// newPodEndpoint reads the credential volume get-cert publishes into and the
// pod's own addresses. It binds nothing.
func newPodEndpoint(c *podEndpointConfig, logger *slog.Logger) (*podEndpoint, error) {
	volume, err := credentialVolumeFor(c.chainPath, c.keyPath, c.caPath)
	if err != nil {
		return nil, err
	}
	probes, err := probeTargetsFor(c.probes)
	if err != nil {
		return nil, err
	}
	own, err := ownPodAddresses()
	if err != nil {
		return nil, err
	}
	return &podEndpoint{
		credentials: &credentials{
			volume: volume,
			logger: logger,
		},
		own:         own,
		origDst:     defaultOrigDstFunc,
		logger:      logger,
		bufPool:     newBufPool(),
		probes:      probes,
		probeClient: newProbeClient(),
	}, nil
}

// probeTargetsFor resolves the rendered probe paths into the loopback URLs the
// endpoint forwards them to. An unrenderable or mesh-port target fails here,
// before the endpoint binds: the pod's probes are its injected shape, so a
// target the endpoint cannot serve is a refusal, not a silent omission.
func probeTargetsFor(rendered []string) (probeTargets, error) {
	targets := make(probeTargets, len(rendered))
	for _, path := range rendered {
		port, appPath, err := workloadclaims.ParseMeshProbePath(path)
		if err != nil {
			return nil, err
		}
		if isMeshPort(int(port)) {
			return nil, fmt.Errorf("probe path %q names mesh port %d", path, port)
		}
		targets[path] = fmt.Sprintf("http://127.0.0.1:%d%s", port, appPath)
	}
	return targets, nil
}

func isMeshPort(port int) bool {
	return port == podOutboundPort || port == podInboundPort || port == podHealthPort
}

// probeTargets are the application probes the injector rendered, keyed by the
// health-port path each answers on and valued by the loopback URL it reaches.
// The endpoint forwards a probe path this map carries and no other, so neither
// the node nor anything else that reaches the health port can aim it at a port
// the pod spec never named.
type probeTargets map[string]string

type podEndpoint struct {
	credentials *credentials
	own         podAddresses
	origDst     origDstFunc
	logger      *slog.Logger
	bufPool     *bufPool
	probes      probeTargets
	probeClient *http.Client
	// initialized is set once the endpoint runs on its bound listeners.
	initialized atomic.Bool
	// mu guards draining, so a connection is counted in active only while the
	// endpoint still serves it.
	mu       sync.Mutex
	draining bool
	active   sync.WaitGroup
}

// podListeners are the three listeners the endpoint binds and owns.
type podListeners struct {
	outbound, inbound, probes net.Listener
}

// bind binds the two capture ports and the probe port.
func (e *podEndpoint) bind(ctx context.Context, outbound, inbound, health int) (podListeners, error) {
	var listeners podListeners
	var err error
	config := &net.ListenConfig{KeepAlive: podKeepAlive}
	listeners.outbound, err = config.Listen(ctx, "tcp", fmt.Sprintf(":%d", outbound))
	if err != nil {
		listeners.close()
		return podListeners{}, fmt.Errorf("listen on port %d: %w", outbound, err)
	}
	listeners.inbound, err = config.Listen(ctx, "tcp", fmt.Sprintf(":%d", inbound))
	if err != nil {
		listeners.close()
		return podListeners{}, fmt.Errorf("listen on port %d: %w", inbound, err)
	}
	listeners.probes, err = config.Listen(ctx, "tcp", fmt.Sprintf(":%d", health))
	if err != nil {
		listeners.close()
		return podListeners{}, fmt.Errorf("listen on port %d: %w", health, err)
	}
	return listeners, nil
}

func (l podListeners) close() {
	for _, ln := range []net.Listener{l.outbound, l.inbound, l.probes} {
		if ln != nil {
			ln.Close()
		}
	}
}

// serve runs the listeners until ctx is cancelled or one of them fails, then
// drains the connections in flight.
func (e *podEndpoint) serve(ctx context.Context, listeners podListeners) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.credentials.watchGenerations(ctx)
	e.initialized.Store(true)

	runners := []func() error{
		func() error { return e.accept(ctx, listeners.outbound, e.handleOutbound) },
		func() error { return e.accept(ctx, listeners.inbound, e.handleInbound) },
		func() error { return e.serveProbes(ctx, listeners.probes) },
	}
	stopped := make(chan error, len(runners))
	for _, run := range runners {
		go func() { stopped <- run() }()
	}
	err := <-stopped
	cancel()
	e.drain()
	return err
}

// accept hands every connection to handler until ctx is cancelled, which closes
// the listener. An accept failure stops the endpoint: the pod's ruleset keeps
// the pod sealed without it.
func (e *podEndpoint) accept(ctx context.Context, ln net.Listener, handle func(context.Context, net.Conn)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on %s: %w", ln.Addr(), err)
		}
		if !e.track() {
			conn.Close()
			return nil
		}
		go func() {
			defer e.active.Done()
			defer conn.Close()
			handle(ctx, conn)
		}()
	}
}

// track counts a connection the endpoint is about to serve. It reports false
// once the drain began, and the caller closes the connection instead.
func (e *podEndpoint) track() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.draining {
		return false
	}
	e.active.Add(1)
	return true
}

func (e *podEndpoint) drain() {
	e.mu.Lock()
	e.draining = true
	e.mu.Unlock()
	drained := make(chan struct{})
	go func() {
		e.active.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(podDrainTimeout):
		e.logger.Warn("drain timeout exceeded, closing with connections in flight")
	}
}

// handleOutbound carries one captured connection to its original destination
// over armTLS: nothing is sent until the handshake, the mesh ALPN and peer
// authentication have succeeded.
func (e *podEndpoint) handleOutbound(ctx context.Context, app net.Conn) {
	log := e.logger.With("dir", "outbound")
	g, err := e.credentials.usable(time.Now())
	if err != nil {
		log.Warn("refusing a captured connection: no usable credentials", "error", err)
		return
	}
	dst, err := e.capturedDestination(app)
	if err != nil {
		log.Warn("refusing a captured connection: no original destination", "error", err)
		return
	}
	if err := e.requireMeshDestination(dst); err != nil {
		log.Warn("refusing a captured connection", "dst", dst, "error", err)
		return
	}
	peer, err := (&tls.Dialer{
		Config: g.clientTLS,
		NetDialer: &net.Dialer{
			Timeout:   podDialTimeout,
			KeepAlive: podKeepAlive,
		},
	}).DialContext(ctx, "tcp", dst.String())
	if err != nil {
		log.Warn("armTLS dial failed", "dst", dst, "error", err)
		return
	}
	defer peer.Close()
	if _, err := e.credentials.usable(time.Now()); err != nil {
		log.Warn("refusing to forward: the credentials went away during the handshake", "error", err)
		return
	}
	log.Debug("mesh connection established", "dst", dst)
	pipeConns(e.bufPool, app, peer)
}

// handleInbound delivers one authenticated mesh connection to the destination it
// was captured for, which the kernel records and the peer never names.
func (e *podEndpoint) handleInbound(ctx context.Context, peer net.Conn) {
	log := e.logger.With("dir", "inbound")
	g, err := e.credentials.usable(time.Now())
	if err != nil {
		log.Warn("refusing a mesh connection: no usable credentials", "error", err)
		return
	}
	dst, err := e.capturedDestination(peer)
	if err != nil {
		log.Warn("refusing a mesh connection: no original destination", "error", err)
		return
	}
	if err := e.requireDeliverable(dst); err != nil {
		log.Warn("refusing a mesh connection", "dst", dst, "error", err)
		return
	}
	authenticated := tls.Server(peer, g.serverTLS)
	handshake, cancel := context.WithTimeout(ctx, podDialTimeout)
	defer cancel()
	if err := authenticated.HandshakeContext(handshake); err != nil {
		log.Warn("peer authentication failed", "src", peer.RemoteAddr(), "error", err)
		return
	}
	if _, err := e.credentials.usable(time.Now()); err != nil {
		log.Warn("refusing to deliver: the credentials went away during the handshake", "error", err)
		return
	}
	log.Debug("mesh peer authenticated", "dst", dst)
	e.deliverLocal(ctx, authenticated, dst, log)
}

// deliverLocal relays an authenticated peer to the local application socket.
func (e *podEndpoint) deliverLocal(ctx context.Context, peer net.Conn, dst netip.AddrPort, log *slog.Logger) {
	dialer := &net.Dialer{
		Timeout:   podDialTimeout,
		KeepAlive: podKeepAlive,
	}
	app, err := dialer.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		log.Warn("local delivery failed", "dst", dst, "error", err)
		return
	}
	defer app.Close()
	pipeConns(e.bufPool, peer, app)
}

// capturedDestination is the address the kernel recorded for conn before it was
// redirected to a capture port.
func (e *podEndpoint) capturedDestination(conn net.Conn) (netip.AddrPort, error) {
	dst, err := e.origDst(conn)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddrPort(dst)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("original destination %q: %w", dst, err)
	}
	return addr, nil
}

// requireDeliverable holds that inbound mesh bytes reach an application port on
// one of the pod's own addresses, never loopback and never a mesh port.
func (e *podEndpoint) requireDeliverable(dst netip.AddrPort) error {
	if !e.own.contains(dst.Addr()) {
		return fmt.Errorf("%s is not one of the pod's own addresses", dst.Addr())
	}
	return e.rejectMeshPort(dst)
}

// requireMeshDestination holds that a captured connection leaves the pod, and
// enters its peer on an application port rather than a mesh port.
func (e *podEndpoint) requireMeshDestination(dst netip.AddrPort) error {
	if err := e.rejectOwnAddress(dst.Addr()); err != nil {
		return err
	}
	return e.rejectMeshPort(dst)
}

func (e *podEndpoint) rejectOwnAddress(addr netip.Addr) error {
	if e.own.contains(addr) {
		return fmt.Errorf("%s is one of the pod's own addresses", addr)
	}
	return nil
}

func (e *podEndpoint) rejectMeshPort(dst netip.AddrPort) error {
	if isMeshPort(int(dst.Port())) {
		return fmt.Errorf("port %d is a mesh port, not an application port", dst.Port())
	}
	return nil
}

// podAddresses are the pod's own unicast addresses, read once: the CNI assigns
// them before any container starts. Loopback is left out, because inbound mesh
// traffic is never delivered there.
type podAddresses []netip.Addr

func ownPodAddresses() (podAddresses, error) {
	assigned, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("list the pod's addresses: %w", err)
	}
	var own podAddresses
	for _, address := range assigned {
		prefix, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(prefix.IP)
		if !ok || addr.IsLoopback() {
			continue
		}
		own = append(own, addr.Unmap())
	}
	if len(own) == 0 {
		return nil, errors.New("the pod's namespace has no address outside loopback")
	}
	return own, nil
}

func (p podAddresses) contains(addr netip.Addr) bool {
	return slices.Contains(p, addr.Unmap())
}

// probeServer serves the endpoint's own two probes and the application probes
// the injector moved onto this port. An accept failure ends the process, so an
// answer here reports working listeners, and no answer carries a body of the
// endpoint's own: a probe discloses no forwarding destination and no credential
// material.
func (e *podEndpoint) probeServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /startupz", e.handleStartup)
	mux.HandleFunc("GET /readyz", e.handleReady)
	mux.HandleFunc("GET "+workloadclaims.MeshProbePrefix, e.forwardProbe)
	return &http.Server{
		Handler:      mux,
		ReadTimeout:  probeTimeout,
		WriteTimeout: probeTimeout,
		IdleTimeout:  probeTimeout,
	}
}

// newProbeClient forwards one probe inside the pod: a fresh transport, so no
// proxy environment can interpose; no redirect followed, so a redirecting
// application cannot send the probe off the pod; and one bounded hop.
func newProbeClient() *http.Client {
	return &http.Client{
		Timeout:   probeTimeout,
		Transport: &http.Transport{},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// forwardProbe answers one rewritten application probe with the status code the
// application returned and an empty body. The probe arrives in the clear from
// the node, so the answer carries the liveness of a probe target the injector
// rendered and nothing else of the application.
func (e *podEndpoint) forwardProbe(w http.ResponseWriter, r *http.Request) {
	target, ok := e.probes[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		e.logger.Warn("building a forwarded probe failed", "path", r.URL.Path, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp, err := e.probeClient.Do(request)
	if err != nil {
		e.logger.Debug("a forwarded probe failed", "path", r.URL.Path, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// serveProbes serves the probe listener until ctx is cancelled, then lets the
// probe requests in flight finish.
func (e *podEndpoint) serveProbes(ctx context.Context, ln net.Listener) error {
	srv := e.probeServer()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), probeShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handleStartup reports that the endpoint runs on its listeners. It needs no
// leaf: get-cert publishes the first generation after this container starts.
func (e *podEndpoint) handleStartup(w http.ResponseWriter, _ *http.Request) {
	if !e.initialized.Load() {
		http.Error(w, "initializing", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("initialized\n"))
}

// handleReady reports that the endpoint can carry traffic: a usable generation
// with the trust policy it was published with.
func (e *podEndpoint) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !e.initialized.Load() {
		http.Error(w, "initializing", http.StatusServiceUnavailable)
		return
	}
	if _, err := e.credentials.usable(time.Now()); err != nil {
		e.logger.Debug("reporting unready", "error", err)
		http.Error(w, "no usable credential generation", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}
