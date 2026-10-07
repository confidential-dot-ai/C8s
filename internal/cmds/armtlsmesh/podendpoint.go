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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	// podDialTimeout bounds one dial, handshake included.
	podDialTimeout  = 10 * time.Second
	podDrainTimeout = 30 * time.Second
	podKeepAlive    = 30 * time.Second
	probeTimeout    = 5 * time.Second
)

// origDstFunc recovers the address a connection was captured for.
type origDstFunc func(net.Conn) (string, error)

type podEndpointConfig struct {
	chainPath, keyPath, caPath string
	ports                      capturePorts
	logLevel                   string
}

// capturePorts are the ports the pod's ruleset redirects to, plus the port the
// probes answer on.
type capturePorts struct {
	outbound, inbound, health int
}

func newPodEndpointCommand() *cobra.Command {
	var cfg podEndpointConfig
	cmd := &cobra.Command{
		Use:   "pod-endpoint",
		Short: "Carry one pod's captured TCP over armTLS",
		Long: `pod-endpoint is the mesh endpoint of a single member pod. It dials each
captured outbound connection to its original destination over armTLS with the
pod's published credentials, and delivers each inbound armTLS connection to the
original destination on one of the pod's own addresses.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPodEndpoint(cmd.Context(), &cfg)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&cfg.chainPath, "cert-path", "", "path get-cert publishes the certificate chain PEM at")
	flags.StringVar(&cfg.keyPath, "key-path", "", "path get-cert publishes the private key PEM at")
	flags.StringVar(&cfg.caPath, "ca-path", "", "path get-cert publishes the mesh CA set PEM at")
	flags.IntVar(&cfg.ports.outbound, "outbound-port", 15001, "port the pod's ruleset redirects captured application traffic to")
	flags.IntVar(&cfg.ports.inbound, "inbound-port", 15006, "port the pod's ruleset redirects inbound mesh traffic to")
	flags.IntVar(&cfg.ports.health, "health-port", 15021, "port serving GET /startupz and GET /readyz")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	for _, name := range []string{"cert-path", "key-path", "ca-path"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func runPodEndpoint(ctx context.Context, c *podEndpointConfig) error {
	logger, err := certutil.NewJSONLogger(c.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)
	if err := c.ports.validate(); err != nil {
		return err
	}
	volume, err := credentialVolumeFor(c.chainPath, c.keyPath, c.caPath)
	if err != nil {
		return err
	}
	own, err := ownPodAddresses()
	if err != nil {
		return err
	}
	endpoint := &podEndpoint{
		credentials: &credentials{volume: volume, logger: logger},
		own:         own,
		ports:       c.ports,
		origDst:     defaultOrigDstFunc,
		logger:      logger,
		bufPool:     newBufPool(0),
	}
	listeners, err := endpoint.bind(ctx)
	if err != nil {
		return err
	}
	logger.Info("starting the pod mesh endpoint", "outbound_port", c.ports.outbound, "inbound_port", c.ports.inbound, "health_port", c.ports.health, "pod_addresses", own)
	return endpoint.serve(ctx, listeners)
}

// validate holds the invariant the delivery exclusion rests on: three ports in
// range, each naming a different thing.
func (p capturePorts) validate() error {
	ports := []int{p.outbound, p.inbound, p.health}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("--outbound-port, --inbound-port and --health-port must be in 1-65535, not %v", ports)
		}
	}
	if p.outbound == p.inbound || p.outbound == p.health || p.inbound == p.health {
		return fmt.Errorf("--outbound-port, --inbound-port and --health-port must differ, not %v", ports)
	}
	return nil
}

func (p capturePorts) isMeshPort(port int) bool {
	return port == p.outbound || port == p.inbound || port == p.health
}

type podEndpoint struct {
	credentials *credentials
	own         podAddresses
	ports       capturePorts
	origDst     origDstFunc
	logger      *slog.Logger
	bufPool     *sync.Pool
	// initialized is set once the endpoint runs on its bound listeners.
	initialized atomic.Bool
	active      sync.WaitGroup
}

// podListeners are the three listeners the endpoint binds and owns.
type podListeners struct {
	outbound, inbound, probes net.Listener
}

// bind binds the two capture ports and the probe port.
func (e *podEndpoint) bind(ctx context.Context) (podListeners, error) {
	var listeners podListeners
	config := &net.ListenConfig{KeepAlive: podKeepAlive}
	for _, port := range []struct {
		number int
		into   *net.Listener
	}{
		{e.ports.outbound, &listeners.outbound},
		{e.ports.inbound, &listeners.inbound},
		{e.ports.health, &listeners.probes},
	} {
		ln, err := config.Listen(ctx, "tcp", fmt.Sprintf(":%d", port.number))
		if err != nil {
			listeners.close()
			return podListeners{}, fmt.Errorf("listen on port %d: %w", port.number, err)
		}
		*port.into = ln
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
		func() error { return serveHTTP(ctx, e.probeServer(), listeners.probes) },
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
		e.active.Add(1)
		go func() {
			defer e.active.Done()
			defer conn.Close()
			handle(ctx, conn)
		}()
	}
}

func (e *podEndpoint) drain() {
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
// authentication have succeeded (P1).
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
		Config:    g.clientTLS,
		NetDialer: &net.Dialer{Timeout: podDialTimeout, KeepAlive: podKeepAlive},
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
// was captured for, which the kernel records and the peer never names (P3).
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
	app, err := (&net.Dialer{Timeout: podDialTimeout, KeepAlive: podKeepAlive}).DialContext(ctx, "tcp", dst.String())
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

// requireDeliverable holds P3: inbound mesh bytes reach an application port on
// one of the pod's own addresses, never loopback and never a mesh port.
func (e *podEndpoint) requireDeliverable(dst netip.AddrPort) error {
	if !e.own.contains(dst.Addr()) {
		return fmt.Errorf("%s is not one of the pod's own addresses", dst.Addr())
	}
	return e.rejectMeshPort(dst)
}

// requireMeshDestination holds P4: a captured connection leaves the pod, and it
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
	if e.ports.isMeshPort(int(dst.Port())) {
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

// probeServer serves the two probes the injector wires. An accept failure ends
// the process, so an answer here reports working listeners (L2, L3), and the
// bodies are fixed strings: a probe carries no forwarding destination and no
// credential material (L4).
func (e *podEndpoint) probeServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /startupz", e.handleStartup)
	mux.HandleFunc("GET /readyz", e.handleReady)
	return &http.Server{Handler: mux, ReadTimeout: probeTimeout, WriteTimeout: probeTimeout, IdleTimeout: probeTimeout}
}

// handleStartup reports that the endpoint runs on its listeners. It needs no
// leaf: get-cert publishes the first generation after this container starts (L2).
func (e *podEndpoint) handleStartup(w http.ResponseWriter, _ *http.Request) {
	if !e.initialized.Load() {
		http.Error(w, "initializing", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("initialized\n"))
}

// handleReady reports that the endpoint can carry traffic: a usable generation
// with the trust policy it was published with (L3).
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
