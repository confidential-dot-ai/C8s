//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/armtls/cdsclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Run dispatches armtls-mesh CLI args via cobra. Signal handling is wired
// at the root so subcommand RunE bodies read cmd.Context() instead of
// reinstalling their own NotifyContext.
func Run(args []string) error {
	cmd := newArmtlsMeshCommand()
	cmd.SetArgs(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return cmd.ExecuteContext(ctx)
}

// inClusterConfig is a var so tests can exercise newKubeClientset off-cluster.
var inClusterConfig = rest.InClusterConfig

// newKubeClientset builds the Kubernetes client used by the proxy and the
// iptables-sync sidecar: from kubeconfigPath when set, else from the
// in-cluster service-account config. Package var so tests can substitute a
// fake clientset.
var newKubeClientset = func(kubeconfigPath string) (kubernetes.Interface, error) {
	var restCfg *rest.Config
	var err error
	if kubeconfigPath != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("k8s config from --kubeconfig %s: %w", kubeconfigPath, err)
		}
	} else {
		restCfg, err = inClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("k8s in-cluster config: %w", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset: %w", err)
	}
	return clientset, nil
}

func newArmtlsMeshCommand() *cobra.Command {
	var cfg proxyConfig
	cmd := &cobra.Command{
		Use:           "armtls-mesh",
		Short:         "ARmTLS L4 mesh proxy",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxy(cmd.Context(), &cfg)
		},
	}
	bindProxyFlags(cmd.Flags(), &cfg)
	cmd.AddCommand(newIptablesSyncCommand())
	cmd.AddCommand(newIptablesCleanupCommand())
	return cmd
}

// proxyListeners are served instead of binding the matching *Port fields;
// tests pre-bind them.
type proxyListeners struct {
	outbound net.Listener
	inbound  net.Listener
	health   net.Listener
}

type proxyConfig struct {
	platform                  string
	attestationApiURL         string
	kubeconfig                string
	outboundPort              int
	inboundPort               int
	nodeIP                    string
	certDNSSAN                string
	logLevel                  string
	dialTimeout               time.Duration
	tlsDialTimeout            time.Duration
	destHeaderTimeout         time.Duration
	drainTimeout              time.Duration
	keepAlive                 time.Duration
	idleTimeout               time.Duration
	maxConns                  int
	maxConnsPerSource         int
	healthPort                int
	listeners                 proxyListeners
	measurements              string
	rtmrs                     string
	measurementsConfig        string
	cdsMeasurementsConfig     string
	cdsPins                   refvalues.ReferenceValues
	certTTL                   time.Duration
	rotationTimeout           time.Duration
	certMode                  string
	cdsURL                    string
	caCertPath                string
	caPollInterval            time.Duration
	cdsMeasurements           string
	cdsRTMRs                  string
	sessionCacheSize          int
	accessLog                 bool
	certPipelineProbeURL      string
	cdsRetryBackoff           time.Duration
	cdsRetryMaxBackoff        time.Duration
	maxDestHeaderSize         int
	pipeBufferSize            int
	acceptErrThreshold        int64
	healthReadTimeout         time.Duration
	healthWriteTimeout        time.Duration
	metricsUpdateInterval     time.Duration
	localCIDRBootTimeout      time.Duration
	iptablesMetricsFile       string
	cdsOpTimeout              time.Duration
	certPipelineProbeTimeout  time.Duration
	certPipelineProbeInterval time.Duration
}

func bindProxyFlags(fs *pflag.FlagSet, c *proxyConfig) {
	fs.StringVar(&c.platform, "platform", "auto", "TEE platform: sev-snp, tdx, or auto (probes /dev/{tdx_guest,sev-guest})")
	fs.StringVar(&c.attestationApiURL, "attestation-api-url", "", "URL of the local attestation-api (e.g. http://localhost:8400)")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to a kubeconfig for the pod resolver's API access; empty uses the in-cluster service-account config")
	fs.IntVar(&c.outboundPort, "outbound-port", 15001, "outbound listener port (intercepted app traffic)")
	fs.IntVar(&c.inboundPort, "inbound-port", 15006, "inbound listener port (ARmTLS from peer nodes)")
	fs.StringVar(&c.nodeIP, "node-ip", "", "this node's IP (auto-detected from NODE_IP env if unset)")
	fs.StringVar(&c.certDNSSAN, "cert-dns-san", "", "DNS SAN placed on the CDS-issued mesh cert (must match CDS --dns-san-pattern; empty omits SANs). Not used for peer verification, which is attestation-based.")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.DurationVar(&c.dialTimeout, "dial-timeout", 5*time.Second, "plain TCP dial timeout")
	fs.DurationVar(&c.tlsDialTimeout, "tls-dial-timeout", 10*time.Second, "ARmTLS dial timeout")
	fs.DurationVar(&c.destHeaderTimeout, "dest-header-timeout", 5*time.Second, "inbound destination header read timeout")
	fs.DurationVar(&c.drainTimeout, "drain-timeout", 30*time.Second, "graceful shutdown drain timeout")
	fs.DurationVar(&c.keepAlive, "keepalive", 30*time.Second, "TCP keepalive interval (0 to disable)")
	fs.DurationVar(&c.idleTimeout, "idle-timeout", 0, "close connections idle longer than this (0=disabled)")
	fs.IntVar(&c.maxConns, "max-conns", 0, "max concurrent connections (0=unlimited)")
	fs.IntVar(&c.maxConnsPerSource, "max-conns-per-source", 0, "max concurrent connections per source IP (0=unlimited)")
	fs.IntVar(&c.healthPort, "health-port", 15021, "health/metrics HTTP port")
	fs.StringVar(&c.measurements, "measurements", "", "comma-separated hex SHA-384 launch measurements (empty = accept any TEE)")
	fs.StringVar(&c.rtmrs, "rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex> mesh peers must satisfy (RTMR[1] guest kernel, RTMR[2] cmdline with the dm-verity root hash). SNP peers are unaffected. Empty = no RTMR pinning: on TDX --measurements then pins TDVF firmware only, UNSAFE")
	cmdsutil.BindImagePolicyFlags(fs, &c.measurementsConfig, nil, "", "pins mesh peers; also pins CDS unless --cds-image-policy-file is set; excludes --measurements and --rtmrs")
	cmdsutil.BindImagePolicyFlags(fs, &c.cdsMeasurementsConfig, nil, "cds-", "pins CDS independently of mesh peers; excludes --cds-measurements and --cds-rtmrs")
	fs.DurationVar(&c.certTTL, "cert-ttl", 24*time.Hour, "ARmTLS certificate lifetime (rotates at 50%)")
	fs.DurationVar(&c.rotationTimeout, "rotation-timeout", 30*time.Second, "max time for background certificate rotation")
	fs.StringVar(&c.certMode, "cert-mode", "self-signed", "certificate mode: self-signed (default), cds (boots self-signed, upgrades to CDS-issued in background)")
	fs.StringVar(&c.cdsURL, "cds-url", "", "CDS service URL for attestation and CA bundle retrieval (required for cds mode)")
	fs.StringVar(&c.caCertPath, "ca-cert", "", "path to CA certificate file for peer verification")
	fs.DurationVar(&c.caPollInterval, "ca-poll-interval", 5*time.Minute, "interval to poll CDS /ca for CA bundle updates")
	fs.StringVar(&c.cdsMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch measurements that CDS's ARmTLS peer cert must match. Empty = accept any (UNSAFE outside development).")
	fs.StringVar(&c.cdsRTMRs, "cds-rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex> that CDS's ARmTLS peer cert must additionally satisfy. Ignored when CDS presents SNP evidence. Empty = launch-digest pinning only")
	fs.IntVar(&c.sessionCacheSize, "session-cache-size", 64, "TLS session cache size per node (0 disables session resumption)")
	fs.BoolVar(&c.accessLog, "access-log", true, "emit per-connection structured access log")
	fs.StringVar(&c.certPipelineProbeURL, "cert-pipeline-probe-url", "", "CDS /readyz URL for pipeline health probing (empty = disabled)")
	fs.DurationVar(&c.cdsRetryBackoff, "cds-retry-backoff", 2*time.Second, "initial backoff duration for CDS certificate upgrade retries")
	fs.DurationVar(&c.cdsRetryMaxBackoff, "cds-retry-max-backoff", 60*time.Second, "maximum backoff duration for CDS certificate upgrade retries")
	fs.IntVar(&c.maxDestHeaderSize, "max-dest-header-size", 256, "maximum destination header size in bytes")
	fs.IntVar(&c.pipeBufferSize, "pipe-buffer-size", 32768, "buffer size for TCP pipe forwarding")
	fs.Int64Var(&c.acceptErrThreshold, "accept-error-threshold", 10, "consecutive accept errors before marking unhealthy")
	fs.DurationVar(&c.healthReadTimeout, "health-read-timeout", 5*time.Second, "health server read timeout")
	fs.DurationVar(&c.healthWriteTimeout, "health-write-timeout", 10*time.Second, "health server write timeout")
	fs.DurationVar(&c.metricsUpdateInterval, "metrics-update-interval", 10*time.Second, "interval for resolver cache and cert expiry metric updates")
	fs.DurationVar(&c.localCIDRBootTimeout, "local-cidr-boot-timeout", time.Second, "synchronous retry budget at startup for host pod-network CIDR discovery; past this we fall through to the async refresh loop and ValidateLocalDest uses Kubernetes pod HostIP ownership until discovery recovers")
	fs.StringVar(&c.iptablesMetricsFile, "iptables-metrics-file", defaultIptablesMetricsFile, "shared file where iptables-sync publishes counters (empty disables)")
	fs.DurationVar(&c.cdsOpTimeout, "cds-op-timeout", 30*time.Second, "per-operation timeout for CDS certificate upgrade and CA bundle refresh")
	fs.DurationVar(&c.certPipelineProbeTimeout, "cert-pipeline-probe-timeout", 5*time.Second, "HTTP client timeout for cert pipeline health probe requests")
	fs.DurationVar(&c.certPipelineProbeInterval, "cert-pipeline-probe-interval", 60*time.Second, "interval between cert pipeline health probe requests")
}

func runProxy(ctx context.Context, c *proxyConfig) error {
	logger, err := certutil.NewJSONLogger(c.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	if c.nodeIP == "" {
		c.nodeIP = os.Getenv("NODE_IP")
	}
	if c.nodeIP == "" {
		return fmt.Errorf("node IP required: set --node-ip or NODE_IP env var")
	}
	canonicalNodeIP := normalizeIP(c.nodeIP)
	if canonicalNodeIP == "" {
		return fmt.Errorf("--node-ip %q must be a valid IP address", c.nodeIP)
	}
	c.nodeIP = canonicalNodeIP

	if err := validateConfig(c.attestationApiURL, c.outboundPort, c.inboundPort, c.healthPort, c.certTTL); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	clientset, err := newKubeClientset(c.kubeconfig)
	if err != nil {
		return err
	}
	resolver, err := newK8sResolver(ctx, clientset, c.nodeIP, c.localCIDRBootTimeout, logger)
	if err != nil {
		return fmt.Errorf("k8s resolver: %w", err)
	}

	asClient := attestclient.NewClientWithHTTP("", &http.Client{
		Timeout: c.rotationTimeout,
	})
	attestFunc := makeAttestFunc(asClient, c.attestationApiURL)

	// Resolve before the flat fields are read: every gate below reads them,
	// so a config-mode start must fill them first.
	pins, err := resolveMeasurementsConfig(c)
	if err != nil {
		return err
	}

	meshPolicy, err := meshVerifyPolicy(c.attestationApiURL, c.measurements, c.rtmrs)
	if err != nil {
		return err
	}
	meshPolicy.Policy.Images = pins.Images
	if len(meshPolicy.Policy.Measurements) > 0 {
		logger.Info("measurement pinning enabled", "count", len(meshPolicy.Policy.Measurements))
	} else {
		logger.Warn("no --measurements set: accepting any TEE attestation (unsafe for production)")
	}
	if len(meshPolicy.Policy.Registers) > 0 {
		logger.Info("TDX RTMR pinning enabled for mesh peers", "count", len(meshPolicy.Policy.Registers))
	} else if c.platform == "tdx" && len(meshPolicy.Policy.Measurements) > 0 {
		logger.Warn("no --rtmrs set: TDX measurement pinning covers TDVF firmware only (MRTD); peer guest kernel and rootfs are not pinned")
	}

	var caCerts []*x509.Certificate
	if c.caCertPath != "" {
		var caErr error
		caCerts, caErr = certutil.LoadPEMCertificatesFile(c.caCertPath)
		if caErr != nil {
			return fmt.Errorf("load CA certificate(s) from %q: %w", c.caCertPath, caErr)
		}
		names := make([]string, len(caCerts))
		for i, cert := range caCerts {
			names[i] = cert.Subject.CommonName
		}
		logger.Info("CA certificate(s) loaded for dual-mode verification", "count", len(caCerts), "subjects", names)
	}

	if c.certMode != "self-signed" && c.certMode != "cds" {
		return fmt.Errorf("invalid --cert-mode %q (valid: self-signed, cds)", c.certMode)
	}
	if c.certMode == "cds" && (c.cdsURL == "" || c.attestationApiURL == "") {
		return fmt.Errorf("--cds-url and --attestation-api-url are required for --cert-mode cds")
	}
	teeType, err := armtlsTEEType(c.platform)
	if err != nil {
		return err
	}
	if err := checkTEEMatchesPlatform(pins, teeType); err != nil {
		return err
	}
	if err := checkTEEMatchesPlatform(c.cdsPins, teeType); err != nil {
		return err
	}
	effectiveCAURL := effectiveCDSCAURL(c.certMode, c.cdsURL)
	cdsMeasurements, err := refvalues.ParseHexMeasurements(c.cdsMeasurements)
	if err != nil {
		return fmt.Errorf("--cds-measurements: %w", err)
	}
	cdsRTMRs, err := refvalues.ParseRegisterPinsString(c.cdsRTMRs)
	if err != nil {
		return fmt.Errorf("--cds-rtmrs: %w", err)
	}
	if c.certMode == "cds" && len(cdsMeasurements) == 0 {
		logger.Warn("--cds-measurements not set; the ARmTLS handshake will accept any CDS measurement. Set this to the chart-distributed launch digest of CDS to close bootstrap MITM.")
	}

	// The self-signed boot cert carries no SAN: mesh peers authenticate it by
	// hardware attestation, not by SAN/hostname (NewServerTLSConfig sets
	// InsecureSkipVerify and verifies the ARmTLS extension). The CDS-issued
	// upgrade cert does carry a DNS SAN (see cdsclient.Config.DNSSAN).
	runtime, err := newMeshRuntime(&armtls.ServerConfig{
		Platform:        c.platform,
		AttestFunc:      attestFunc,
		CertTTL:         c.certTTL,
		ClientPolicy:    meshPolicy,
		CACert:          caCerts,
		DynamicCACert:   effectiveCAURL != "",
		RotationTimeout: c.rotationTimeout,
		Logger:          logger,
	}, logger, c.sessionCacheSize)
	if err != nil {
		return err
	}
	cdsCfg := &cdsclient.Config{
		CDSURL:            c.cdsURL,
		AttestationApiURL: c.attestationApiURL,
		CDSCAURL:          c.cdsURL,
		CACertURL:         effectiveCAURL,
		NodeIP:            c.nodeIP,
		DNSSAN:            c.certDNSSAN,
		TEEType:           teeType,
		CDSMeasurements:   cdsMeasurements,
		CDSRTMRs:          cdsRTMRs,
		CDSImages:         c.cdsPins.Images,
	}
	if err := runtime.run(ctx, hostMesh{c: c, resolver: resolver, cds: cdsCfg}); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

type hostMesh struct {
	c        *proxyConfig
	resolver *k8sResolver
	cds      *cdsclient.Config
}

func (e hostMesh) configure(r *meshRuntime) *Proxy {
	c, resolver := e.c, e.resolver
	if c.certMode == "cds" {
		r.metrics.certModeConfigured.Store(1)
	}
	r.health = newHealthServer(r.metrics, r.serverCertMgr, r.clientCertMgr, c.acceptErrThreshold, c.healthReadTimeout, c.healthWriteTimeout)
	r.healthPort, r.healthListener = c.healthPort, c.listeners.health
	var connSem chan struct{}
	if c.maxConns > 0 {
		connSem = make(chan struct{}, c.maxConns)
	}

	return &Proxy{
		outboundAddr:      fmt.Sprintf(":%d", c.outboundPort),
		inboundAddr:       fmt.Sprintf(":%d", c.inboundPort),
		outboundLn:        c.listeners.outbound,
		inboundLn:         c.listeners.inbound,
		nodeIP:            c.nodeIP,
		inboundPort:       c.inboundPort,
		resolver:          resolver,
		accessLog:         c.accessLog,
		dialTimeout:       c.dialTimeout,
		tlsDialTimeout:    c.tlsDialTimeout,
		destHeaderTimeout: c.destHeaderTimeout,
		drainTimeout:      c.drainTimeout,
		keepAlive:         c.keepAlive,
		idleTimeout:       c.idleTimeout,
		maxDestHeaderSize: c.maxDestHeaderSize,
		pipeBufferSize:    c.pipeBufferSize,
		connSem:           connSem,
		maxConnsPerSrc:    c.maxConnsPerSource,
	}
}

func (e hostMesh) start(ctx context.Context, r *meshRuntime) {
	c, resolver := e.c, e.resolver
	logger, m, proxy := r.logger, r.metrics, r.proxy
	serverCertMgr, clientCertMgr := r.serverCertMgr, r.clientCertMgr
	// Periodically update resolver cache and cert expiry metrics.
	go func() {
		t := time.NewTicker(c.metricsUpdateInterval)
		defer t.Stop()
		// iptablesMetricsSeen flips true on the first successful read of the
		// sidecar metrics file. Before that, ENOENT is the cold-start path
		// and stays at Debug; after, every read failure (including ENOENT)
		// is escalated to Warn because something stopped writing.
		var iptablesMetricsSeen bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.resolverCacheSize.Set(float64(resolver.CacheSize()))
				m.resolverLocalCIDRs.Set(float64(resolver.LocalCIDRCount()))
				m.resolverLastEvent.Set(float64(resolver.LastEventTime()))
				switch err := m.refreshIptablesMetrics(c.iptablesMetricsFile); {
				case err == nil:
					iptablesMetricsSeen = true
				case iptablesMetricsSeen:
					logger.Warn("read iptables metrics file failed after prior success; sidecar may be wedged", "path", c.iptablesMetricsFile, "error", err)
				case !errors.Is(err, fs.ErrNotExist):
					logger.Debug("read iptables metrics file failed", "path", c.iptablesMetricsFile, "error", err)
				}

				if exp := serverCertMgr.CertExpiry(); !exp.IsZero() {
					m.certExpiry.WithLabelValues("server").Set(float64(exp.Unix()))
				}
				if clientCertMgr != nil {
					if exp := clientCertMgr.CertExpiry(); !exp.IsZero() {
						m.certExpiry.WithLabelValues("client").Set(float64(exp.Unix()))
					}
				}
			}
		}
	}()

	if c.certMode == "cds" && r.startCDS(ctx, e.cds, cdsUpgrade{
		logPrefix: "cds", retryBackoff: c.cdsRetryBackoff,
		retryMaxBackoff: c.cdsRetryMaxBackoff, opTimeout: c.cdsOpTimeout,
	}, c.caPollInterval) {
		logger.Info("CA bundle refresh enabled", "url", e.cds.CACertURL, "interval", c.caPollInterval)
	}

	// Cert pipeline health probe: periodically check CDS /readyz.
	if c.certPipelineProbeURL != "" {
		m.certPipelineHealthy.Set(0) // Start as unhealthy until first probe succeeds.
		go func() {
			client := &http.Client{Timeout: c.certPipelineProbeTimeout}
			ticker := time.NewTicker(c.certPipelineProbeInterval)
			defer ticker.Stop()

			// lastHealth is kept goroutine-local for the transition-log gate;
			// the metric value is whatever Set was last called with.
			lastHealth := -1
			probe := func() {
				health := 0
				resp, err := client.Get(c.certPipelineProbeURL)
				if err != nil || resp.StatusCode != http.StatusOK {
					if lastHealth != 0 {
						logger.Warn("cert pipeline probe failed", "url", c.certPipelineProbeURL, "error", err)
					}
					if resp != nil {
						resp.Body.Close()
					}
				} else {
					resp.Body.Close()
					health = 1
					if lastHealth != 1 {
						logger.Info("cert pipeline probe healthy", "url", c.certPipelineProbeURL)
					}
				}
				lastHealth = health
				m.certPipelineHealthy.Set(float64(health))
			}

			probe() // Initial probe immediately.
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					probe()
				}
			}
		}()
		logger.Info("cert pipeline health probe enabled", "url", c.certPipelineProbeURL)
	}
	// When the probe is not configured, the gauge stays at its initial -1
	// (set in newMetrics) — operators can branch on -1 to know it isn't a
	// real "unhealthy" signal.

	logger.Info("starting armtls-mesh",
		"outbound", proxy.outboundAddr,
		"inbound", proxy.inboundAddr,
		"node", c.nodeIP,
		"platform", c.platform,
		"cert_mode", c.certMode,
		"resolver", "k8s",
		"health_port", c.healthPort,
		"max_conns", c.maxConns,
		"max_conns_per_source", c.maxConnsPerSource,
		"idle_timeout", c.idleTimeout,
		"keepalive", c.keepAlive,
		"session_cache_size", c.sessionCacheSize,
	)
}

type iptablesSyncConfig struct {
	outboundPort            int
	kubeconfig              string
	uid                     int
	excludeUIDs             string
	excludeSourceNamespaces string
	nodeIPs                 []string
	resyncPeriod            time.Duration
	watchdogPeriod          time.Duration
	ipsetMaxElem            int
	cwInboundPassthrough    string
	readyFile               string
	readyAddr               string
	metricsFile             string
	logLevel                string
}

func newIptablesSyncCommand() *cobra.Command {
	var cfg iptablesSyncConfig
	cmd := &cobra.Command{
		Use:           "iptables-sync",
		Short:         "Watch K8s pods and keep iptables/ipset routing current",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIptablesSync(cmd.Context(), &cfg)
		},
	}
	fs := cmd.Flags()
	fs.IntVar(&cfg.outboundPort, "outbound-port", 15001, "outbound listener port")
	fs.StringVar(&cfg.kubeconfig, "kubeconfig", "", "path to a kubeconfig for the pod watch; empty uses the in-cluster service-account config")
	fs.IntVar(&cfg.uid, "uid", defaultProxyUID, "UID to exclude from redirect")
	fs.StringVar(&cfg.excludeUIDs, "exclude-uids", "0", "comma-separated UIDs to skip (e.g. root=0 so kubelet/containerd can reach registries)")
	fs.StringVar(&cfg.excludeSourceNamespaces, "exclude-source-namespaces", defaultMeshExcludedSourceNamespacesCSV(), "comma-separated local source namespaces excluded from transparent mesh interception")
	fs.StringSliceVar(&cfg.nodeIPs, "node-ip", nil, "local node IP(s); repeat or comma-separate for dual-stack (one per family). Defaults to NODE_IP env. Each address must be a non-loopback, non-unspecified IP bound to a local interface.")
	fs.DurationVar(&cfg.resyncPeriod, "resync-period", 30*time.Second, "periodic full ipset reconciliation interval")
	fs.DurationVar(&cfg.watchdogPeriod, "watchdog-period", 2*time.Second, "interval at which the base-chain jump rules are re-asserted at the head of their chain (bounds the race window against kube-proxy reinserting KUBE-SERVICES)")
	fs.IntVar(&cfg.ipsetMaxElem, "ipset-maxelem", defaultIPSetMaxElem, "maximum members per managed ipset")
	fs.StringVar(&cfg.cwInboundPassthrough, "cw-inbound-passthrough", formatCWPassthrough(defaultCWPassthrough), "comma-separated proto:source-port replies exempted from the always-on cw inbound guard (which drops FORWARD-path traffic to confidential.ai/cw pods). Each entry matches only a destination port in 32768-60999 and, for TCP, a reply segment shape. Empty = strict drop-all; DNS is the default")
	fs.StringVar(&cfg.readyFile, "ready-file", "", "path to write after initial ipset and iptables sync succeeds")
	fs.StringVar(&cfg.readyAddr, "ready-addr", "", "host:port serving GET /readyz, 200 once the initial sync succeeded (empty disables it). The DaemonSet's startup probe uses it: a locked node image denies exec probes")
	fs.StringVar(&cfg.metricsFile, "iptables-metrics-file", defaultIptablesMetricsFile, "shared file where iptables-sync publishes counters (empty disables)")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	return cmd
}

func newIptablesCleanupCommand() *cobra.Command {
	var (
		keepGuard   bool
		onShutdown  bool
		settleDelay time.Duration
	)
	cmd := &cobra.Command{
		Use:   "iptables-cleanup",
		Short: "Remove iptables NAT rules and ipsets created by the mesh",
		Long: `iptables-cleanup removes the mesh's iptables rules and ipsets.

With --keep-guard the fail-closed guard (ARMTLS-MESH-CW and
ARMTLS-MESH-CW-EGRESS filter chains, their FORWARD jumps, and the cw pod
ipsets) is left in place while the traffic-interception NAT rules are
removed. The daemonset's cleanup sidecar uses this so a terminating mesh keeps
the guard live: unmeshed inbound and non-TCP egress are still dropped; TCP
to non-pod destinations was never meshed. A full teardown (no
--keep-guard) also removes the guard.

With --on-shutdown the command instead idles until SIGTERM and cleans up
then. That is how the DaemonSet's cleanup sidecar runs it: a locked node
image denies every runc exec, so a lifecycle exec hook would never run.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !onShutdown {
				return runIptablesCleanup(keepGuard)
			}
			if settleDelay < 0 {
				return fmt.Errorf("--settle-delay must not be negative, got %s", settleDelay)
			}
			// Native sidecars stop in reverse init order, so this SIGTERM
			// arrives after the proxy has drained — the ordering the preStop
			// hook used to give.
			<-cmd.Context().Done()
			if err := runIptablesCleanup(keepGuard); err != nil {
				return err
			}
			// Stay alive briefly so the pod's last flows finish against the
			// cleaned-up rules rather than a half-torn-down netns.
			time.Sleep(settleDelay)
			return nil
		},
	}
	cmd.Flags().BoolVar(&keepGuard, "keep-guard", false,
		"keep the fail-closed filter guard (cw chains + cw ipsets) while removing interception")
	cmd.Flags().BoolVar(&onShutdown, "on-shutdown", false,
		"idle until SIGTERM, then clean up (the DaemonSet sidecar's mode)")
	cmd.Flags().DurationVar(&settleDelay, "settle-delay", 0,
		"with --on-shutdown, how long to stay alive after cleanup")
	return cmd
}

// validateConfig checks for misconfigurations that would cause cryptic runtime
// failures. Called once at startup before any goroutine.
func validateConfig(attestationApiURL string, outboundPort, inboundPort, healthPort int, certTTL time.Duration) error {
	if attestationApiURL == "" {
		return fmt.Errorf("--attestation-api-url is required")
	}
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", attestationApiURL); err != nil {
		return err
	}
	if err := validatePort("--outbound-port", outboundPort); err != nil {
		return err
	}
	if err := validatePort("--inbound-port", inboundPort); err != nil {
		return err
	}
	if err := validatePort("--health-port", healthPort); err != nil {
		return err
	}
	for _, pair := range []struct {
		aFlag, bFlag string
		aPort, bPort int
	}{
		{"--outbound-port", "--inbound-port", outboundPort, inboundPort},
		{"--outbound-port", "--health-port", outboundPort, healthPort},
		{"--inbound-port", "--health-port", inboundPort, healthPort},
	} {
		if pair.aPort == pair.bPort {
			return fmt.Errorf("%s and %s must differ (both are %d)", pair.aFlag, pair.bFlag, pair.aPort)
		}
	}
	if certTTL < time.Minute {
		return fmt.Errorf("--cert-ttl %s is too short (minimum 1m to avoid rotation thrashing)", certTTL)
	}
	return nil
}

func validatePort(flag string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s %d out of range (1-65535)", flag, port)
	}
	return nil
}

// makeAttestFunc returns an AttestFunc that calls the attestation-api
// via attestclient. Used for ARmTLS self-signed certificates.
func makeAttestFunc(client attestclient.Client, attestationApiURL string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		// customData is hex-encoded REPORTDATA (e.g. SHA-384 of pubkey,
		// zero-padded to 64 bytes for the SNP REPORTDATA field).
		reportDataBytes, err := hex.DecodeString(customData)
		if err != nil {
			return "", fmt.Errorf("decode report data hex: %w", err)
		}

		// Strip SNP REPORTDATA zero-padding before sending to the attestation
		// service. Bare-metal SNP pads server-side; vTPM passes the data as
		// the TPM2_Quote nonce (TPM2B_DATA) which has a smaller max size than
		// 64 bytes, so sending the full padded array causes TPM_RC_SIZE.
		reportDataBytes = reportDataBytes[:sha512.Size384]

		resp, err := client.GenerateEvidence(attestationApiURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation-api: %w", err)
		}

		return attestclient.ARMTLSEvidence(resp)
	}
}

// meshVerifyPolicy builds the mesh peer-verification policy: evidence checked
// by the same-node attestation-api, launch measurements pinned to the
// --measurements allowlist, and TDX peers additionally pinned to the --rtmrs
// registers. Empty measurements leaves the policy unpinned (accept any TEE —
// development only).
func meshVerifyPolicy(attestationApiURL, measurements, rtmrs string) (*armtls.VerifyPolicy, error) {
	policy := &armtls.VerifyPolicy{AttestationApiURL: attestationApiURL}
	pins, err := refvalues.ParseRegisterPinsString(rtmrs)
	if err != nil {
		return nil, fmt.Errorf("--rtmrs: %w", err)
	}
	policy.Policy.Registers = pins
	if measurements == "" {
		return policy, nil
	}
	for h := range strings.SplitSeq(measurements, ",") {
		h = strings.TrimSpace(h)
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid measurement hex %q: %w", h, err)
		}
		if len(b) != armtls.SNPMeasurementSize {
			return nil, fmt.Errorf("invalid measurement length: %q is %d bytes, want %d (SHA-384 measurement must be %d hex characters)",
				h, len(b), armtls.SNPMeasurementSize, armtls.SNPMeasurementSize*2)
		}
		policy.Policy.Measurements = append(policy.Policy.Measurements, b)
	}
	return policy, nil
}

func effectiveCDSCAURL(certMode, cdsURL string) string {
	if certMode != "cds" {
		return ""
	}
	return strings.TrimRight(cdsURL, "/") + "/ca"
}

func armtlsTEEType(platform string) (armtls.TEEType, error) {
	switch strings.TrimSpace(platform) {
	case "auto":
		// Probe the guest device tree; attestation-rs's own is_available()
		// does the same check. Prefer TDX over SNP for the (theoretical)
		// mixed case — an operator setting --platform=auto wants a working
		// guest, and choosing arbitrarily is the sanest tiebreaker for a
		// shape we don't ship today.
		if _, err := os.Stat("/dev/tdx_guest"); err == nil {
			return armtls.TEETypeTDX, nil
		}
		if _, err := os.Stat("/dev/sev-guest"); err == nil {
			return armtls.TEETypeSEVSNP, nil
		}
		return "", fmt.Errorf("armtls-mesh: --platform=auto found neither /dev/tdx_guest nor /dev/sev-guest — the node does not expose a TEE device")
	case "":
		return "", fmt.Errorf("--platform is required")
	}
	family, err := teetypes.ParseFamily(platform)
	if err != nil {
		return "", fmt.Errorf("armtls-mesh: unsupported --platform %q", platform)
	}
	return family, nil
}
