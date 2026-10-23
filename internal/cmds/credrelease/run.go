package credrelease

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// maxConcurrentConns caps accepted sockets. cred-release is the external
// credential choke point and binds every interface, so an unbounded accept
// loop lets any peer that can route to the guest spend its memory and its
// attestation-api budget on handshakes alone.
const maxConcurrentConns = 64

// newServer builds the release HTTP server. The resource bounds live here so
// they are stated once and can be asserted: none of them changes how the
// service answers a legitimate request, so a regression is otherwise silent.
func newServer(addr string, handler http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Allow the bounded body read, attestation, and response write.
		WriteTimeout: attestTimeout + 20*time.Second,
		IdleTimeout:  30 * time.Second,
		// Go's 1MiB default lets one unauthenticated request buy far more
		// memory than any real CSR needs.
		MaxHeaderBytes: 16 << 10,
	}
}

// Config is the release service configuration.
type Config struct {
	// ListenAddr is the HTTPS bind address (e.g. ":8443").
	ListenAddr string
	// listener, when set, is served instead of binding ListenAddr.
	listener net.Listener
	// AttestationAPIURL is the local attestation-api base URL (the same
	// loopback service the rest of the stack uses). It provides the armTLS
	// serving quote, fresh bootstrap evidence, and the verified self-report
	// that anchors the operator key to the launch binding.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx" or "snp"; no default).
	Platform string
	// MeasuredPoliciesFile is the node's measured-policy journal
	// (armtls.NodeJournal). The operator-key binding check replays it, and the
	// serving certificate and /attest responses list it. Empty lists none.
	MeasuredPoliciesFile string
	// ClientCACert / ClientCAKey locate the cluster's client-signing CA
	// (defaults: the RKE2 paths; kubeadm works via /etc/kubernetes/pki/ca.{crt,key}).
	ClientCACert string
	ClientCAKey  string
	// ServerCACert locates the CA that signs the apiserver serving cert — the
	// trust anchor embedded in the released kubeconfig.
	ServerCACert string
	// CertTTL is the lifetime of issued operator certs.
	CertTTL time.Duration
	// CertOrg / CertCN are the Kubernetes group / user the issued cert carries.
	// Authorization is ordinary RBAC on that group: the node image's baked
	// cred-release-rbac AddOn binds defaultCertOrg to the bounded
	// c8s-node-operator ClusterRole (never cluster-admin). Revocation
	// semantics are in docs/operator.md.
	CertOrg string
	CertCN  string
	// LogCertTTL / LogCertOrg / LogCertCN are the same for the log-reader
	// role (RoleLogReader); the node image binds defaultLogCertOrg to the
	// baked c8s-log-reader ClusterRole.
	LogCertTTL time.Duration
	LogCertOrg string
	LogCertCN  string
}

// roles is the per-role identity set the handler issues from this Config.
func (cfg Config) roles() Roles {
	return Roles{
		RoleOperator:  {Org: cfg.CertOrg, CN: cfg.CertCN, TTL: cfg.CertTTL},
		RoleLogReader: {Org: cfg.LogCertOrg, CN: cfg.LogCertCN, TTL: cfg.LogCertTTL},
	}
}

// Run loads the measured operator key and cluster CA, then serves the
// armTLS-protected bootstrap and credential endpoints. It blocks until ctx is done.
//
// Startup order matters for the trust story:
//  1. LoadMeasuredOperatorKey — read the opkeydata pubkey and CONFIRM it
//     matches the launch binding (TDX RTMR[3] / SNP HOSTDATA). Fails closed
//     if the key was substituted after boot.
//  2. loadClusterCA — the cluster client-CA that signs the operator's cert.
//  3. serve over an armTLS config so the caller can attest this is the real
//     guest before trusting the returned cert.
func Run(ctx context.Context, cfg Config) error {
	// armTLS is mandatory here: this endpoint hands out operator creds,
	// so serving without an attested cert (empty platform => plain HTTP in the
	// armtls package) would let a host MITM impersonate the guest. Reject it.
	if strings.TrimSpace(cfg.Platform) == "" {
		return fmt.Errorf("--platform is required (armTLS is mandatory for credential release)")
	}
	// Fail on a bad value here, before the RTMR and cluster-CA reads below.
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil {
		return fmt.Errorf("--platform: %w", err)
	}
	cfg.Platform = family.String()

	operatorPub, err := LoadMeasuredOperatorKey(ctx, cfg.AttestationAPIURL, cfg.MeasuredPoliciesFile)
	if err != nil {
		return fmt.Errorf("load measured operator key: %w", err)
	}

	ca, err := loadClusterCA(cfg.ClientCACert, cfg.ClientCAKey, cfg.ServerCACert)
	if err != nil {
		return fmt.Errorf("load cluster CA: %w", err)
	}

	handler, err := NewHandler(operatorPub, ca, cfg.roles())
	if err != nil {
		return fmt.Errorf("build handler: %w", err)
	}
	attestationClient := attestclient.NewClient("")
	handler.attester = localEvidenceGenerator{client: attestationClient, apiURL: cfg.AttestationAPIURL}
	handler.measuredPolicies = armtls.NewJournal(cfg.MeasuredPoliciesFile)
	return serveARMTLS(ctx, cfg.listener, cfg.ListenAddr, cfg.Platform, cfg.AttestationAPIURL, cfg.MeasuredPoliciesFile, handler)
}

type servingKeyCtx struct{}

// ServingKey returns the public key of the armTLS certificate that served
// the request's connection, or nil outside ServeARMTLS.
func ServingKey(ctx context.Context) crypto.PublicKey {
	if f, ok := ctx.Value(servingKeyCtx{}).(func() crypto.PublicKey); ok {
		return f()
	}
	return nil
}

// WithServingKey is for tests of handlers that call ServingKey.
func WithServingKey(ctx context.Context, pub crypto.PublicKey) context.Context {
	return context.WithValue(ctx, servingKeyCtx{}, func() crypto.PublicKey { return pub })
}

// ServeARMTLS serves handler over armTLS on addr until ctx is done: the
// self-signed serving cert embeds a fresh quote from the local
// attestation-api whose report data binds the cert's own key, so a client
// verifying it (getkubeconfig) knows the channel ends in the measured guest.
// platform must already be a parsed family name. measuredPoliciesFile is the
// RTMR[3] journal the serving cert lists as its runtime extensions; empty
// lists none.
func ServeARMTLS(ctx context.Context, addr, platform, attestationAPIURL, measuredPoliciesFile string, handler http.Handler) error {
	return serveARMTLS(ctx, nil, addr, platform, attestationAPIURL, measuredPoliciesFile, handler)
}

// serveARMTLS is ServeARMTLS over ln when one is given; tests pass a bound
// listener so the port is known before the server accepts.
func serveARMTLS(ctx context.Context, ln net.Listener, addr, platform, attestationAPIURL, measuredPoliciesFile string, handler http.Handler) error {
	// AttestFunc is platform-generic despite the SNP name: it reads
	// resp.Platform, so it yields a TDX quote on TDX; same pattern as cds.
	attestFunc := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), attestationAPIURL)
	tlsCfg, certMgr, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   platform,
		AttestFunc: attestFunc,
		Logger:     slog.Default(),

		MeasuredPoliciesFile: measuredPoliciesFile,
	})
	if err != nil {
		return fmt.Errorf("build armTLS config: %w", err)
	}
	// Provision the serving cert (and its quote) before accepting traffic, so
	// the first request doesn't race a cold cert manager.
	warmCtx, cancelWarm := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up armTLS serving cert: %w", err)
	}

	go certMgr.RunRotation(ctx)

	// Remember which certificate each connection was served with, so a
	// handler can bind evidence to this channel (ServingKey).
	var served sync.Map // underlying net.Conn -> crypto.PublicKey
	getCert := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCert(hello)
		if err == nil {
			// armtls sets Leaf on every certificate it serves.
			served.Store(hello.Conn, cert.Leaf.PublicKey)
		}
		return cert, err
	}
	srv := newServer(addr, handler, tlsCfg)
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			return context.WithValue(ctx, servingKeyCtx{}, func() crypto.PublicKey {
				key, _ := served.Load(tc.NetConn())
				pub, _ := key.(crypto.PublicKey)
				return pub
			})
		}
		return ctx
	}
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		if tc, ok := c.(*tls.Conn); ok && (state == http.StateClosed || state == http.StateHijacked) {
			served.Delete(tc.NetConn())
		}
	}

	// Bind explicitly so the accepted sockets can be capped: every connection
	// costs an armTLS handshake before any request is read.
	if ln == nil {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		// certs come from tlsCfg (armTLS), so no cert/key files.
		errCh <- srv.ServeTLS(netutil.LimitListener(ln, maxConcurrentConns), "", "")
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
