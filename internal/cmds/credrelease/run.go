package credrelease

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
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
	// AttestationAPIURL is the local attestation-api base URL (the same
	// loopback service the rest of the stack uses). It provides the ARmTLS
	// serving quote, fresh bootstrap evidence, and the verified self-report
	// that anchors the operator key to the launch binding.
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx" or "snp"; no default).
	Platform string
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
// ARmTLS-protected bootstrap and credential endpoints. It blocks until ctx is done.
//
// Startup order matters for the trust story:
//  1. LoadMeasuredOperatorKey — read the opkeydata pubkey and CONFIRM it
//     matches the launch binding (TDX RTMR[3] / SNP HOSTDATA). Fails closed
//     if the key was substituted after boot.
//  2. loadClusterCA — the cluster client-CA that signs the operator's cert.
//  3. serve over an ARmTLS config so the caller can attest this is the real
//     guest before trusting the returned cert.
func Run(ctx context.Context, cfg Config) error {
	// ARmTLS is mandatory here: this endpoint hands out operator creds,
	// so serving without an attested cert (empty platform => plain HTTP in the
	// armtls package) would let a host MITM impersonate the guest. Reject it.
	if strings.TrimSpace(cfg.Platform) == "" {
		return fmt.Errorf("--platform is required (ARmTLS is mandatory for credential release)")
	}
	// Fail on a bad value here, before the RTMR and cluster-CA reads below.
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil {
		return fmt.Errorf("--platform: %w", err)
	}
	cfg.Platform = family.String()

	operatorPub, err := LoadMeasuredOperatorKey(ctx, cfg.AttestationAPIURL)
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

	// ARmTLS serving config: the presented cert embeds a fresh TDX quote
	// bound to its own public key, so the operator's ARmTLS client verifies
	// it's talking to a genuine, correctly-measured guest before sending the
	// CSR or trusting the returned cert. AttestFunc fetches the quote from the
	// local attestation-api (platform-generic despite the SNP name — it reads
	// resp.Platform, so it yields a TDX quote here); same pattern as cds.
	attestFunc := attestclient.MakeSNPARMTLSAttestFunc(attestationClient, cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("build ARmTLS config: %w", err)
	}
	// Provision the serving cert (and its quote) before accepting traffic, so
	// the first request doesn't race a cold cert manager.
	warmCtx, cancelWarm := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up ARmTLS serving cert: %w", err)
	}

	srv := newServer(cfg.ListenAddr, handler, tlsCfg)

	// Bind explicitly so the accepted sockets can be capped: every connection
	// costs an ARmTLS handshake before the operator token is ever checked.
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		// certs come from tlsCfg (ARmTLS), so no cert/key files.
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
