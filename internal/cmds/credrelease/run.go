package credrelease

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

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
	// The self-signed serving cert embeds a fresh quote whose report data
	// binds the cert's own key, so a client verifying it (getkubeconfig)
	// knows the channel ends in the measured guest. The attest func reads
	// resp.Platform, so it yields a TDX quote on TDX despite its SNP name.
	// cfg.listener, when set, is served instead of binding ListenAddr.
	return armtls.ServeListener(ctx, cfg.listener, cfg.ListenAddr, handler, &armtls.ServerConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestationClient, cfg.AttestationAPIURL),
		Logger:     slog.Default(),

		MeasuredPoliciesFile: cfg.MeasuredPoliciesFile,
	})
}
