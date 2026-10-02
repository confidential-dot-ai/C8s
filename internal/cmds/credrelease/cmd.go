package credrelease

import (
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultCertTTL = 7 * 24 * time.Hour
	defaultCertOrg = "c8s:node-operators"
	defaultCertCN  = "operator"
	// The log-reader identity is handed on to people who cannot re-release
	// it themselves (only the operator key can); it lives a week like the
	// operator cert so released kubeconfigs need weekly, not daily, renewal.
	defaultLogCertTTL = 7 * 24 * time.Hour
	defaultLogCertOrg = "c8s:log-readers"
	defaultLogCertCN  = "log-reader"
)

// NewCmd builds the `cred-release` subcommand: the in-guest service that
// issues an operator a short-lived kube client cert, gated on possession of
// the operator key bound into the launch identity (TDX RTMR[3] / SNP
// HOSTDATA). Baked as a systemd unit in the c8s node image; not run by hand
// in normal operation.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "cred-release",
		Short: "Release a kube operator credential to the attested holder of the launch-bound key",
		Long: "cred-release serves an RA-TLS endpoint that issues a short-lived\n" +
			"kube client certificate to a caller who proves possession of the\n" +
			"operator key whose public half was bound into the launch identity\n" +
			"(TDX: RTMR[3]; SNP: HOSTDATA) at launch.\n" +
			"It gives an external operator console-free, non-TOFU, RBAC-backed\n" +
			"operator access with no pre-shared secret and no trust in the\n" +
			"host. The same key may instead request a log-reader cert (role\n" +
			"log-reader: pods and their logs, nothing else) to hand on to\n" +
			"someone who should not hold the operator role.\n" +
			"The cert is signed by the cluster's client CA and the\n" +
			"kubeconfig anchors to the serving CA (RKE2 paths by default; any\n" +
			"distribution works via --client-ca-cert/--client-ca-key/\n" +
			"--server-ca-cert — on kubeadm all three are\n" +
			"/etc/kubernetes/pki/ca.crt). Authorization is the cluster's RBAC on\n" +
			"the issued group: the c8s node image bakes ClusterRoleBindings for\n" +
			"the default --cert-org and --log-cert-org; elsewhere create them or\n" +
			"pass groups the cluster already binds, or every request is denied.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return Run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":8443", "HTTPS (RA-TLS) bind address")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (RA-TLS serving quote; on SNP also the HOSTDATA self-verify)")
	f.StringVar(&cfg.Platform, "platform", "", "TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.ClientCACert, "client-ca-cert", defaultClientCACert, "cluster client-CA cert that signs kube client certs (kubeadm: /etc/kubernetes/pki/ca.crt)")
	f.StringVar(&cfg.ClientCAKey, "client-ca-key", defaultClientCAKey, "cluster client-CA key (kubeadm: /etc/kubernetes/pki/ca.key)")
	f.StringVar(&cfg.ServerCACert, "server-ca-cert", defaultServerCACert, "CA that signs the apiserver serving cert; embedded in the released kubeconfig (kubeadm: /etc/kubernetes/pki/ca.crt)")
	f.DurationVar(&cfg.CertTTL, "cert-ttl", defaultCertTTL, "lifetime of issued operator certs")
	f.StringVar(&cfg.CertOrg, "cert-org", defaultCertOrg, "Kubernetes group (cert Subject O) for the issued cert; the cluster's RBAC must bind it (the c8s node image binds the default to the baked, bounded c8s-node-operator ClusterRole)")
	f.StringVar(&cfg.CertCN, "cert-cn", defaultCertCN, "Kubernetes user (cert Subject CN) for the issued cert")
	f.DurationVar(&cfg.LogCertTTL, "log-cert-ttl", defaultLogCertTTL, "lifetime of issued log-reader certs")
	f.StringVar(&cfg.LogCertOrg, "log-cert-org", defaultLogCertOrg, "Kubernetes group (cert Subject O) for log-reader certs; the cluster's RBAC must bind it (the c8s node image binds the default to the baked c8s-log-reader ClusterRole)")
	f.StringVar(&cfg.LogCertCN, "log-cert-cn", defaultLogCertCN, "Kubernetes user (cert Subject CN) for log-reader certs")
	// No default: the baked unit always passes the flag explicitly.
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}
