package podstatus

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// NewCmd returns `pod-status serve` (guest) and `pod-status get` (client).
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pod-status", Short: "Serve or read a pod CVM's attested pod status"}
	cmd.AddCommand(newServeCmd())
	return cmd
}

func newServeCmd() *cobra.Command {
	var cfg ServeConfig
	cmd := &cobra.Command{
		Use:          "serve",
		Short:        "Serve the signed static pod's kubelet status over armTLS (pod role)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, _ []string) error { return Serve(cmd.Context(), cfg) },
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":8443", "HTTPS listen address")
	f.StringVar(&cfg.Platform, "platform", "", "TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", launchconfig.DefaultAttestationAPIURL, "node-local attestation API")
	f.StringVar(&cfg.KubeletURL, "kubelet-url", "https://127.0.0.1:10250", "loopback kubelet base URL")
	f.StringVar(&cfg.KubeletCert, "kubelet-cert", KubeletCertPath, "the kubelet's self-signed serving certificate, pinned on every dial")
	f.StringVar(&cfg.StagedPath, "staged", launchconfig.DefaultStagedPath, "staged launch configuration")
	f.StringVar(&cfg.JournalPath, "journal", armtls.NodeJournal, "RTMR[3] journal of measured workload digests, kept by nri-image-policy")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}
