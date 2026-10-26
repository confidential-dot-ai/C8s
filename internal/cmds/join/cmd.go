package join

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	// Port is where a server releases agent credentials and agents connect.
	Port = "8444"
	// DefaultTimeout bounds each network step of one enrollment attempt.
	DefaultTimeout = 30 * time.Second
)

// NewReleaseCmd builds the `join-release` subcommand: the in-guest service on
// an rke2 server node that releases the cluster join token, and each agent's
// node password, to attested authorized agents. Baked as a systemd unit in the c8s node image; not run by
// hand in normal operation.
func NewReleaseCmd() *cobra.Command {
	var cfg ReleaseConfig
	cmd := &cobra.Command{
		Use:   "join-release",
		Short: "Release the rke2 agent join token and node passwords to attested authorized agents",
		Long: "join-release serves the RKE2 agent-only token over mutually attested TLS,\n" +
			"with the node password for the name in the agent's signed launch document.\n" +
			"The document must be signed by an agent key in --launch-config, and the\n" +
			"agent must attest an authorized image measured under that same key in\n" +
			"--measurements-config. The policy supports TDX and SEV-SNP.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunRelease(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":"+Port, "HTTPS (armTLS) bind address")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (serving-cert quote source and peer-quote verifier)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (tdx or sev-snp)")
	f.StringVar(&cfg.TokenPath, "token-path", "/var/lib/rancher/rke2/server/agent-token", "rke2 agent-only join token file (appears once rke2-server has initialised)")
	f.StringVar(&cfg.MeasurementsConfig, "measurements-config", "", "authorized agent image/operator policy (required)")
	_ = cmd.MarkFlagRequired("measurements-config")
	f.StringVar(&cfg.LaunchConfig, "launch-config", launchconfig.DefaultStagedPath, "this server's staged launch document")
	f.StringVar(&cfg.NodePasswordKey, "node-password-key", launchconfig.NodePasswordKeyPath, "RAM-backed key node passwords derive from")
	f.StringVar(&cfg.MeasuredPoliciesFile, "measured-policies-file", armtls.NodeJournal, "the node's journal of allowlist policies extended into TDX RTMR[3], listed in the serving certificate. Empty lists none")
	f.DurationVar(&cfg.VerifyTimeout, "verify-timeout", 10*time.Second, "per-request peer verification timeout")
	return cmd
}

// NewJoinCmd builds the `join` subcommand: the one-shot agent-side client
// that fetches the join token over the mutually attested channel and stages
// it for rke2-agent. Baked as a systemd unit ordered before rke2-agent.
func NewJoinCmd() *cobra.Command {
	var cfg JoinConfig
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Fetch the rke2 join token from an attested designated server",
		Long: "join verifies the designated server image and measured operator key\n" +
			"in --measurements-config, presents its own attested client certificate,\n" +
			"sends its signed launch document, and stages the agent token in RAM and\n" +
			"the node password for RKE2. Retries belong to the calling unit.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunJoin(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ServerAddr, "server", "", "join-release endpoint as host:port (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (client-cert quote source and server-quote verifier)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (tdx or sev-snp)")
	f.StringVar(&cfg.TokenOut, "token-out", "/run/confos/join-token", "where to write the token (rejected unless RAM-backed; never persistent storage)")
	f.StringVar(&cfg.MeasurementsConfig, "measurements-config", "", "designated server image/operator policy (required)")
	f.StringVar(&cfg.DocumentPath, "launch-document", launchconfig.Dir+"/"+launchconfig.SignedDocumentFile, "this agent's signed launch document")
	f.StringVar(&cfg.SignaturePath, "launch-signature", launchconfig.Dir+"/"+launchconfig.SignatureFile, "detached signature of --launch-document")
	f.StringVar(&cfg.NodePasswordOut, "node-password-out", launchconfig.NodePasswordPath, "where RKE2 reads this node's password")
	f.StringVar(&cfg.MeasuredPoliciesFile, "measured-policies-file", armtls.NodeJournal, "the node's journal of allowlist policies extended into TDX RTMR[3], listed in the client certificate. Empty lists none")
	_ = cmd.MarkFlagRequired("measurements-config")
	f.DurationVar(&cfg.Timeout, "timeout", DefaultTimeout, "per-step network timeout")
	_ = cmd.MarkFlagRequired("server")
	return cmd
}
