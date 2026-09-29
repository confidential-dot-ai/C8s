package join

import (
	"time"

	"github.com/spf13/cobra"
)

const (
	// Port is where a server releases the agent token and agents connect.
	Port = "8444"
	// DefaultTimeout bounds each network step of one enrollment attempt.
	DefaultTimeout = 30 * time.Second
)

// NewReleaseCmd builds the `join-release` subcommand: the in-guest service on
// an rke2 server node that releases the cluster join token to attested
// authorized agents. Baked as a systemd unit in the c8s node image; not run by
// hand in normal operation.
func NewReleaseCmd() *cobra.Command {
	var cfg ReleaseConfig
	cmd := &cobra.Command{
		Use:   "join-release",
		Short: "Release the rke2 agent join token to attested authorized agents",
		Long: "join-release serves the RKE2 agent-only token over mutually attested TLS.\n" +
			"Each agent must match an authorized image and measured operator key\n" +
			"in --measurements-config. The policy supports TDX and SEV-SNP.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunRelease(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":"+Port, "HTTPS (RA-TLS) bind address")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (serving-cert quote source and peer-quote verifier)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (tdx or sev-snp)")
	f.StringVar(&cfg.TokenPath, "token-path", "/var/lib/rancher/rke2/server/agent-token", "rke2 agent-only join token file (appears once rke2-server has initialised)")
	f.StringVar(&cfg.MeasurementsConfig, "measurements-config", "", "authorized agent image/operator policy (required)")
	_ = cmd.MarkFlagRequired("measurements-config")
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
			"and stages the agent token in RAM. Retries belong to the calling unit.",
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
	_ = cmd.MarkFlagRequired("measurements-config")
	f.DurationVar(&cfg.Timeout, "timeout", DefaultTimeout, "per-step network timeout")
	_ = cmd.MarkFlagRequired("server")
	return cmd
}
