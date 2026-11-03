package podstatus

import (
	"encoding/json"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// NewAttestCmd returns `pod-attest`.
func NewAttestCmd() *cobra.Command {
	var cfg AttestConfig
	cmd := &cobra.Command{
		Use:   "pod-attest",
		Short: "Verify a pod CVM's image, launch key and RTMR[3]-measured workloads",
		Long: `Send a random nonce to <node>:8443, verify the fresh evidence (platform
chain, image tuple from the manifest, report data = nonce), fetch the
measured digest list and require RTMR[3] = launch-key seed extended by
those digests in order. Prints {image, launch_key_sha256, measured_digests,
rtmr3}. With --expect-digest, the measured set must equal the given set.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, client, err := Attest(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			client.CloseIdleConnections()
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		},
	}
	addClientFlags(cmd, &cfg)
	cmd.Flags().StringArrayVar(&cfg.ExpectDigests, "expect-digest", nil, "image digest (sha256:<hex> or name@sha256:<hex>) the pod must have measured; repeatable; the measured set must equal the given set")
	return cmd
}

func addClientFlags(cmd *cobra.Command, cfg *AttestConfig) {
	f := cmd.Flags()
	f.StringVar(&cfg.Node, "node", "", "pod CVM host or IP (port 8443 unless host:port)")
	f.StringVar(&cfg.LaunchKeyPubPath, "launch-key-pub", "", "pod launch public key PEM (the bundle's pod/pubkey)")
	f.StringVar(&cfg.ImageManifestPath, "image-manifest", "", "manifest.json of the exact node image the pod CVM booted")
	f.DurationVar(&cfg.Timeout, "timeout", 60*time.Second, "overall timeout, including evidence verification")
	for _, name := range []string{"node", "launch-key-pub", "image-manifest"} {
		_ = cmd.MarkFlagRequired(name)
	}
}

// NewCmd returns `pod-status serve` (guest) and `pod-status get` (client).
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pod-status", Short: "Serve or read a pod CVM's attested pod status"}
	cmd.AddCommand(newServeCmd(), newGetCmd())
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

func newGetCmd() *cobra.Command {
	var cfg AttestConfig
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Verify a pod CVM (image + pod launch key) and print its pod status JSON",
		Long: `Attest the pod CVM as pod-attest does, then print GET /v1/pod: the
pod's uid, namespace and name and the kubelet's phase, conditions and
container states, in v1 Pod field names. The service serves no spec, no
labels or annotations, no addresses and no reason or message text. Fails
non-zero if verification fails.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := Get(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
	addClientFlags(cmd, &cfg)
	return cmd
}
