package podlaunch

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// NewCmd returns the pod CVM launch configuration commands: the operator-side
// document generator and the guest-side stage.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "launch-config", Short: "Create and stage a pod CVM's signed launch configuration"}
	cmd.AddCommand(newPodBundleCmd(), newStageCmd())
	return cmd
}

func newPodBundleCmd() *cobra.Command {
	var opts PodBundleOptions
	cmd := &cobra.Command{
		Use:   "new-pod",
		Short: "Create a signed Pod CVM launch document",
		Long: `Write a role-pod launch document for one pod CVM, signed with the pod
launch key:

  <out>/pod.key   pod launch key (omitted when --launch-key is given)
  <out>/pod/      pubkey, launch.yaml, launch.yaml.sig: the pod CVM's opkeydata

The document names no pod and carries no allowlist entries: the guest boots
generic, serves its status service and waits for one authenticated assignment
signed with the pod launch key, which delivers the pod, its entries and its
mesh peers. The guest polls CDS at --cds-address, authenticated with the
launch-file-bound --cds-image-policy-file.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := NewPodBundle(opts); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote pod launch bundle %s\n", filepath.Join(opts.Dir, podDir))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ClusterID, "cluster-id", "", "cluster name, an RFC1123 label")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the exact TDX node image to boot")
	f.StringVar(&opts.NodeName, "name", "", "node name of this pod CVM, an RFC1123 label")
	f.StringVar(&opts.LaunchKeyPath, "launch-key", "", "existing pod launch key PEM (default: generate <out>/pod.key)")
	f.StringVar(&opts.CDSAddress, "cds-address", "", "external CDS host:port")
	f.StringVar(&opts.CDSImagePolicyPath, "cds-image-policy-file", "", "measurements document binding the external CDS image to its exact launch file")
	f.StringVar(&opts.CDSChain, "cds-chain", "", "<seq>:<hash> of one entry of the CDS replica set's chain the pod CVM pins (docs/cds-ha.md)")
	cmdsutil.RequireFlags(cmd, "out", "cluster-id", "image-manifest", "name", "cds-address", "cds-image-policy-file")
	return cmd
}

func newStageCmd() *cobra.Command {
	var cfg Config
	stage := &cobra.Command{
		Use: "stage", Short: "Verify a pod CVM's signed launch configuration and stage it",
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := Stage(cmd.Context(), cfg); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "authenticated launch configuration staged")
			return nil
		},
	}
	f := stage.Flags()
	f.StringVar(&cfg.Platform, "platform", "", "image TEE platform: tdx or snp (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", DefaultAttestationAPIURL, "trusted node-local attestation API")
	f.StringVar(&cfg.DocumentPath, "config", "", "required signed launch.yaml")
	f.StringVar(&cfg.SignaturePath, "signature", "", "required detached launch.yaml.sig")
	f.StringVar(&cfg.MeasuredPoliciesFile, "measured-policies-file", armtls.NodeJournal, "the guest's RTMR[3] journal; the launch-key binding check replays it. Empty replays none")
	cmdsutil.RequireFlags(stage, "platform", "config", "signature")
	return stage
}
