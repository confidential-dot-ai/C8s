package launchconfig

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
)

// NewCmd returns the authenticated launch configuration command group: the
// operator-side bundle generator and the guest-side stage.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "launch-config", Short: "Create, extend and stage a measured node's signed launch configuration"}
	cmd.AddCommand(newBundleCmd(), newAddAgentCmd(), newStageCmd())
	return cmd
}

func newBundleCmd() *cobra.Command {
	var opts BundleOptions
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a cluster's launch bundle: keys and signed server/agent documents",
		Long: `Create everything one cluster needs to boot from the measured node image:
a server launch key and an agent launch key, a signed launch.yaml per node
and the client policy that pins the server. Documents carry no credentials:
the server mints the RKE2 agent token in RAM and releases it only to agents
that attest as one of the bundle's signed image and key tuples.

  <out>/server.key    server launch key; also the operator key for
                      'c8s get-kubeconfig --operator-key' and signed CDS writes
  <out>/agent.key     the agent launch key; 'add-agent' reuses it
  <out>/server.json   C8S_MEASUREMENTS_CONFIG for clients of this cluster
  <out>/server/       pubkey, launch.yaml, launch.yaml.sig: the server's opkeydata
  <out>/<agent>/      the same three files for each --agent

Attach each node directory as its opkeydata disk (an ISO labelled opkeydata,
or a KubeVirt Secret volume with volumeLabel opkeydata). On SNP, also set
HOST_DATA to SHA-256 of that node's pubkey file. See docs/operator.md,
"Authenticated launch configuration".`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := NewBundle(opts); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote launch bundle %s: %s", opts.Dir, filepath.Join(opts.Dir, serverDir))
			for _, name := range opts.Agents {
				fmt.Fprintf(cmd.OutOrStdout(), ", %s", filepath.Join(opts.Dir, name))
			}
			fmt.Fprintf(cmd.OutOrStdout(), " (private keys: %s, %s)\n",
				filepath.Join(opts.Dir, serverKeyFile), filepath.Join(opts.Dir, agentKeyFile))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "out", "", "bundle directory to create (must not exist)")
	f.StringVar(&opts.ClusterID, "cluster-id", "", "cluster name, an RFC1123 label")
	f.StringVar(&opts.ManifestPath, "image-manifest", "", "manifest.json published with the exact node image to boot")
	f.IntVar(&opts.VCPUs, "vcpus", 0, "SNP only: the VM's vCPU count, selecting its launch digest from the manifest")
	f.StringVar(&opts.ServerName, "server-name", "", "server node name (default <cluster-id>-server)")
	f.StringVar(&opts.ServerAddress, "server-address", "", "server IPv4 address every node can reach; required with agents, otherwise the server autodetects it")
	f.StringArrayVar(&opts.Agents, "agent", nil, "agent node name; repeatable")
	f.StringVar(&opts.TLSSAN, "tls-san", "", "DNS name for the front-door certificate (default c8s.local)")
	f.StringVar(&opts.WorkloadsPath, "workloads", "", "optional c8s.allowlist/v1 JSON file applied as the initial workload allowlist")
	for _, name := range []string{"out", "cluster-id", "image-manifest"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newAddAgentCmd() *cobra.Command {
	var dir, name, serverAddress string
	cmd := &cobra.Command{
		Use:   "add-agent",
		Short: "Add a signed agent document to an existing launch bundle",
		Long: `Derive an agent launch.yaml from the bundle's server document (same
cluster, image and keys; documents carry no credentials), sign it with
the bundle's agent key and write <bundle>/<name>. Nothing the server
already booted with changes.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := AddAgent(dir, name, serverAddress); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", filepath.Join(dir, name))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "bundle", "", "bundle directory created by 'launch-config new'")
	f.StringVar(&name, "name", "", "agent node name, an RFC1123 label")
	f.StringVar(&serverAddress, "server-address", "", "server IPv4 address (default: the server document's, which must then be explicit)")
	for _, flag := range []string{"bundle", "name"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

func newStageCmd() *cobra.Command {
	var cfg Config
	stage := &cobra.Command{
		Use: "stage", Short: "Verify signed launch configuration and stage the selected node role",
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
	for _, name := range []string{"platform", "config", "signature"} {
		_ = stage.MarkFlagRequired(name)
	}
	return stage
}
