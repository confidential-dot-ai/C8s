// Package cdslaunch implements `c8s ta config`: the operator-side generator
// for the two files an external Trust Authority VM is launched and verified with.
package talaunch

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
)

// options are one cluster's Trust Authority settings as the operator supplies them.
type options struct {
	dir              string
	clusterID        string
	operatorKeys     string
	allowlistSeed    string
	workloads        string
	nodePins         string
	podImagePolicy   string
	nodeCIDRs        []string
	podCIDRs         []string
	serviceCIDRs     []string
	leafDNSNames     []string
	leafDNSPatterns  []string
	manifest         string
	platform         string
	vcpus            []int
	kmsURL           string
	kmsTLSKey        string
	haEndpoints      []string
	haInputConfigMap string
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Build the configuration a Trust Authority VM boots on",
	}
	cmd.AddCommand(newNewCmd())
	return cmd
}

func newNewCmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write a cluster's Trust Authority configuration and the measurements document pinning its Trust Authority VM",
		Long: `Write the two files an external Trust Authority VM is launched and verified with:

  <out>/cds-config.yaml   the launch file the Trust Authority VM boots on
  <out>/cds-pin.json      the measurements document its clients pin it with

Each pin entry binds the configuration exactly; on SEV-SNP there is one entry
per --vcpus count the VM may boot with.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("leaf-dns-pattern") {
				opts.leafDNSPatterns = []string{cmdsutil.ServiceDNSSANPattern}
			}
			if err := write(opts); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s\n",
				filepath.Join(opts.dir, taconfig.ConfigFile), filepath.Join(opts.dir, taconfig.PinFile))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.dir, "out", "", "directory to create the two outputs in (must not exist)")
	f.StringVar(&opts.clusterID, "cluster-id", "", "cluster name, an RFC1123 label")
	f.StringVar(&opts.operatorKeys, "operator-keys", "", "PEM bundle of the operator public keys authorizing policy writes")
	f.StringVar(&opts.allowlistSeed, "allowlist-seed", "", "JSON allowlist holding this cluster's component entries")
	f.StringVar(&opts.workloads, "workloads", "", "JSON allowlist of tenant workloads added to the seed; an entry may not take a component entry's name")
	f.StringVar(&opts.nodePins, "node-pins", "", "node measurements document (required); with --ha-endpoint, measurements may be empty but tee must name the worker family")
	f.StringVar(&opts.podImagePolicy, "pod-image-policy-file", "", "optional complete TDX Pod image and launch-key policy embedded in the measured Trust Authority configuration; grants no node authority")
	f.StringArrayVar(&opts.nodeCIDRs, "node-cidr", nil, "subnet holding the node addresses Trust Authority may dial for a sandbox's admission inventory; repeatable")
	f.StringArrayVar(&opts.podCIDRs, "pod-cidr", nil, "the cluster's pod range; a node subnet reaching into it is refused; repeatable")
	f.StringArrayVar(&opts.serviceCIDRs, "service-cidr", nil, "the cluster's service range; a node subnet reaching into it is refused; repeatable")
	f.StringArrayVar(&opts.leafDNSNames, "leaf-dns-name", nil, "literal DNS SAN a leaf may carry; repeatable")
	f.StringArrayVar(&opts.leafDNSPatterns, "leaf-dns-pattern", nil,
		"regex a leaf's DNS SANs may match in full; repeatable (default the in-cluster Service DNS pattern)")
	f.StringVar(&opts.kmsURL, "kms-url", "", "optional https URL of the key management service Trust Authority brokers pod secret release to (docs/pod-secrets.md); needs --pod-image-policy-file")
	f.StringVar(&opts.kmsTLSKey, "kms-tls-key-sha256", "", "lowercase hex SHA-256 of the DER SubjectPublicKeyInfo of the KMS's TLS certificate; required with --kms-url")
	f.StringVar(&opts.manifest, "image-manifest", "", "manifest.json published with the Trust Authority guest image the VM boots")
	f.StringVar(&opts.platform, "platform", "", "TEE platform the Trust Authority VM runs on: sev-snp or tdx")
	f.IntSliceVar(&opts.vcpus, "vcpus", nil, "SEV-SNP only: a vCPU count the Trust Authority VM may boot with, one pin entry each; repeatable")
	f.StringArrayVar(&opts.haEndpoints, "ha-endpoint", nil, "<host>:<port> one replica of a stateless Trust Authority serves on (1, 3 or 5); repeatable, in slot order")
	f.StringVar(&opts.haInputConfigMap, "ha-input-configmap", "", "optional signed policy/routes input ConfigMap in the store credential's namespace; requires --ha-endpoint and is bound by the launch pin")
	cmdsutil.RequireFlags(cmd,
		"out",
		"cluster-id",
		"operator-keys",
		"allowlist-seed",
		"node-pins",
		"node-cidr",
		"pod-cidr",
		"service-cidr",
		"image-manifest",
		"platform",
	)
	return cmd
}
