// Package cdslaunch implements `c8s cds config`: the operator-side generator
// for the two files an external CDS VM is launched and verified with.
package cdslaunch

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// options are one cluster's CDS settings as the operator supplies them.
type options struct {
	dir             string
	clusterID       string
	operatorKeys    string
	allowlistSeed   string
	workloads       string
	nodePins        string
	nodeCIDRs       []string
	podCIDRs        []string
	serviceCIDRs    []string
	leafDNSNames    []string
	leafDNSPatterns []string
	manifest        string
	platform        string
	vcpus           []int
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Build the configuration a CDS VM boots on",
	}
	cmd.AddCommand(newNewCmd())
	return cmd
}

func newNewCmd() *cobra.Command {
	var opts options
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write a cluster's CDS configuration and the measurements document pinning its CDS VM",
		Long: `Write the two files an external CDS VM is launched and verified with:

  <out>/cds-config.yaml   the launch file the CDS VM boots on
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
				filepath.Join(opts.dir, cdsconfig.ConfigFile), filepath.Join(opts.dir, cdsconfig.PinFile))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.dir, "out", "", "directory to create the two outputs in (must not exist)")
	f.StringVar(&opts.clusterID, "cluster-id", "", "cluster name, an RFC1123 label")
	f.StringVar(&opts.operatorKeys, "operator-keys", "", "PEM bundle of the operator public keys authorizing policy writes")
	f.StringVar(&opts.allowlistSeed, "allowlist-seed", "", "JSON allowlist holding this cluster's component entries")
	f.StringVar(&opts.workloads, "workloads", "", "JSON allowlist of tenant workloads added to the seed; an entry may not take a component entry's name")
	f.StringVar(&opts.nodePins, "node-pins", "", "measurements config pinning the node launch identities CDS admits and serves")
	f.StringArrayVar(&opts.nodeCIDRs, "node-cidr", nil, "subnet holding the node addresses CDS may dial for a sandbox's admission inventory; repeatable")
	f.StringArrayVar(&opts.podCIDRs, "pod-cidr", nil, "the cluster's pod range; a node subnet reaching into it is refused; repeatable")
	f.StringArrayVar(&opts.serviceCIDRs, "service-cidr", nil, "the cluster's service range; a node subnet reaching into it is refused; repeatable")
	f.StringArrayVar(&opts.leafDNSNames, "leaf-dns-name", nil, "literal DNS SAN a leaf may carry; repeatable")
	f.StringArrayVar(&opts.leafDNSPatterns, "leaf-dns-pattern", nil,
		"regex a leaf's DNS SANs may match in full; repeatable (default the in-cluster Service DNS pattern)")
	f.StringVar(&opts.manifest, "image-manifest", "", "manifest.json published with the CDS guest image the VM boots")
	f.StringVar(&opts.platform, "platform", "", "TEE platform the CDS VM runs on: sev-snp or tdx")
	f.IntSliceVar(&opts.vcpus, "vcpus", nil, "SEV-SNP only: a vCPU count the CDS VM may boot with, one pin entry each; repeatable")
	for _, name := range []string{
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
	} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}
