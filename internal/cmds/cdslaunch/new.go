package cdslaunch

import (
	"fmt"
	"os"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// write renders both outputs before it creates anything, so a refused input
// leaves no half-built directory to launch a CDS VM from.
func write(opts options) error {
	family, err := cdsconfig.ParsePlatform(opts.platform)
	if err != nil {
		return fmt.Errorf("--platform: %w", err)
	}
	operatorKeys, err := readOperatorKeys(opts.operatorKeys)
	if err != nil {
		return err
	}
	components, err := readInput("allowlist-seed", opts.allowlistSeed)
	if err != nil {
		return err
	}
	var tenant []byte
	if opts.workloads != "" {
		if tenant, err = readInput("workloads", opts.workloads); err != nil {
			return err
		}
	}
	nodes, err := readInput("node-pins", opts.nodePins)
	if err != nil {
		return err
	}
	var podImagePolicy []byte
	if opts.podImagePolicy != "" {
		if podImagePolicy, err = readInput("pod-image-policy-file", opts.podImagePolicy); err != nil {
			return err
		}
		if len(podImagePolicy) == 0 {
			return fmt.Errorf("--pod-image-policy-file must contain a nonempty Pod image policy")
		}
	}
	config, pin, err := cdsconfig.Build(cdsconfig.Inputs{
		ClusterID:       opts.clusterID,
		OperatorKeys:    operatorKeys,
		ComponentSeed:   components,
		TenantWorkloads: tenant,
		Nodes:           nodes,
		PodImagePolicy:  podImagePolicy,
		NodeCIDRs:       opts.nodeCIDRs,
		ClusterCIDRs:    append(slices.Clone(opts.podCIDRs), opts.serviceCIDRs...),
		LeafDNSNames:    opts.leafDNSNames,
		LeafDNSPatterns: opts.leafDNSPatterns,
		ManifestPath:    opts.manifest,
		Family:          family,
		VCPUs:           opts.vcpus,
	})
	if err != nil {
		return err
	}
	// A configuration and the pin binding it are only usable together.
	return fileutil.WriteNewDir(opts.dir, 0o755, []fileutil.NewFile{
		{Name: cdsconfig.ConfigFile, Data: config, Mode: 0o644},
		{Name: cdsconfig.PinFile, Data: pin, Mode: 0o644},
	})
}

func readOperatorKeys(path string) (operatorauth.KeyBundle, error) {
	pemBytes, err := readInput("operator-keys", path)
	if err != nil {
		return operatorauth.KeyBundle{}, err
	}
	bundle, err := operatorauth.ParseKeyBundle(pemBytes)
	if err != nil {
		return operatorauth.KeyBundle{}, fmt.Errorf("--operator-keys: %w", err)
	}
	return bundle, nil
}

func readInput(flag string, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flag, err)
	}
	return data, nil
}
