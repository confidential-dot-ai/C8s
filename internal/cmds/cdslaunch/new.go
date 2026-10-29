package cdslaunch

import (
	"fmt"
	"os"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// write renders both outputs before it creates anything, so a refused input
// leaves no half-built directory to launch a CDS VM from.
func write(opts options) error {
	family, err := platformFamily(opts.platform)
	if err != nil {
		return fmt.Errorf("--platform: %w", err)
	}
	clusterRanges := append(slices.Clone(opts.podCIDRs), opts.serviceCIDRs...)
	if err := cdsconfig.CheckNodeSubnets(opts.nodeCIDRs, clusterRanges); err != nil {
		return err
	}
	document, err := documentFrom(opts)
	if err != nil {
		return err
	}
	config, err := cdsconfig.Format(document)
	if err != nil {
		return err
	}
	pin, err := cdsconfig.Pin(opts.manifest, family, opts.vcpus, config)
	if err != nil {
		return err
	}
	// A configuration and the pin binding it are only usable together.
	return fileutil.WriteNewDir(opts.dir, 0o755, []fileutil.NewFile{
		{Name: configFile, Data: config, Mode: 0o644},
		{Name: pinFile, Data: pin, Mode: 0o644},
	})
}

// platformFamily accepts a bare TEE family only: a cloud paravisor's launch
// binding carries no file for a pin to bind.
func platformFamily(platform string) (teetypes.Family, error) {
	switch platform {
	case string(teetypes.FamilySNP):
		return teetypes.FamilySNP, nil
	case string(teetypes.FamilyTDX):
		return teetypes.FamilyTDX, nil
	default:
		return "", fmt.Errorf("%q, want %s or %s", platform, teetypes.FamilySNP, teetypes.FamilyTDX)
	}
}

func documentFrom(opts options) (cdsconfig.Document, error) {
	operatorKeys, err := readOperatorKeys(opts.operatorKeys)
	if err != nil {
		return cdsconfig.Document{}, err
	}
	workloads, err := mergedWorkloads(opts)
	if err != nil {
		return cdsconfig.Document{}, err
	}
	nodes, err := readInput("node-pins", opts.nodePins)
	if err != nil {
		return cdsconfig.Document{}, err
	}
	return cdsconfig.Document{
		ClusterID:       opts.clusterID,
		OperatorKeys:    operatorKeys,
		Workloads:       workloads,
		Nodes:           nodes,
		NodeCIDRs:       opts.nodeCIDRs,
		LeafDNSNames:    opts.leafDNSNames,
		LeafDNSPatterns: opts.leafDNSPatterns,
	}, nil
}

func mergedWorkloads(opts options) (*allowlist.Allowlist, error) {
	components, err := readInput("allowlist-seed", opts.allowlistSeed)
	if err != nil {
		return nil, err
	}
	var tenant []byte
	if opts.workloads != "" {
		if tenant, err = readInput("workloads", opts.workloads); err != nil {
			return nil, err
		}
	}
	return cdsconfig.MergeWorkloads(components, tenant)
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
