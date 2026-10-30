//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// seedTemplate renders the component entries alone.
const seedTemplate = "templates/allowlist-seed.yaml"

// placeholderCDSPin is the pin document a render that names no CDS carries.
const placeholderCDSPin = `{
  "schema_version": "2",
  "tee": "sev-snp",
  "measurements": [
    {
      "name": "placeholder",
      "measurement": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "launch_file": "this render names no CDS"
    }
  ]
}`

// documentationRangeCDSAddress is the RFC 5737 documentation address a render
// that names no CDS carries.
const documentationRangeCDSAddress = "192.0.2.1:8443"

// seedRender is one render of this release's component entries: the chart,
// the release it is applied as, and every values source the install gives
// helm, in the order helm reads them.
type seedRender struct {
	chart       string
	release     string
	namespace   string
	kubeVersion string
	valueFiles  []string
	// helm reads this last, as it does on the install itself.
	computed string
	// cds names a CDS the release itself does not, as --set arguments that
	// outrank every file above.
	cds []string
}

// installSeed is the component entries this install needs its CDS to serve.
func installSeed(ctx context.Context, render seedRender) (*pkgallowlist.Allowlist, error) {
	args := []string{
		"template", render.release, render.chart,
		"--namespace", render.namespace,
		"--kube-version", render.kubeVersion,
		"--show-only", seedTemplate,
	}
	for _, vf := range render.valueFiles {
		args = append(args, "-f", vf)
	}
	args = append(args, "-f", render.computed)
	args = append(args, render.cds...)
	out, err := exec.CommandContext(ctx, "helm", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("render the allowlist seed: %w", withStderr(err))
	}
	var seed corev1.ConfigMap
	if err := yaml.Unmarshal(out, &seed); err != nil {
		return nil, fmt.Errorf("decode the rendered allowlist seed: %w", err)
	}
	document, ok := seed.Data["allowlist-seed.json"]
	if !ok {
		return nil, fmt.Errorf("%s rendered no allowlist-seed.json: %s", seedTemplate, out)
	}
	return pkgallowlist.ParseJSON([]byte(document))
}

// writeInstallSeed writes that seed as the document `c8s cds config new`
// takes, under a CDS no rendered entry reaches: the chart requires an address
// and a pin, and no component's arguments or mounts carry either, which is
// what lets an operator render the seed before the CDS that serves it exists.
func writeInstallSeed(ctx context.Context, render seedRender, path string) error {
	pin, err := fileutil.WriteTemp("c8s-placeholder-pin-*.json", []byte(placeholderCDSPin))
	if err != nil {
		return fmt.Errorf("write the placeholder CDS pin: %w", err)
	}
	defer os.Remove(pin)
	render.cds = []string{
		"--set-string", "cds.address=" + documentationRangeCDSAddress,
		"--set-file", "cds.measurementsConfig=" + pin,
	}
	seed, err := installSeed(ctx, render)
	if err != nil {
		return err
	}
	document, err := seed.Canonical()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(document, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stdout, "+ wrote %d component entries to %s\n", len(seed.Workloads), path)
	fmt.Fprintf(os.Stdout, "  Pass it to `c8s cds config new --allowlist-seed %s`, then install with --%s and --%s.\n", path, flagCDSAddress, flagCDSPin)
	return nil
}

// clusterKubeVersion is the Kubernetes version a render must simulate: the
// one this cluster runs, since helm's own default can sit below the chart's
// floor.
func clusterKubeVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "version", "-o", "json").Output()
	if err != nil {
		return "", fmt.Errorf("kubectl version: %w", withStderr(err))
	}
	var version struct {
		ServerVersion struct {
			GitVersion string `json:"gitVersion"`
		} `json:"serverVersion"`
	}
	if err := json.Unmarshal(out, &version); err != nil {
		return "", fmt.Errorf("parse the cluster version: %w", err)
	}
	if version.ServerVersion.GitVersion == "" {
		return "", fmt.Errorf("the cluster reports no server version: %s", out)
	}
	return version.ServerVersion.GitVersion, nil
}

// checkSeedServed refuses an install naming a CDS whose configuration does not
// carry every entry this release renders: no node would admit those components.
func checkSeedServed(seed *pkgallowlist.Allowlist, config *cdsconfig.Config) error {
	for name, rendered := range seed.Workloads {
		served, ok := config.Workloads.Workloads[name]
		if !ok {
			return fmt.Errorf("the CDS this install names serves no entry %q, so no node would admit that component: re-run `c8s cds config new` with the seed `c8s install --%s` writes", name, flagSeedOut)
		}
		if !reflect.DeepEqual(rendered, served) {
			return fmt.Errorf("the CDS this install names serves a different entry %q, so its nodes would admit another shape of that component: re-run `c8s cds config new` with the seed `c8s install --%s` writes", name, flagSeedOut)
		}
	}
	return nil
}

// clusterNodes reads the live node list, which is what says where this
// cluster assigns pod addresses.
func clusterNodes(ctx context.Context) (*corev1.NodeList, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w", withStderr(err))
	}
	var nodes corev1.NodeList
	if err := json.Unmarshal(out, &nodes); err != nil {
		return nil, fmt.Errorf("parse node list: %w", err)
	}
	return &nodes, nil
}

// checkNodeSubnets refuses a CDS whose inventory bound reaches pod addresses:
// inside it, a pod answering as a node's admission inventory would have CDS
// resolve its signing key, so the bound must hold node addresses alone.
func checkNodeSubnets(ctx context.Context, config *cdsconfig.Config) error {
	nodes, err := clusterNodes(ctx)
	if err != nil {
		return err
	}
	var podRanges []string
	for _, node := range nodes.Items {
		ranges := workloadclaims.PodCIDRs(&node)
		if len(ranges) == 0 {
			return fmt.Errorf("node %s publishes no podCIDR, so nothing says whether this CDS's node subnets reach its pods", node.Name)
		}
		podRanges = append(podRanges, ranges...)
	}
	subnets := make([]string, 0, len(config.NodeCIDRs))
	for _, subnet := range config.NodeCIDRs {
		subnets = append(subnets, subnet.String())
	}
	if err := cdsconfig.CheckNodeSubnets(subnets, podRanges); err != nil {
		return fmt.Errorf("the CDS this install names dials sandbox inventories where this cluster's pods answer (%w): a pod there could answer as a node's inventory. Re-run `c8s cds config new` with node subnets outside the cluster's pod ranges", err)
	}
	return nil
}

// checkNamedCDS checks what the named CDS is configured to serve against what
// this release needs served, and where its inventory calls may land. A
// release naming no CDS has nothing to check.
func checkNamedCDS(ctx context.Context, render seedRender, pin *cdsPin) error {
	if pin == nil {
		return nil
	}
	seed, err := installSeed(ctx, render)
	if err != nil {
		return err
	}
	if err := checkSeedServed(seed, pin.config); err != nil {
		return err
	}
	return checkNodeSubnets(ctx, pin.config)
}
