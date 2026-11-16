//go:build !c8s_node

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
)

var (
	installNamespace string
	installRelease   string
	installValues    []string
	installWait      bool

	installPlatform        string
	installVolumes         bool
	installImagePullSecret string
	installOperatorKeys    string
	installForce           bool

	installUpstream     string
	installWorkloadRefs []string

	installChartDir   string
	installCDSAddress string
	installCDSPin     string
	installSeedOut    string
	installPodCIDRs   []string

	// installCDS is the pin this install holds its CDS to, resolved once from
	// the values the release renders with, so the chart, the clients this
	// install dials and the commands it prints name one document.
	installCDS *cdsPin
)

// Flag names referenced in more than one place (registration plus a Changed()
// gate or an arg-builder call). Naming them once keeps the references from
// drifting.
const (
	flagChart            = "chart"
	flagPlatform         = "platform"
	flagHardwarePlatform = "hardware-platform"
	flagWorkloadRef      = "workload-ref"
	flagUpstream         = "upstream"
	flagCDSAddress       = "cds-address"
	flagCDSPin           = "cds-pin"
	flagSeedOut          = "allowlist-seed-out"
	flagPodCIDR          = "pod-cidr"
)

// cloudPlatforms name the cloud chart's stock values files,
// values-<platform>.yaml.
var cloudPlatforms = []string{
	"aks-snp",
	"aks-tdx",
	"gke-snp",
}

// validatePlatform accepts an empty --platform: the -f files then set the
// platform keys the chart requires.
func validatePlatform(platform string) error {
	if platform == "" || slices.Contains(cloudPlatforms, platform) {
		return nil
	}
	return fmt.Errorf("--%s must be one of %s, got %q", flagPlatform, strings.Join(cloudPlatforms, ", "), platform)
}

// orderedValuesFiles are the -f files a release renders with, in helm's
// precedence order: the stock file --platform selects, then the operator's own.
// Install passes this list to everything that reads the values.
func orderedValuesFiles(chartPath, platform string, userFiles []string) []string {
	if platform == "" {
		return userFiles
	}
	stock := filepath.Join(chartPath, "values-"+platform+".yaml")
	return append([]string{stock}, userFiles...)
}

// c8sComponent is a chart image from the component table: the values path of
// its image object and that object's default repository.
type c8sComponent struct {
	valuesPath string
	repository string
}

// componentsFile is c8s-lib's files/components.yaml: the component table the
// chart derives its allowlist from and the router's nginx pin beside it. The
// file's own header states each field's contract.
type componentsFile struct {
	Components  []componentDeclaration `yaml:"components"`
	RouterNginx routerNginxDeclaration `yaml:"routerNginx"`
}

type componentDeclaration struct {
	ValuePath string `yaml:"valuePath"`
}

type routerNginxDeclaration struct {
	Image componentImagePin `yaml:"image"`
}

type componentImagePin struct {
	Repository string `yaml:"repository"`
	Digest     string `yaml:"digest"`
}

// chartComponents reads the component set from the chart at chartPath: the
// table in its c8s-lib files/components.yaml, which the chart's c8s.components
// helper reads too, and each repository from `helm show values` (which dumps
// values.yaml without rendering templates, so no render guard fires).
func chartComponents(ctx context.Context, chartPath string) ([]c8sComponent, error) {
	values, err := chartValues(ctx, chartPath)
	if err != nil {
		return nil, err
	}
	file, err := chartComponentsFile(chartPath)
	if err != nil {
		return nil, err
	}
	return componentsFromFile(file, values)
}

func chartValues(ctx context.Context, chartPath string) (map[string]any, error) {
	out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
	if err != nil {
		return nil, fmt.Errorf("helm show values %q: %w", chartPath, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return nil, fmt.Errorf("parse chart values: %w", err)
	}
	return tree, nil
}

// chartComponentsFile reads the components file of the chart's c8s-lib
// dependency.
func chartComponentsFile(chartPath string) (componentsFile, error) {
	path := filepath.Join(chartPath, helmchart.ComponentsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return componentsFile{}, fmt.Errorf("read %s (build the chart's c8s-lib dependency with `helm dependency build`): %w", path, err)
	}
	var file componentsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return componentsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return file, nil
}

// componentsFromFile reads the components file's table, each repository from
// its valuePath in the values tree.
func componentsFromFile(components componentsFile, values map[string]any) ([]c8sComponent, error) {
	if len(components.Components) == 0 {
		return nil, fmt.Errorf("chart declares no components")
	}

	comps := make([]c8sComponent, 0, len(components.Components))
	for _, declared := range components.Components {
		if declared.ValuePath == "" {
			return nil, fmt.Errorf("components entry declares no valuePath: %+v", declared)
		}
		repo, err := stringAtPath(values, declared.ValuePath+".repository")
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", declared.ValuePath, err)
		}
		comps = append(comps, c8sComponent{
			valuesPath: declared.ValuePath,
			repository: repo,
		})
	}
	return comps, nil
}

// cdsValues are the CDS settings the -f files name, merged as helm merges
// them: the last file writing a path is the one the release renders with.
func cdsValues(valuesFiles []string) (map[string]any, error) {
	values := map[string]any{}
	for _, f := range valuesFiles {
		tree, err := decodeValuesFile(f)
		if err != nil {
			return nil, err
		}
		for _, path := range []string{
			"cds.address",
			"cds.measurementsConfig",
		} {
			if v, ok := valueAtPath(tree, path); ok {
				values[path] = v
			}
		}
	}
	return values, nil
}

// boolAtPath walks a dotted path through a decoded YAML tree and returns the
// bool at it, or false if a segment is missing or the leaf is not a bool.
func boolAtPath(tree map[string]any, path string) bool {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur = m[seg]
	}
	b, _ := cur.(bool)
	return b
}

// stringsAtPath returns the string list at a dotted path; a missing key, a
// non-list leaf, or a non-string element yields what could be read.
func stringsAtPath(tree map[string]any, path string) []string {
	value, ok := valueAtPath(tree, path)
	if !ok {
		return nil
	}
	return stringList(value)
}

// stringList reads a decoded YAML list of strings, skipping what is not one.
func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if s, ok := entry.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// nestedMap walks map keys and returns the map[string]any at the path.
func nestedMap(tree map[string]any, keys ...string) (map[string]any, bool) {
	cur := tree
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// stringAtPath walks a dotted path through a decoded YAML tree and returns the
// string at it, erroring if a segment is missing or the leaf is not a string.
func stringAtPath(tree map[string]any, path string) (string, error) {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("path %q: %q is not a mapping", path, seg)
		}
		cur, ok = m[seg]
		if !ok {
			return "", fmt.Errorf("path %q: missing segment %q", path, seg)
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: not a string (%T)", path, cur)
	}
	return s, nil
}

// valueAtPath walks a dotted path through a decoded YAML tree. ok reports
// whether the key is there, so a key written with a null or empty value is
// distinguishable from one that is absent.
func valueAtPath(tree map[string]any, path string) (value any, ok bool) {
	var cur any = tree
	for seg := range strings.SplitSeq(path, ".") {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// decodeValuesFile reads and parses one -f values file.
func decodeValuesFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read values file %q: %w", path, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("parse values file %q: %w", path, err)
	}
	return tree, nil
}

// materializeStdinValues replaces each "-" entry (helm's -f - idiom) with a
// temp file holding the piped values, so every values consumer — the
// TEE-selector scan, effectiveValues, and helm itself — reads the same
// bytes. Stdin is drained once, so a repeated "-" gets an empty file, as does
// helm's own repeated -f -. The returned cleanup removes the temp files.
func materializeStdinValues(files []string, stdin io.Reader) ([]string, func(), error) {
	out := make([]string, 0, len(files))
	var temps []string
	cleanup := func() {
		for _, t := range temps {
			os.Remove(t)
		}
	}
	for _, f := range files {
		if f != "-" {
			out = append(out, f)
			continue
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("read values from stdin: %w", err)
		}
		tmp, err := fileutil.WriteTemp("c8s-install-stdin-*.yaml", data)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("write stdin values file: %w", err)
		}
		temps = append(temps, tmp)
		out = append(out, tmp)
	}
	return out, cleanup, nil
}

const (
	exemptNamespacesPath   = "nriImagePolicy.policy.exemptNamespaces"
	exemptRepositoriesPath = "nriImagePolicy.policy.exemptRepositories"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install C8s on a cloud cluster of confidential VMs via Helm",
	Long: `Extracts the bundled c8s-cloud chart and runs
'helm upgrade --install' against the current kubeconfig context. --platform
names the cluster's confidential VMs (aks-snp, aks-tdx or gke-snp) and selects
the chart's values-<platform>.yaml, which -f files override; without it the -f
files set the platform's values. Deploys:

  - the install namespace (labeled pod-security=privileged)
  - the c8s Deployment + Service (admission webhook + status-mirror controllers)
  - the ConfidentialWorkload CRD
  - the mutating admission webhook configuration
  - the attestation-api DaemonSet (per-node /attest + /verify)
  - cds.address and cds.measurementsConfig, pointing the cluster at the external
    CDS named by --cds-address and --cds-pin
  - the pod-validating webhook configuration
  - the nri-image-policy and router components

The provider's kube-system pods are not on the c8s allowlist, so every
confidential node admits, in the namespaces nriImagePolicy.policy.exemptNamespaces
names, the images whose repository nriImagePolicy.policy.exemptRepositories names
for that namespace — the provider's add-on repositories, which the chart's
values-<platform>.yaml carries. The install matches these exemptions against
the images requested in pod specs and prints the matching images.

Before changing the cluster, install checks requested containers on confidential
nodes against repository exemptions, component and bootstrap digests, and the
authenticated allowlist fetched from CDS. It refuses resolved platform images
outside that available policy; --force overrides this guard. Other uncovered
images and containers without a current digest are reported as warnings.
This checks image coverage; runtime admission also checks the full workload,
and a tag may resolve to a different digest when pulled again.

A release build pins each component image to the digest the c8s-cloud chart of
its own version carries for the same repository
(oci://ghcr.io/confidential-dot-ai/charts/c8s-cloud), and reads nothing else
from that chart. --chart renders a chart directory instead, with the image digests
or tags it and the -f files set; a build that is not a release needs it.

When the c8s images live in a registry that requires authentication, create a
kubernetes.io/dockerconfigjson Secret in the release namespace and pass
--image-pull-secret <name>: the chart wires it into every component's
imagePullSecrets, so pods authenticate from first start.
This is the cluster-side (kubelet) credential; --workload-ref images resolve
locally via crane and your local docker login.

--volumes deploys volumed, the node agent that opens a pod's encrypted volumes
into its mount namespace (docs/volumes.md).

To adopt already-running workloads, pass --workload-ref <id>=<namespace>/<kind>/<name>[:<port>].
The release namespace is excluded from workload injection, so adopted workloads
must live in a separate namespace. After the chart is ready, install patches each
workload's pod template with confidential.ai/cw=<id>; the rollout then goes
through the c8s webhook and the operator provisions the c8s-<id> headless Service.
Install also writes one
nriImagePolicy.bootstrapAllowlist.workloads entry per adopted workload, named
after its cw id and listing every image of its pod template under any command
and args, with mounts limited to the template's memory-backed emptyDirs (the
webhook refuses a workload container that mounts the cert volume), so image
admission (the host NRI plugin) allows the rollout and CDS stamps the cw id on
the workload's certificate. A template mounting anything else or a subPath, or
requesting c8s secrets or volumes, gets an entry admitting any mounts and a
warning: CDS still names the pod, so a route written to it later
trusts those mounts. For the --upstream workload install refuses instead;
write its entry with 'c8s allowlist'. Install refuses an adoption whose pod another entry of the
seed also describes, since CDS would then name it nothing.

The router routes only by the operator-signed route manifest on CDS, verified
under --operator-keys. Without one the router takes the keys from the pinned
CDS. To front an adopted workload, give its ref the :<port> it serves TLS on,
with its get-cert
certificate, and pass --upstream <id>: install builds a manifest whose every
router.san DNS name routes / to c8s-<id>.<ns>.svc.cluster.local:<port>, verified
as the allowlist entry <id>. With --operator-key (or C8S_OPERATOR_KEY) install
signs it and stores it on CDS once the release is ready, keeping the routes of a
manifest CDS already stores (verified against --operator-keys). Without one, or
when storing fails, it writes the manifest to --routes-out and prints the
'c8s routes add' commands that store the route. Its revision is the later of
the stored one plus one and the current Unix time in seconds, or
--routes-revision. The router answers 503 until a manifest is stored.

Requires the 'helm' and 'kubectl' CLIs on PATH, and 'crane' for a
--workload-ref image named by tag.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return installC8s(cmd)
	},
}

// installC8s and the steps it calls read the flags' package globals; only
// installC8s sets any of them.
func installC8s(cmd *cobra.Command) error {
	ctx := cmd.Context()
	seedOnly := installSeedOut != ""
	if err := validatePlatform(installPlatform); err != nil {
		return err
	}
	// Substitute any "-f -" before anything reads installValues, so the
	// preflights and helm all see the piped values at a real path.
	substituted, stdinCleanup, err := materializeStdinValues(installValues, cmd.InOrStdin())
	if err != nil {
		return err
	}
	defer stdinCleanup()
	installValues = substituted

	adoptions, upstream, err := resolveWorkloadAdoptions()
	if err != nil {
		return err
	}
	pin, removePin, err := resolveCDSPin(installValues)
	if err != nil {
		return err
	}
	defer removePin()
	installCDS = pin
	installRoutesOutSet, installRoutesMaxAgeSet = cmd.Flags().Changed("routes-out"), cmd.Flags().Changed("routes-max-age")
	if err := checkInstallFlags(seedOnly); err != nil {
		return err
	}
	adopted, err := readAdoptedWorkloads(ctx, adoptions)
	if err != nil {
		return err
	}

	// The cluster before the registry: an install that cannot reach the
	// cluster it is for says so without first pulling a chart.
	kubeVersion, err := clusterKubeVersion(ctx)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "c8s-install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	release, removeComputed, err := renderRelease(ctx, work, kubeVersion, adopted)
	if err != nil {
		return err
	}
	defer removeComputed()
	if seedOnly {
		return writeInstallSeed(ctx, release.seedRender(), installSeedOut)
	}

	plan, err := preflightCluster(ctx, release, upstream)
	if err != nil {
		return err
	}
	return applyRelease(ctx, release, plan, adoptions)
}

func resolveWorkloadAdoptions() (adoptions []workloadAdoption, upstream string, err error) {
	adoptions, err = collectWorkloadAdoptions(installWorkloadRefs)
	if err != nil {
		return nil, "", err
	}
	if err := validateWorkloadAdoptionFlags(installNamespace, adoptions, installWait); err != nil {
		return nil, "", err
	}
	upstream, err = upstreamAddress(installUpstream, adoptions)
	if err != nil {
		return nil, "", err
	}
	return adoptions, upstream, nil
}

func checkInstallFlags(seedOnly bool) error {
	if err := preflightUpstreamRoutes(); err != nil {
		return err
	}
	if err := preflightRoutesOut(); err != nil {
		return err
	}
	if seedOnly {
		if installCDSAddress != "" || installCDSPin != "" {
			return fmt.Errorf("--%s writes the seed the CDS is configured with, so it runs before --%s and --%s name one", flagSeedOut, flagCDSAddress, flagCDSPin)
		}
	} else if err := cdsPreflight(installCDSAddress, installCDSPin, installValues); err != nil {
		return err
	}
	if _, err := exec.LookPath("helm"); err != nil {
		return fmt.Errorf("helm CLI not found on PATH: %w", err)
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
	}
	return nil
}

func readAdoptedWorkloads(
	ctx context.Context,
	adoptions []workloadAdoption,
) ([]adoptedWorkload, error) {
	adopted := make([]adoptedWorkload, 0, len(adoptions))
	for _, adoption := range adoptions {
		template, err := adoptedWorkloadTemplate(ctx, adoption.ref)
		if err != nil {
			return nil, err
		}
		reportAdoptedImages(adoption, podTemplateImages(template).all())
		adopted = append(adopted, adoptedWorkload{workloadAdoption: adoption, template: template})
	}
	return adopted, nil
}

type releaseRender struct {
	chart       renderChart
	kubeVersion string
	valuesFiles []string
	// computed is the file the computed values are written to, the last -f
	// helm reads.
	computed string
	// adoptedEntries are the allowlist entries written for adopted workloads.
	adoptedEntries map[string]adoptedEntry
}

func (r releaseRender) seedRender() seedRender {
	return seedRender{
		chart:       r.chart.path,
		release:     installRelease,
		namespace:   installNamespace,
		kubeVersion: r.kubeVersion,
		valueFiles:  r.valuesFiles,
		computed:    r.computed,
	}
}

// renderRelease writes the computed values file, which the returned func
// removes.
func renderRelease(
	ctx context.Context,
	work string,
	kubeVersion string,
	adopted []adoptedWorkload,
) (releaseRender, func(), error) {
	chart, err := installChart(ctx, work)
	if err != nil {
		return releaseRender{}, nil, err
	}
	valuesFiles := orderedValuesFiles(chart.path, installPlatform, installValues)
	// The computed values reach helm as the last -f, so they win over the
	// operator's files on the keys they set.
	values, err := buildComputedValues(chart.imagePins)
	if err != nil {
		return releaseRender{}, nil, err
	}
	adoption, err := resolvedWorkloadImageValues(ctx, adopted, installUpstream)
	if err != nil {
		return releaseRender{}, nil, err
	}
	computed, err := writeComputedValues(helmchart.MergeValues(values, adoption.values))
	if err != nil {
		return releaseRender{}, nil, err
	}
	release := releaseRender{
		chart:          chart,
		kubeVersion:    kubeVersion,
		valuesFiles:    valuesFiles,
		computed:       computed,
		adoptedEntries: adoption.entries,
	}
	removeComputed := func() {
		os.Remove(computed)
	}
	return release, removeComputed, nil
}

type installPlan struct {
	values map[string]any
	// routes and cdsURL are set only with --upstream.
	routes upstreamRoutes
	cdsURL string
}

func (p installPlan) routesUpstream() bool {
	return p.routes.address != ""
}

// preflightCluster runs, in this order, every check that reads the cluster
// before the install changes it, and plans the --upstream routes; what they
// print follows the same order.
func preflightCluster(
	ctx context.Context,
	release releaseRender,
	upstream string,
) (installPlan, error) {
	if installImagePullSecret != "" {
		if err := preflightImagePullSecret(ctx, installNamespace, installImagePullSecret); err != nil {
			return installPlan{}, err
		}
	}
	// The values the release will actually render with (chart defaults + -f
	// + computed), read once and shared by the checks below.
	values, err := effectiveValues(ctx, release.chart.path, append(slices.Clone(release.valuesFiles), release.computed))
	if err != nil {
		return installPlan{}, err
	}
	// The nodes this release runs on: the chart places every node agent
	// and the router on the confidential ones, and the checks below read
	// those nodes alone.
	nodeSelector, err := confidentialNodeSelector(values)
	if err != nil {
		return installPlan{}, err
	}
	nodes, err := confidentialNodes(ctx, nodeSelector)
	if err != nil {
		return installPlan{}, err
	}
	// Fail fast when router's host port is already taken on every
	// confidential node (e.g. an existing ingress owns 443), which would
	// otherwise wedge `--wait`.
	if err := preflightRouterHostPort(ctx, nodes); err != nil {
		return installPlan{}, err
	}
	if err := checkAdoptedEntries(release.adoptedEntries, values); err != nil {
		return installPlan{}, err
	}
	pods, err := confidentialNodePods(ctx, nodes)
	if err != nil {
		return installPlan{}, err
	}
	servedDigests, warn, err := checkNamedCDS(ctx, release.seedRender(), installCDS, values)
	if err != nil {
		return installPlan{}, err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, "warning: "+warn)
	}
	plan := installPlan{values: values}
	if upstream != "" {
		if plan.routes, plan.cdsURL, err = planUpstreamRoutes(values, upstream); err != nil {
			return installPlan{}, err
		}
	}
	if warn, err := preflightImagePolicy(os.Stdout, values, release.chart.components, servedDigests, installNamespace, pods, installForce); err != nil {
		return installPlan{}, err
	} else if warn != "" {
		fmt.Fprintln(os.Stderr, "warning: "+warn)
	}
	if err := preflightUpstreamContainerd(ctx, nodeSelector); err != nil {
		return installPlan{}, err
	}
	if err := preflightContainerdVersion(ctx, nodeSelector); err != nil {
		return installPlan{}, err
	}
	return plan, nil
}

// planUpstreamRoutes is the route manifest --upstream needs: every router.san
// DNS name routes to the upstream workload.
func planUpstreamRoutes(values map[string]any, upstream string) (upstreamRoutes, string, error) {
	hosts, skipped := routeHosts(values, installRelease)
	for _, san := range skipped {
		fmt.Fprintf(os.Stderr, "warning: router.san entry %q cannot be a route manifest host, so --%s routes no requests for it\n", san, flagUpstream)
	}
	if len(hosts) == 0 {
		return upstreamRoutes{}, "", fmt.Errorf("--%s needs a DNS name in router.san to route requests for: a route manifest host cannot be a wildcard, an IP address or end in a numeric label", flagUpstream)
	}
	cdsURL, err := installCDSURL(values)
	if err != nil {
		return upstreamRoutes{}, "", err
	}
	return upstreamRoutes{hosts: hosts, address: upstream, workload: installUpstream}, cdsURL, nil
}

// interruptOnCancel stops helm with SIGINT when hc's context ends, as a
// Ctrl-C would, so helm can wind down its release operation itself.
func interruptOnCancel(hc *exec.Cmd) {
	hc.Cancel = func() error { return hc.Process.Signal(os.Interrupt) }
}

// applyRelease is the only step that changes the cluster.
func applyRelease(
	ctx context.Context,
	release releaseRender,
	plan installPlan,
	adoptions []workloadAdoption,
) error {
	// The install ships privileged pods (nri-image-policy and
	// attestation-api), so the namespace is labelled privileged: a
	// CIS-hardened cluster would otherwise reject them at admission.
	if err := applyNamespace(ctx, installNamespace); err != nil {
		return err
	}
	helmArgs := buildInstallHelmArgs(release.chart.path, release.computed, release.valuesFiles, installWait)
	fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
	hc := exec.CommandContext(ctx, "helm", helmArgs...)
	interruptOnCancel(hc)
	hc.Stdout, hc.Stderr = os.Stdout, os.Stderr
	if err := hc.Run(); err != nil {
		return fmt.Errorf("helm install failed: %w", err)
	}
	for _, adoption := range adoptions {
		if err := patchAdoptedWorkload(ctx, adoption.ref, adoption.cwID); err != nil {
			return err
		}
	}
	var storedRouteDigest string
	if plan.routesUpstream() {
		digest, err := deliverUpstreamRoutes(ctx, os.Stdout, plan.routes, plan.cdsURL, release.adoptedEntries)
		if err != nil {
			return err
		}
		storedRouteDigest = digest
	}
	printInstallVerifyHint(plan.values, storedRouteDigest)
	return nil
}

func printInstallVerifyHint(values map[string]any, storedRouteDigest string) {
	verifyURL, verifyPin := "https://<cds-address>", "<cds-pin.json>"
	if url, err := installCDSURL(values); err == nil {
		verifyURL = url
	}
	if installCDS != nil {
		verifyPin = installCDS.path
	}
	printVerifyHint(os.Stdout, verifyURL, verifyPin, installOperatorKeysFlag(), storedRouteDigest)
}

// printVerifyHint names the check a client runs on this cluster's front door.
// storedRouteDigest is the digest install stored a route manifest under, empty
// when this run stored none.
func printVerifyHint(
	w io.Writer,
	cdsURL string,
	cdsPin string,
	operatorKeys string,
	storedRouteDigest string,
) {
	routeDigest := cmp.Or(storedRouteDigest, "<ROUTE_DIGEST>")
	fmt.Fprintln(w, "+ router attestation sidecar enabled; clients verify the front door against the")
	fmt.Fprintln(w, "  node measurements, the mesh anchor and the route digest:")
	fmt.Fprintf(w, "    c8s verify https://<router> --kind lb --mode attest-lb --image-policy-file <node-pins.json> --mesh-ca mesh-ca.pem --route-digest %s\n", routeDigest)
	fmt.Fprintln(w, "  node-pins.json pins the node images: the nodes of the CDS configuration, or")
	fmt.Fprintln(w, "  'c8s measurements derive' of a node image build, never what the endpoint reports.")
	fmt.Fprintf(w, "  Write the anchor with: c8s cds ca --url %s --image-policy-file %s --out mesh-ca.pem\n", cdsURL, cdsPin)
	if storedRouteDigest == "" {
		fmt.Fprintf(w, "  Read the route digest with: c8s routes show --url %s --image-policy-file %s --operator-keys %s\n",
			cdsURL, cdsPin, operatorKeys)
	}
}

// applyNamespace creates the install namespace before helm, labelled to allow
// privileged pods (the install's privileged components, see RunE). helm
// --create-namespace cannot set labels, so we always pre-apply.
func applyNamespace(ctx context.Context, namespace string) error {
	manifest, err := namespaceManifest(namespace)
	if err != nil {
		return fmt.Errorf("render namespace manifest: %w", err)
	}
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # Namespace/%s (pod-security=privileged)\n", namespace)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply namespace %q: %w", namespace, err)
	}
	return nil
}

// namespaceManifest renders the release Namespace as JSON (valid kubectl apply
// input), labelled privileged at the enforce, warn, and audit modes so the
// install's privileged pods admit on a cluster whose default profile is
// stricter (e.g. CIS-hardened restricted).
func namespaceManifest(namespace string) ([]byte, error) {
	ns := corev1.Namespace{
		APIVersion: "v1", Kind: "Namespace",
		Name: namespace,
		Labels: map[string]string{
			"pod-security.kubernetes.io/enforce": "privileged",
			"pod-security.kubernetes.io/warn":    "privileged",
			"pod-security.kubernetes.io/audit":   "privileged",
		},
	}
	return json.Marshal(ns)
}

// buildInstallHelmArgs assembles the `helm upgrade --install` argv. Ordering is
// load-bearing: the operator's -f files come first and the computed values file
// LAST, so the CLI's computed values win on the keys they set (helm merges -f
// last-wins) — matching the prior "--set beats -f" precedence.
func buildInstallHelmArgs(chartPath, computedValues string, valueFiles []string, wait bool) []string {
	helmArgs := []string{
		"upgrade", "--install", installRelease, chartPath,
		"--namespace", installNamespace,
	}
	for _, vf := range valueFiles {
		helmArgs = append(helmArgs, "-f", vf)
	}
	helmArgs = append(helmArgs, "-f", computedValues)
	if wait {
		timeout := "--timeout=5m"
		helmArgs = append(helmArgs, "--wait", timeout)
	}
	return helmArgs
}

// writeComputedValues writes the computed values as a values.yaml in a
// tmpfile and returns its path (caller removes it). install passes it as a -f
// instead of shelling a pile of --set flags.
func writeComputedValues(values map[string]any) (string, error) {
	out, err := yaml.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("marshal computed values: %w", err)
	}
	// Echo the computed values so the install is still legible now that they are
	// a -f file rather than inline --set flags (stderr; helm's own output stays
	// on stdout).
	fmt.Fprintf(os.Stderr, "+ computed values:\n%s", out)
	path, err := fileutil.WriteTemp("c8s-install-values-*.yaml", out)
	if err != nil {
		return "", fmt.Errorf("write computed values: %w", err)
	}
	return path, nil
}

// allowedPlatforms is what --hardware-platform takes: the canonical family
// names, which is also what the operator and the chart consume. The alias
// spellings teetypes.ParseFamily accepts are deliberately not taken here —
// node labelling compares this value as written.
var allowedPlatforms = []string{string(teetypes.FamilySNP), string(teetypes.FamilyTDX)}

// validateHardwarePlatform enforces that the worker commands'
// --hardware-platform is set and known.
func validateHardwarePlatform(hardwarePlatform string) error {
	if hardwarePlatform == "" {
		return fmt.Errorf("--%s is required; one of %s", flagHardwarePlatform, strings.Join(allowedPlatforms, ", "))
	}
	if !slices.Contains(allowedPlatforms, hardwarePlatform) {
		return fmt.Errorf("--%s must be one of %s, got %q", flagHardwarePlatform, strings.Join(allowedPlatforms, ", "), hardwarePlatform)
	}
	return nil
}

// effectiveValues resolves the values tree the release will actually render
// with, in helm's precedence order: chart defaults < -f files in order, the
// computed values last. Callers that decide on a value the operator may have
// overridden must read this, not the defaults.
func effectiveValues(ctx context.Context, chartPath string, valuesFiles []string) (map[string]any, error) {
	tree, err := chartValues(ctx, chartPath)
	if err != nil {
		return nil, err
	}
	for _, vf := range valuesFiles {
		overlay, err := decodeValuesFile(vf)
		if err != nil {
			return nil, err
		}
		helmchart.MergeValues(tree, overlay)
	}
	return tree, nil
}

func init() {
	installCmd.Flags().StringVar(&installNamespace, "namespace", "c8s-system", "namespace to install into")
	installCmd.Flags().StringVar(&installRelease, "release", "c8s", "Helm release name")
	installCmd.Flags().StringSliceVarP(&installValues, "values", "f", nil, "values files (repeatable)")
	installCmd.Flags().BoolVar(&installWait, "wait", true, "wait for the release to become ready (helm --wait)")
	installCmd.Flags().BoolVar(&installVolumes, "volumes", false, "serve encrypted volumes (docs/volumes.md): deploy volumed, the node agent that opens a pod's volume devices, and pin its image into the NRI allowlist. Off by default — it runs privileged, with hostPID and a writable bind of the kubelet directory")
	installCmd.Flags().StringSliceVar(&installWorkloadRefs, flagWorkloadRef, nil, "existing workload to adopt as a c8s confidential workload, as <cw-id>=<namespace>/<kind>/<name>[:<port>]; repeatable. Kind is any resource exposing a pod template at spec.template (deployment, statefulset, daemonset, or an operator CRD such as <kind>.<group>). The optional :<port> is the port the workload serves TLS on with its get-cert certificate, needed on the ref --upstream selects")
	installCmd.Flags().StringVar(&installUpstream, flagUpstream, "", "confidential.ai/cw id of the adopted --workload-ref workload to route / to: writes a route manifest naming c8s-<id>.<ns>.svc.cluster.local:<port> (that ref's :<port>, serving TLS on its get-cert certificate) and the allowlist entry <id>, for every router.san DNS name")
	installCmd.Flags().StringVar(&installOperatorKey, flagOperatorKey, "", "operator EC private key PEM (env "+cdsconn.EnvOperatorKey+") that signs the --upstream route manifest; install then stores it on CDS, pinned by --cds-pin. Without it the manifest goes to --routes-out. Requires --upstream")
	installCmd.Flags().StringVar(&installRoutesOut, "routes-out", "routes.json", "file the --upstream route manifest is written to when no --operator-key signs it, or when install cannot store it on CDS")
	installCmd.Flags().Uint64Var(&installRoutesRevision, "routes-revision", 0, "revision of the --upstream route manifest, above the one CDS stores; default the later of the stored revision plus one and the current Unix time. After a CDS reset, pass one above the highest revision any router applied")
	installCmd.Flags().DurationVar(&installRoutesMaxAge, "routes-max-age", 24*time.Hour, "maxAgeSeconds of a new --upstream route manifest: how long the router admits new attested sessions by it without a successful fetch from CDS; application routing goes on regardless. A manifest CDS already stores keeps its own")
	installCmd.Flags().StringVar(&installPlatform, flagPlatform, "", "the cluster's confidential VMs: aks-snp and aks-tdx (Azure, evidence from the vTPM), or gke-snp (GKE, evidence from the SNP report). Selects the chart's values-<platform>.yaml; without it the -f files set the platform's values")
	installCmd.Flags().StringVar(&installChartDir, flagChart, "", "chart directory to render instead of the bundled chart, with the component images it and the -f files set; required for a build that is not a release")
	installCmd.Flags().StringVar(&installCDSAddress, flagCDSAddress, "", "<host>:<port> of the CDS this cluster trusts, the host a DNS name or an IPv4 address: the VM 'c8s cds config new' wrote a configuration and a pin for. Sets cds.address, which every client of this cluster dials and whose port is the only one their packet rules admit outside the cluster")
	installCmd.Flags().StringVar(&installCDSPin, flagCDSPin, "", "path to that CDS's pin document (cds-pin.json): the image and launch file its VM proves. Sets cds.measurementsConfig, which every client holds the CDS to")
	installCmd.Flags().StringArrayVar(&installPodCIDRs, flagPodCIDR, nil, "a range this cluster assigns pod addresses from, the one 'c8s cds config new --pod-cidr' names; repeatable. The CDS's node subnets are checked against these ranges and the ones the nodes publish, and every pod must answer inside them")
	installCmd.Flags().StringVar(&installSeedOut, flagSeedOut, "", "write the component allowlist entries this install needs served to <file> and stop, changing nothing in the cluster: it reads the cluster's Kubernetes version, so the seed matches the render this install applies. The input 'c8s cds config new --allowlist-seed' takes before the CDS this install then names exists")
	installCmd.Flags().StringVar(&installImagePullSecret, "image-pull-secret", "", "name of an existing registry-credential Secret (kubernetes.io/dockerconfigjson) in the release namespace; the chart appends it to every component's imagePullSecrets, so all pods can pull the c8s images from an authenticated registry (e.g. a private mirror) from first start. The Secret itself is never created or managed by the install — the install fails fast if it is missing or has the wrong type")
	installCmd.Flags().StringVar(&installOperatorKeys, "operator-keys", "", "path to a PEM bundle of operator EC public keys the router verifies route manifests under; sets cds.operatorKeys. Without it the router uses the keys the pinned CDS serves. CDS's own write keys come from 'c8s cds config new --operator-keys'")
	installCmd.Flags().BoolVar(&installForce, "force", false, "install despite a fail-closed image policy that would deny the cluster's own platform pods (they do not come back after the containerd restart)")
	rootCmd.AddCommand(installCmd)
}

// withStderr appends the stderr an exec failure captured (Cmd.Output records
// it on ExitError when Cmd.Stderr is unset), so kubectl's own reason reaches
// the operator instead of a bare "exit status 1".
func withStderr(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return err
}
