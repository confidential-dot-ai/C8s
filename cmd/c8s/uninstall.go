//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hostSweepScript sweeps C8s host state off a single node (see the script
// header for the full inventory). It lives in the chart
// (files/scripts/host-sweep.sh) so the allowlist pin and the sweep DaemonSet
// built in hostSweepDaemonSet share one source.
var hostSweepScript = helmchart.HostSweepScript()

var (
	uninstallNamespace       string
	uninstallRelease         string
	uninstallWait            bool
	uninstallHostSweep       bool
	uninstallHostSweepOnly   bool
	uninstallForce           bool
	uninstallDeleteCRDs      bool
	uninstallDeleteNamespace bool
)

// confidentialWorkloadCRD is the chart's one CRD (crds/ dir, so helm never
// deletes it); --delete-crds removes it by name.
const confidentialWorkloadCRD = "confidentialworkloads.confidential.ai"

// volumePodJSONPath dumps one "namespace\tname\tphase\tvolumes" line per pod,
// where volumes is the webhook's volume-request annotation; jsonpath needs the
// dots in an annotation key escaped.
var volumePodJSONPath = `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.annotations.` +
	strings.ReplaceAll(webhook.AnnotationVolumes, ".", `\.`) + `}{"\n"}{end}`

// hostUninstallConfig is the slice of the release's computed values the host
// sweep needs. It is read from `helm get values --all` BEFORE the release is
// deleted — afterwards the -f/--set overrides from install time
// (nriImagePolicy.hostPaths) are unrecoverable.
type hostUninstallConfig struct {
	ContainerdConfigDir string
	RestartCommand      string
	SweepImage          string
	// SweepArgv/PauseArgv are the OCI argv the sweep DaemonSet's init and
	// pause containers run. Default: this CLI's embedded sweep spec; when the
	// release exists, resolveSweepArgvs replays the argv its allowlist seed
	// pins instead, so a newer CLI's sweep stays admissible on a cluster
	// installed by an older chart (the pin is rendered at install time).
	SweepArgv []string
	PauseArgv []string
	// NRI image-policy host paths: where the chart's installer DaemonSet
	// wrote the plugin.
	NriPluginDir       string
	NriPluginFilename  string
	NriConfigDir       string
	NriRuntimeDir      string
	NriCacheDir        string
	ImagePullSecretRef []string // Secret names for the sweep pod's imagePullSecrets
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the c8s Helm release and sweep host artifacts off the hosts",
	Long: `Removes the release 'c8s install' deployed and sweeps the host-side
NRI, mesh and volume-attach artifacts off every node.

The uninstall first deletes the NRI image-policy installer DaemonSet, so no
installer run re-adds the plugin the sweep removes. 'helm uninstall' then
removes every other resource the release deployed, among them the operator
and its admission webhooks, the router and its namespace, the attestation-api
DaemonSet and, when enabled, volumed. It leaves every node enforcing: taking
the NRI image-policy host plugin off a node is the host sweep's job alone.

The sweep removes all of the host state below, not only what this release's
shape put there: a previous install on the same host may have had a different
shape, and leftovers brick or degrade the next cluster. After the release is
gone the sweep runs a short-lived privileged DaemonSet on every linux node —
with the release's NRI plugin image, which the fail-closed plugin already
admits (the sweep is what removes the plugin) — and removes, idempotently:

  - the NRI image-policy host plugin: its containerd registration, the plugin
    binary, its config/cache/runtime dirs. The sweep restarts containerd on
    a node where it removed that registration or the plugin still runs
  - the netfilter state of a node-level armtls-mesh from an earlier install:
    the ARMTLS-MESH chains and their base-chain jumps in iptables and
    ip6tables, and the ARMTLS-MESH-* ipsets
  - the LIO loopback disks 'c8s volume attach' built: only a backstore whose
    unit serial is c8s-vol-<name> and the target attach derived for it, torn
    down as 'c8s volume detach' does. A disk that has a holder (an open
    dm-crypt mapping), is mounted in any mount namespace, or is swap is left
    in place and named; detach it once released. A process holding the raw
    device open with nothing else is not detected. The sweep replays the
    script the release's chart pinned, so a release from a chart without this
    step leaves these disks: run 'c8s volume detach <name>' for them (the
    uninstall says so when it applies)

Which host paths to sweep is read from the release's computed values ('helm get
values --all') before the release is deleted, so
-f overrides from install time are honored. For a release that is already
gone (e.g. a previous bare 'helm uninstall' left the hosts dirty), pass
--host-sweep-only: the helm step is skipped and the sweep uses the embedded
chart's defaults.

The sweep pod runs on the node's network. Where a node's kubelet starts no
sweep container, the uninstall names that node, the state its sweep is in, and
the removal to run on the node itself.

The uninstall refuses to proceed while a pod holds a c8s encrypted volume: volumed is
the only component that unmaps the dm-crypt/dm-verity stack behind one, so
removing it under a live volume strands the mappings on the node, where they
keep the backing disk open against the next install. Scale those workloads to
zero first — volumed tears the volumes down — or pass --force, which leaves
those mappings open and their volumes decrypted on nodes this uninstall stops
enforcing; reboot those nodes.

Left in place by default: the ConfidentialWorkload CRD (helm never deletes
crds/; --delete-crds removes it ALONG WITH EVERY ConfidentialWorkload object)
and the release namespace (--delete-namespace).

Requires the 'helm' and 'kubectl' CLIs to be on PATH.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return uninstallC8s(cmd)
	},
}

// The phases before removeC8s only read: the release's computed values and the
// allowlist seed the sweep replays are gone once the release is deleted.
func uninstallC8s(cmd *cobra.Command) error {
	ctx := cmd.Context()
	if err := checkUninstallFlags(); err != nil {
		return err
	}
	plan, err := planUninstall(ctx)
	if err != nil {
		return err
	}
	if err := preflightUninstall(ctx, plan); err != nil {
		return err
	}
	return removeC8s(ctx, plan)
}

func checkUninstallFlags() error {
	if err := validateUninstallFlags(uninstallHostSweep, uninstallHostSweepOnly); err != nil {
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

type uninstallPlan struct {
	// values are the release's computed values, nil where the release is gone.
	values map[string]any
	host   hostUninstallConfig
}

// A release that is gone, and one that never deployed volumed, hold no volume
// mapping the uninstall could strand.
func (p uninstallPlan) deployedVolumed() bool {
	return boolAtPath(p.values, "volumed.enabled")
}

func planUninstall(ctx context.Context) (uninstallPlan, error) {
	values, found, err := releaseValues(ctx, uninstallRelease, uninstallNamespace)
	if err != nil {
		return uninstallPlan{}, err
	}
	if !found && !uninstallHostSweepOnly {
		return uninstallPlan{}, fmt.Errorf("helm release %q not found in namespace %q — nothing to uninstall. If a previous uninstall already deleted the release but left host artifacts on the nodes, re-run with --host-sweep-only", uninstallRelease, uninstallNamespace)
	}
	host, err := sweepHostConfig(ctx, values, found)
	if err != nil {
		return uninstallPlan{}, err
	}
	return uninstallPlan{values: values, host: host}, nil
}

// The sweep's host paths and argv come from the release's own computed values,
// or — for host state that outlived the release that created it — the embedded
// chart's defaults.
func sweepHostConfig(ctx context.Context, values map[string]any, found bool) (hostUninstallConfig, error) {
	if !found {
		fmt.Fprintf(os.Stdout, "+ release %q not found — sweeping with chart defaults\n", uninstallRelease)
		return chartDefaultHostConfig(ctx)
	}
	cfg, err := hostConfigFromValues(values)
	if err != nil {
		return hostUninstallConfig{}, fmt.Errorf("read host config from release values: %w", err)
	}
	if uninstallHostSweep {
		cfg.SweepArgv, cfg.PauseArgv = resolveSweepArgvs(ctx, uninstallNamespace, uninstallRelease, cfg)
	}
	return cfg, nil
}

func preflightUninstall(ctx context.Context, plan uninstallPlan) error {
	if uninstallHostSweep {
		if err := refuseNodelessSweep(ctx); err != nil {
			return err
		}
	}
	if plan.deployedVolumed() {
		return refuseLiveVolumePods(ctx)
	}
	return nil
}

// volumed goes with the release and is the only component that unmaps a pod's
// volume devices, so the teardown order is load-bearing.
func refuseLiveVolumePods(ctx context.Context) error {
	pods, err := listVolumePods(ctx)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return nil
	}
	if !uninstallForce {
		return volumePodsRunningError(pods)
	}
	fmt.Fprintf(os.Stdout, "%s\n", forcedVolumePodsWarning(pods))
	return nil
}

// removeC8s is the only phase that changes the cluster.
func removeC8s(ctx context.Context, plan uninstallPlan) error {
	if !uninstallHostSweepOnly {
		if err := deleteRelease(ctx); err != nil {
			return err
		}
	}
	if uninstallHostSweep {
		if err := runHostSweep(ctx, uninstallNamespace, uninstallRelease, plan.host); err != nil {
			return err
		}
	}
	if uninstallDeleteCRDs {
		if err := kubectlRun(ctx, "delete", "crd", confidentialWorkloadCRD, "--ignore-not-found"); err != nil {
			return err
		}
	}
	if uninstallDeleteNamespace {
		return kubectlRun(ctx, "delete", "namespace", uninstallNamespace, "--ignore-not-found")
	}
	return nil
}

func deleteRelease(ctx context.Context) error {
	if err := removeNriInstaller(ctx, uninstallNamespace, uninstallRelease); err != nil {
		return err
	}
	helmArgs := buildHelmUninstallArgs(uninstallRelease, uninstallNamespace, uninstallWait)
	fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
	hc := exec.CommandContext(ctx, "helm", helmArgs...)
	interruptOnCancel(hc)
	hc.Stdout, hc.Stderr = os.Stdout, os.Stderr
	if err := hc.Run(); err != nil {
		return fmt.Errorf("helm uninstall failed: %w — the nodes are still enforcing; once the release is gone, sweep them with 'c8s uninstall --host-sweep-only --release %s --namespace %s'", err, uninstallRelease, uninstallNamespace)
	}
	return nil
}

// validateUninstallFlags rejects --host-sweep-only with --host-sweep=false:
// the former exists only to run the sweep, so together they ask for nothing.
func validateUninstallFlags(hostSweep, hostSweepOnly bool) error {
	if hostSweepOnly && !hostSweep {
		return fmt.Errorf("--host-sweep-only runs only the host sweep, which --host-sweep=false disables; drop one of the two flags")
	}
	return nil
}

// The label selecting every linux node: the nodes the sweep DaemonSet runs on
// (hostSweepDaemonSet).
const (
	linuxNodeLabel = "kubernetes.io/os"
	linuxNodeValue = "linux"
)

func linuxNodeSelector() string {
	return fmt.Sprintf("%s=%s", linuxNodeLabel, linuxNodeValue)
}

// A DaemonSet that wants no pod rolls out successfully having swept nothing.
func refuseNodelessSweep(ctx context.Context) error {
	selector := linuxNodeSelector()
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-l", selector, "-o", "name").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes -l %s: %w", selector, withStderr(err))
	}
	if strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("no node matches %s, the nodes this uninstall sweeps", selector)
	}
	return nil
}

// nriInstallerSelector selects a release's NRI installer DaemonSet and its
// pods.
func nriInstallerSelector(release string) string {
	return fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/component=%s", release, helmchart.NriInstallerComponent)
}

// removeNriInstaller deletes the release's NRI installer and waits out its
// pods, so no installer run re-adds the plugin the sweep takes off the nodes.
func removeNriInstaller(ctx context.Context, namespace, release string) error {
	selector := nriInstallerSelector(release)
	if err := kubectlRun(ctx, "delete", "daemonset", "-n", namespace, "-l", selector, "--ignore-not-found"); err != nil {
		return err
	}
	if err := waitPodsGone(ctx, namespace, selector); err != nil {
		return fmt.Errorf("waiting for the NRI installer pods to terminate: %w", err)
	}
	return nil
}

// buildHelmUninstallArgs assembles the helm uninstall invocation. --wait
// holds helm until the release resources are actually gone, with the same
// fixed timeout the install uses.
func buildHelmUninstallArgs(release, namespace string, wait bool) []string {
	helmArgs := []string{"uninstall", release, "--namespace", namespace}
	if wait {
		helmArgs = append(helmArgs, "--wait", "--timeout=5m")
	}
	return helmArgs
}

// releaseValues reads the release's computed values (chart defaults merged
// with install-time -f/--set) as a decoded tree. found=false means the
// release does not exist; any other helm failure is an error.
func releaseValues(ctx context.Context, release, namespace string) (map[string]any, bool, error) {
	out, err := exec.CommandContext(ctx, "helm", "get", "values", release,
		"--namespace", namespace, "--all", "--output", "json").Output()
	if err != nil {
		var ee *exec.ExitError
		// helm reports a missing release as "Error: release: not found".
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "release: not found") {
			return nil, false, nil
		}
		if errors.As(err, &ee) {
			return nil, false, fmt.Errorf("helm get values %s -n %s: %w: %s", release, namespace, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, false, fmt.Errorf("helm get values %s -n %s: %w", release, namespace, err)
	}
	var tree map[string]any
	if err := json.Unmarshal(out, &tree); err != nil {
		return nil, false, fmt.Errorf("parse release values: %w", err)
	}
	return tree, true, nil
}

// chartDefaultHostConfig builds the sweep config for the --host-sweep-only
// path when the release (and with it the install-time values) is already
// gone: the embedded chart's defaults.
func chartDefaultHostConfig(ctx context.Context) (hostUninstallConfig, error) {
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		return hostUninstallConfig{}, fmt.Errorf("extract embedded chart: %w", err)
	}
	defer os.RemoveAll(dir)

	out, err := exec.CommandContext(ctx, "helm", "show", "values", filepath.Join(dir, helmchart.CloudChartFSPath)).Output()
	if err != nil {
		return hostUninstallConfig{}, fmt.Errorf("helm show values: %w", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return hostUninstallConfig{}, fmt.Errorf("parse chart values: %w", err)
	}

	// With the release gone the installed plugin still enforces the
	// release-pinned nri-image-policy digest; sweeping with the CLI's own
	// version tag resolves to that same digest on a same-version install.
	if nri, ok := nestedMap(tree, "nriImagePolicy"); ok {
		if img, ok := nestedMap(nri, "image"); ok {
			img["tag"] = sweepImageTag(version.Version)
		}
	}

	cfg, err := hostConfigFromValues(tree)
	if err != nil {
		return hostUninstallConfig{}, err
	}
	return cfg, nil
}

// fallbackImageTag is the tag every C8s component publishes from main.
const fallbackImageTag = "main"

// stableReleaseTag matches a vX.Y.Z CLI version, which names its own image tag.
var stableReleaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// sweepImageTag is the image tag a CLI version names: its stable release tag,
// or fallbackImageTag.
func sweepImageTag(cliVersion string) string {
	if stableReleaseTag.MatchString(cliVersion) {
		return cliVersion
	}
	return fallbackImageTag
}

// hostConfigFromValues extracts the sweep config from a decoded values tree
// (helm get values --all, or helm show values for the chart-defaults path).
// An unpinned sweep image is an error; the host layout is the chart's, which
// is where the install wrote.
func hostConfigFromValues(tree map[string]any) (hostUninstallConfig, error) {
	sweepImage, err := sweepImageRef(tree)
	if err != nil {
		return hostUninstallConfig{}, err
	}
	cfg := hostUninstallConfig{
		ContainerdConfigDir: hostContainerdConfigDir,
		RestartCommand:      hostRestartCommand,
		SweepImage:          sweepImage,
		SweepArgv:           []string{"/bin/sh", "-c", hostSweepScript},
		PauseArgv:           []string{"/bin/sleep", "2147483647"},
	}
	cfg = nriConfigFromValues(tree, cfg)
	cfg.ImagePullSecretRef = imagePullSecretNames(tree)
	return cfg, nil
}

// nriConfigFromValues fills the NRI image-policy host paths: the two the
// stock values files set per platform, read from the release, and the rest the
// chart renders as constants.
func nriConfigFromValues(tree map[string]any, cfg hostUninstallConfig) hostUninstallConfig {
	cfg.NriPluginDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.pluginDir", hostNriPluginDir)
	cfg.NriPluginFilename = hostNriPluginFilename
	cfg.NriConfigDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.configDir", hostNriConfigDir)
	cfg.NriRuntimeDir = hostNriRuntimeDir
	cfg.NriCacheDir = hostNriCacheDir
	return cfg
}

// stringOrDefault reads a dotted path from a decoded values tree, returning
// fallback when the path is absent or not a string.
func stringOrDefault(tree map[string]any, path, fallback string) string {
	s, err := stringAtPath(tree, path)
	if err != nil {
		return fallback
	}
	return s
}

// imagePullSecretNames collects the chart-wide pull secret references
// (imagePullSecret + imagePullSecrets[].name) so the sweep pod can pull its
// image where the install needed credentials. Absent on a default release.
func imagePullSecretNames(tree map[string]any) []string {
	var names []string
	if s, err := stringAtPath(tree, "imagePullSecret"); err == nil && s != "" {
		names = append(names, s)
	}
	if list, ok := tree["imagePullSecrets"].([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := m["name"].(string); ok && name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// The host paths and restart the sweep cleans, each the constant the chart's
// own helpers render (templates/nri-image-policy-helpers.tpl). The sweep
// restarts containerd when it removed the NRI config block or the plugin still
// runs.
const (
	hostContainerdConfigDir = "/etc/containerd"
	hostNriCacheDir         = "/var/lib/nri-image-policy"
	hostNriConfigDir        = "/etc/nri/conf.d"
	hostNriPluginDir        = "/opt/nri/plugins"
	hostNriPluginFilename   = "10-nri-image-policy"
	hostNriRuntimeDir       = "/run/nri-image-policy"
	hostRestartCommand      = "systemctl restart containerd"
)

// resolveSweepArgvs replays the sweep and pause argv the release's allowlist
// seed pins for the sweep image's digest: c8s.argvPinnedEntries pins them on
// the image's entry — the script shape marked by the script's own "c8s host
// sweep" banner, the pause as the one shape not running /bin/sh -c. The pin
// is rendered by the installed chart, so replaying it — rather than running
// this CLI's embedded spec — keeps the sweep admissible when the CLI and the
// install drift versions. Any miss falls back to the embedded defaults.
func resolveSweepArgvs(ctx context.Context, namespace, release string, cfg hostUninstallConfig) (sweep, pause []string) {
	pinned, err := seedPinnedSweepArgvs(ctx, namespace, release, cfg.SweepImage)
	if err != nil {
		fmt.Fprintf(os.Stdout, "+ allowlist seed has no usable host-sweep pin (%v) — using this CLI's embedded sweep spec\n", err)
		return cfg.SweepArgv, cfg.PauseArgv
	}
	fmt.Fprintf(os.Stdout, "+ host sweep argv replayed from the release's allowlist seed\n")
	if sweep := pinned[0]; len(sweep) == 0 || !strings.Contains(sweep[len(sweep)-1], hostSweepLIOMarker) {
		fmt.Fprintf(os.Stdout, "! the release's pinned host sweep predates 'c8s volume attach' disk cleanup: run 'c8s volume detach <name>' on each node for every volume attached there\n")
	}
	return pinned[0], pinned[1]
}

// hostSweepLIOMarker is in every host-sweep.sh that detaches `c8s volume
// attach` disks. A replayed older script lacks it, and its LIO disks outlive
// the uninstall.
const hostSweepLIOMarker = "lio_sweep_script"

// seedPinnedSweepArgvs reads the release's allowlist seed ConfigMap (which
// helm uninstall is about to delete) and returns the [sweep, pause] argv the
// seed's entry for image's digest pins. The parser sorts each entry's
// containers, so the shapes are identified by content, not position: the
// script by its banner, the pause as the entry's one non-/bin/sh -c shape.
// Ambiguity is an error — replaying the wrong argv fails closed at admission.
func seedPinnedSweepArgvs(ctx context.Context, namespace, release, image string) ([][]string, error) {
	_, digest, ok := strings.Cut(image, "@")
	if !ok {
		return nil, fmt.Errorf("sweep image %q is not digest-pinned", image)
	}
	d, err := types.ParseDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("sweep image digest: %w", err)
	}
	cmName := seedConfigMapName(release)

	out, err := exec.CommandContext(ctx, "kubectl", "get", "configmap", cmName,
		"-n", namespace, "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get configmap %s: %w", cmName, err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &cm); err != nil {
		return nil, fmt.Errorf("parse seed ConfigMap: %w", err)
	}
	seed, err := allowlist.ParseServedJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		return nil, fmt.Errorf("parse allowlist seed: %w", err)
	}
	// The chart names the entry by its policy hash, so find it by digest.
	var entryName string
	for name, w := range seed.Workloads {
		if len(w.Containers) == 0 || slices.ContainsFunc(w.Containers, func(c allowlist.Container) bool { return c.Digest != d }) {
			continue
		}
		if entryName != "" {
			return nil, fmt.Errorf("seed has two entries for %s: %q and %q", d, entryName, name)
		}
		entryName = name
	}
	if entryName == "" {
		return nil, fmt.Errorf("seed has no entry for %s", d)
	}
	entry := seed.Workloads[entryName]
	var sweep, pause []string
	for _, c := range entry.Containers {
		argv, err := exactArgv(c)
		if err != nil || len(argv) == 0 {
			continue
		}
		switch {
		case helmchart.IsHostSweepScript(argv):
			if sweep != nil {
				return nil, fmt.Errorf("entry %q pins two host-sweep script shapes", entryName)
			}
			sweep = argv
		case argv[0] != "/bin/sh" || len(argv) == 1 || argv[1] != "-c":
			if pause != nil {
				return nil, fmt.Errorf("entry %q pins two non-script shapes", entryName)
			}
			pause = argv
		}
	}
	if sweep == nil || pause == nil {
		return nil, fmt.Errorf("entry %q pins no host-sweep script/pause pair", entryName)
	}
	return [][]string{sweep, pause}, nil
}

// exactArgv renders an allowlist container's pinned OCI argv: command prefix
// plus exact args. Anything not pinned exact/exact is an error.
func exactArgv(c allowlist.Container) ([]string, error) {
	if c.Command.Policy != allowlist.PolicyExact || c.Args.Policy != allowlist.PolicyExact {
		return nil, fmt.Errorf("not argv-exact")
	}
	return append(append([]string{}, c.Command.Argv...), c.Args.Argv...), nil
}

// seedConfigMapName is the allowlist seed ConfigMap of a release, as
// templates/allowlist-seed.yaml names it (c8s.fullname).
func seedConfigMapName(release string) string {
	name := release
	if len(name) > 63 {
		name = strings.TrimSuffix(name[:63], "-")
	}
	return name + "-allowlist-seed"
}

// sweepImageRef picks the image the sweep DaemonSet runs. The fail-closed
// NRI plugin is live on the host, so the sweep pod's image must already be on
// the allowlist — the sweep is what removes the plugin, so it cannot ask for
// admission afterwards. The one image guaranteed admitted there is the
// plugin's own (the installer DaemonSet ran it; debian-based: sh, coreutils,
// and util-linux's nsenter are all present). Digest wins over tag, mirroring
// the chart helper; neither set is an error, never a silently-floating
// default.
func sweepImageRef(tree map[string]any) (string, error) {
	if ref, ok := imageRefAt(tree, "nriImagePolicy.image"); ok {
		return ref, nil
	}
	return "", fmt.Errorf("nriImagePolicy.image resolves to no pinned reference (digest or tag)")
}

// imageRefAt renders values image block <path> (repository + digest|tag) as
// a pullable reference. ok=false when the block is missing, incomplete, or
// carries neither digest nor tag.
func imageRefAt(tree map[string]any, path string) (string, bool) {
	img, ok := nestedMap(tree, strings.Split(path, ".")...)
	if !ok {
		return "", false
	}
	repo, _ := img["repository"].(string)
	digest, _ := img["digest"].(string)
	tag, _ := img["tag"].(string)
	if repo == "" {
		return "", false
	}
	if digest != "" {
		return repo + "@" + digest, true
	}
	if tag != "" {
		return repo + ":" + tag, true
	}
	return "", false
}

// listVolumePods returns "namespace/name" for every pod holding a C8s volume.
// The annotation is not a server-side field selector, so the filter runs
// client-side over a one-line-per-pod jsonpath dump.
func listVolumePods(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces",
		"-o", "jsonpath="+volumePodJSONPath).Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	return filterVolumePods(strings.Split(strings.TrimSpace(string(out)), "\n")), nil
}

// filterVolumePods keeps the "namespace\tname\tphase\tvolumes" lines of pods
// that requested a volume and have not finished. A pod in a terminal phase has
// no container left holding a mapping, so counting it would refuse an
// uninstall that has nothing to lose.
func filterVolumePods(lines []string) []string {
	var pods []string
	for _, l := range lines {
		fields := strings.Split(l, "\t")
		if len(fields) != 4 || fields[3] == "" {
			continue
		}
		if fields[2] == string(corev1.PodSucceeded) || fields[2] == string(corev1.PodFailed) {
			continue
		}
		pods = append(pods, fields[0]+"/"+fields[1])
	}
	return pods
}

// volumePodsRunningError is the volume guard's refusal: it names the pods and
// the ordering that avoids the leak.
func volumePodsRunningError(pods []string) error {
	return fmt.Errorf("pods are still holding c8s encrypted volumes, and volumed is the only thing that unmaps them:\n  %s\nscale those workloads to zero first (volumed then tears the volumes down), or pass --force to uninstall with those mappings still open",
		strings.Join(pods, "\n  "))
}

// forcedVolumePodsWarning is what --force buys: the uninstall proceeds, and
// the mappings these pods hold stay open on nodes it stops enforcing.
func forcedVolumePodsWarning(pods []string) string {
	return fmt.Sprintf("! --force: these pods still hold c8s encrypted volumes:\n  %s\ntheir dm-crypt/dm-verity mappings stay open, holding the volumes decrypted and the backing disks open, on nodes this uninstall stops enforcing. Delete these pods and re-run the uninstall to leave the nodes clean; otherwise reboot those nodes",
		strings.Join(pods, "\n  "))
}

// waitPodsGone polls until no pod in the namespace matches the selector.
// Terminating pods still list, so an empty result means every container —
// including any preStop hook — is finished.
func waitPodsGone(ctx context.Context, namespace, selector string) error {
	const timeout = 5 * time.Minute
	fmt.Fprintf(os.Stdout, "+ waiting for pods -l %s to terminate\n", selector)
	deadline := time.Now().Add(timeout)
	for {
		out, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
			"-n", namespace, "-l", selector, "-o", "name").Output()
		if err != nil {
			return fmt.Errorf("kubectl get pods -n %s -l %s: %w", namespace, selector, err)
		}
		if strings.TrimSpace(string(out)) == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pods -l %s still present after %s", selector, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// kubectlRun executes kubectl streaming output to the user, prefixed with the
// echoed command line like the install's helm/kubectl calls.
func kubectlRun(ctx context.Context, args ...string) error {
	fmt.Fprintf(os.Stdout, "+ kubectl %s\n", strings.Join(args, " "))
	kc := exec.CommandContext(ctx, "kubectl", args...)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func init() {
	uninstallCmd.Flags().StringVar(&uninstallNamespace, "namespace", "c8s-system", "namespace the release was installed into")
	uninstallCmd.Flags().StringVar(&uninstallRelease, "release", "c8s", "Helm release name")
	uninstallCmd.Flags().BoolVar(&uninstallWait, "wait", true, "wait for the release deletion to complete (helm --wait); the host sweep additionally waits for the host pods to be gone either way")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweep, "host-sweep", true, "after the release is deleted, sweep c8s host artifacts (NRI image-policy plugin, armtls-mesh netfilter state, idle 'c8s volume attach' LIO disks on releases whose chart carries that step) off every node via a short-lived privileged DaemonSet. =false leaves every node enforcing with no CDS to ask, refusing the pods its cached allowlist does not admit, until 'c8s uninstall --host-sweep-only' runs")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweepOnly, "host-sweep-only", false, "skip the helm uninstall and only run the host sweep — for a cluster whose release is already gone (e.g. a previous bare 'helm uninstall') but whose nodes still carry c8s artifacts. Uses the chart defaults when the release values are unavailable")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "uninstall while pods hold c8s encrypted volumes (their mappings stay open, holding the volumes decrypted, on nodes this uninstall stops enforcing; reboot those nodes)")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteCRDs, "delete-crds", false, "also delete the ConfidentialWorkload CRD — this deletes EVERY ConfidentialWorkload object in the cluster with it")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteNamespace, "delete-namespace", false, "also delete the release namespace (and everything left in it, e.g. an operator-created image pull Secret)")
	rootCmd.AddCommand(uninstallCmd)
}
