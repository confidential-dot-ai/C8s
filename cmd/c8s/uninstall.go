//go:build !c8s_node

package main

import (
	"bytes"
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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

'helm uninstall' already unwinds most of the install: the release resources
(operator, CDS, attestation-api, armtls-mesh, router, webhook
configuration), the NRI image-policy host plugin (pre-delete hook), and
the mesh traffic interception (preStop hook).

The host sweep then nukes what that path cannot guarantee. The preStop hook
is bounded by the pod's termination grace period (and the runtime restart it
triggers can kill the pod mid-cleanup), the pre-delete hooks only fire on a
release healthy enough to run them, and none of them knows about the
c8s-side artifacts. The sweep runs on every uninstall because the host state below is not confined to the release's own
shape: a previous install on the same host may have had a different shape,
and leftovers brick or degrade the next cluster. After the
release is gone the sweep runs a short-lived privileged DaemonSet on every
linux node — with the release's NRI plugin image, which the fail-closed
plugin already admits (the sweep is what removes the plugin) — and removes,
idempotently:

  - the NRI image-policy host plugin: its containerd registration, the plugin
    binary, its config/cache/runtime dirs
  - the armtls-mesh netfilter state: the ARMTLS-MESH chains and their
    base-chain jumps in iptables and ip6tables, and the ARMTLS-MESH-* ipsets
    (the mesh's own preStop deliberately keeps the fail-closed guard, so this
    survives every healthy uninstall too)
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

The uninstall refuses to proceed while a pod holds a c8s encrypted volume: volumed is
the only component that unmaps the dm-crypt/dm-verity stack behind one, so
removing it under a live volume strands the mappings on the node, where they
keep the backing disk open against the next install. Scale those workloads to
zero first — volumed tears the volumes down — or pass --force. Whatever is
still mapped when the release goes is reaped by the chart's volumed pre-delete
hook, which runs on every node before the daemon is removed. That hook can only
close a mapping nothing is using: a live consumer keeps the device open through
its own mount namespace, which the hook's host-side unmount does not reach, so
under --force the hook fails on those and names them. Whatever it leaves is
swept by volumed the next time it starts.

Left in place by default: the ConfidentialWorkload CRD (helm never deletes
crds/; --delete-crds removes it ALONG WITH EVERY ConfidentialWorkload object)
and the release namespace (--delete-namespace).

Requires the 'helm' and 'kubectl' CLIs to be on PATH.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateUninstallFlags(uninstallHostSweep, uninstallHostSweepOnly); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}

		ctx := cmd.Context()
		values, found, err := releaseValues(ctx, uninstallRelease, uninstallNamespace)
		if err != nil {
			return err
		}
		if !found && !uninstallHostSweepOnly {
			return fmt.Errorf("helm release %q not found in namespace %q — nothing to uninstall. If a previous uninstall already deleted the release but left host artifacts on the nodes, re-run with --host-sweep-only", uninstallRelease, uninstallNamespace)
		}

		var cfg hostUninstallConfig
		if found {
			cfg, err = hostConfigFromValues(values)
			if err != nil {
				return fmt.Errorf("read host config from release values: %w", err)
			}
			if uninstallHostSweep {
				cfg.SweepArgv, cfg.PauseArgv = resolveSweepArgvs(ctx, uninstallNamespace, uninstallRelease, cfg)
			}
		} else {
			fmt.Fprintf(os.Stdout, "+ release %q not found — sweeping with chart defaults\n", uninstallRelease)
			cfg, err = chartDefaultHostConfig(ctx)
			if err != nil {
				return err
			}
		}
		// Sweep host state even if it outlived the release that created it.
		// Chart pre-delete hooks are the healthy-release first line;
		// --host-sweep=false opts out of this additional cleanup.
		sweep := uninstallHostSweep

		// volumed goes with the release and is the only component that unmaps
		// a pod's volume devices, so the teardown order is load-bearing.
		if boolAtPath(values, "volumed.enabled") {
			pods, err := listVolumePods(ctx)
			if err != nil {
				return err
			}
			if len(pods) > 0 {
				if !uninstallForce {
					return volumePodsRunningError(pods)
				}
				fmt.Fprintf(os.Stdout, "%s\n", forcedVolumePodsWarning(pods))
			}
		}

		if !uninstallHostSweepOnly {
			helmArgs := buildHelmUninstallArgs(uninstallRelease, uninstallNamespace, uninstallWait)
			fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
			hc := exec.CommandContext(ctx, "helm", helmArgs...)
			hc.Stdout = os.Stdout
			hc.Stderr = os.Stderr
			if err := hc.Run(); err != nil {
				return fmt.Errorf("helm uninstall failed: %w — a wedged pre-delete hook blocks the sweep too; recover with 'helm uninstall --no-hooks %s --namespace %s' followed by 'c8s uninstall --host-sweep-only'", err, uninstallRelease, uninstallNamespace)
			}
		}

		if sweep {
			if err := runHostSweep(ctx, uninstallNamespace, uninstallRelease, cfg); err != nil {
				return err
			}
		}

		if uninstallDeleteCRDs {
			if err := kubectlRun(ctx, "delete", "crd", confidentialWorkloadCRD, "--ignore-not-found"); err != nil {
				return err
			}
		}
		if uninstallDeleteNamespace {
			if err := kubectlRun(ctx, "delete", "namespace", uninstallNamespace, "--ignore-not-found"); err != nil {
				return err
			}
		}
		return nil
	},
}

// validateUninstallFlags rejects --host-sweep-only with --host-sweep=false:
// the former exists only to run the sweep, so together they ask for nothing.
func validateUninstallFlags(hostSweep, hostSweepOnly bool) error {
	if hostSweepOnly && !hostSweep {
		return fmt.Errorf("--host-sweep-only runs only the host sweep, which --host-sweep=false disables; drop one of the two flags")
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

	out, err := exec.CommandContext(ctx, "helm", "show", "values", filepath.Join(dir, helmchart.ChartRoot)).Output()
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
// own helpers render (templates/nri-image-policy-helpers.tpl). The sweep only
// restarts when it removed a still-registered NRI config block.
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
		case strings.Contains(argv[len(argv)-1], "c8s host sweep"):
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

// forcedVolumePodsWarning is what --force buys: the uninstall proceeds, and the
// mappings these pods hold stay open on their nodes, because the pre-delete
// hook cannot close a device a live mount namespace still references.
func forcedVolumePodsWarning(pods []string) string {
	return fmt.Sprintf("! --force: these pods still hold c8s encrypted volumes:\n  %s\nthe volumed pre-delete hook will fail to close their dm-crypt/dm-verity mappings, which then hold the backing disks open. Delete these pods and re-run the uninstall to leave the nodes clean; otherwise volumed sweeps the residue the next time it starts, so a reinstall clears it",
		strings.Join(pods, "\n  "))
}

// runHostSweep removes the host artifacts from every Linux node after the
// release is gone: a short-lived privileged DaemonSet runs host-sweep.sh as an
// init container on each node. The CLI waits for it to complete everywhere
// (rollout status blocks until every pod has passed init), then deletes it.
func runHostSweep(ctx context.Context, namespace, release string, cfg hostUninstallConfig) error {
	// The mesh re-asserts its base-chain iptables jumps on a
	// watchdog, so sweeping while a mesh pod still runs leaks the rules the
	// sweep just deleted (helm --wait=false leaves pods terminating).
	meshSelector := fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/name=armtls-mesh", release)
	if err := waitPodsGone(ctx, namespace, meshSelector); err != nil {
		return fmt.Errorf("waiting for armtls-mesh pods to terminate: %w", err)
	}

	// The sweep pods are privileged; re-assert the namespace's privileged
	// pod-security labels (idempotent — the install already set them, but on
	// the --host-sweep-only path the namespace may have been deleted).
	if err := applyNamespace(ctx, namespace); err != nil {
		return err
	}

	manifest, err := json.Marshal(hostSweepDaemonSet(release, namespace, cfg))
	if err != nil {
		return fmt.Errorf("render sweep manifest: %w", err)
	}
	name := hostSweepName(release)
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # DaemonSet/%s (host sweep)\n", name)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply sweep DaemonSet: %w", err)
	}

	if err := kubectlRun(ctx, "rollout", "status", "daemonset/"+name,
		"-n", namespace, "--timeout=5m"); err != nil {
		// Leave the DaemonSet in place: its sweep container logs are the
		// only record of which node failed and why.
		return fmt.Errorf("host sweep did not complete: %w — inspect with 'kubectl -n %s logs ds/%s -c sweep', then remove it with 'kubectl -n %s delete ds %s'", err, namespace, name, namespace, name)
	}

	return kubectlRun(ctx, "delete", "daemonset", name, "-n", namespace, "--ignore-not-found")
}

func hostSweepName(release string) string {
	return release + "-host-sweep"
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

// hostSweepDaemonSet renders the sweep DaemonSet: every linux node (the
// NRI installer and mesh DaemonSets land on all of them, and a node can carry a
// previous install's leftovers), tolerating all taints, with host-sweep.sh as
// an init container and a pause container whose readiness lets `kubectl
// rollout status` double as "every node finished sweeping".
func hostSweepDaemonSet(release, namespace string, cfg hostUninstallConfig) *appsv1.DaemonSet {
	labels := map[string]string{
		"app.kubernetes.io/name":      "c8s-operator",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/component": "host-sweep",
	}
	nodeSelector := map[string]string{"kubernetes.io/os": "linux"}
	privileged := true
	pullSecrets := make([]corev1.LocalObjectReference, 0, len(cfg.ImagePullSecretRef))
	for _, n := range cfg.ImagePullSecretRef {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: n})
	}
	return &appsv1.DaemonSet{
		APIVersion: "apps/v1", Kind: "DaemonSet",
		Name:      hostSweepName(release),
		Namespace: namespace,
		Labels:    labels,
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// hostPID: the sweep nsenters into PID 1 for host binaries
					// (systemctl, iptables, losetup) and the runtime restart.
					HostPID:      true,
					NodeSelector: nodeSelector,
					// The install's pull secret, so the sweep image pulls on
					// private-mirror clusters too (chart-wide values).
					ImagePullSecrets: pullSecrets,
					// Sweep control-plane and otherwise-tainted nodes too.
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: []corev1.Container{{
						Name:            "sweep",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         cfg.SweepArgv,
						Env: []corev1.EnvVar{
							{Name: "HOST_CONTAINERD_DIR", Value: cfg.ContainerdConfigDir},
							{Name: "RESTART_COMMAND", Value: cfg.RestartCommand},
							{Name: "NRI_PLUGIN_DIR", Value: cfg.NriPluginDir},
							{Name: "NRI_PLUGIN_FILENAME", Value: cfg.NriPluginFilename},
							{Name: "NRI_CONFIG_DIR", Value: cfg.NriConfigDir},
							{Name: "NRI_RUNTIME_DIR", Value: cfg.NriRuntimeDir},
							{Name: "NRI_CACHE_DIR", Value: cfg.NriCacheDir},
						},
						// Removing a runtime from a host requires privileges
						// and the host root mounted.
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						VolumeMounts:    []corev1.VolumeMount{{Name: "host", MountPath: "/host"}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
					Containers: []corev1.Container{{
						Name:            "pause",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						// The pod lives only until the CLI's rollout-status
						// wait returns anyway.
						Command: cfg.PauseArgv,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("16Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name:     "host",
						HostPath: &corev1.HostPathVolumeSource{Path: "/"},
					}},
				},
			},
		},
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
	uninstallCmd.Flags().BoolVar(&uninstallHostSweep, "host-sweep", true, "after the release is deleted, sweep c8s host artifacts (NRI image-policy plugin, armtls-mesh netfilter state, idle 'c8s volume attach' LIO disks on releases whose chart carries that step) off every node via a short-lived privileged DaemonSet")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweepOnly, "host-sweep-only", false, "skip the helm uninstall and only run the host sweep — for a cluster whose release is already gone (e.g. a previous bare 'helm uninstall') but whose nodes still carry c8s artifacts. Uses the chart defaults when the release values are unavailable")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "uninstall while pods hold c8s encrypted volumes (the pre-delete hook cannot close a mapping a live pod holds, and fails naming it)")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteCRDs, "delete-crds", false, "also delete the ConfidentialWorkload CRD — this deletes EVERY ConfidentialWorkload object in the cluster with it")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteNamespace, "delete-namespace", false, "also delete the release namespace (and everything left in it, e.g. an operator-created image pull Secret)")
	rootCmd.AddCommand(uninstallCmd)
}
