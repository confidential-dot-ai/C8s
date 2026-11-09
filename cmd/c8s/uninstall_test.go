//go:build !c8s_node

package main

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildHelmUninstallArgs(t *testing.T) {
	got := buildHelmUninstallArgs("c8s", "c8s-system", true)
	assertArgsEqual(t, got, []string{
		"uninstall", "c8s", "--namespace", "c8s-system", "--wait", "--timeout=5m",
	})

	got = buildHelmUninstallArgs("c8s", "c8s-system", false)
	assertArgsEqual(t, got, []string{"uninstall", "c8s", "--namespace", "c8s-system"})
}

// --host-sweep-only exists only to run the sweep, so combining it with
// --host-sweep=false asks for nothing and must error rather than silently
// no-op.
func TestValidateUninstallFlagsRejectsSweepOnlyWithoutSweep(t *testing.T) {
	if err := validateUninstallFlags(false, true); err == nil {
		t.Fatal("--host-sweep-only with --host-sweep=false: want error, got nil")
	}
	for _, tc := range []struct{ hostSweep, hostSweepOnly bool }{
		{true, true}, {true, false}, {false, false},
	} {
		if err := validateUninstallFlags(tc.hostSweep, tc.hostSweepOnly); err != nil {
			t.Errorf("hostSweep=%t hostSweepOnly=%t: unexpected error: %v", tc.hostSweep, tc.hostSweepOnly, err)
		}
	}
}

// chartValuesTree decodes a YAML values document the way the uninstall reads
// helm output into a values tree.
func chartValuesTree(t *testing.T, doc string) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(doc), &tree); err != nil {
		t.Fatalf("unmarshal test values: %v", err)
	}
	return tree
}

// The sweep uses the release's NRI host-path overrides.
func TestHostConfigFromValuesUsesNRIPaths(t *testing.T) {
	tree := chartValuesTree(t, `
nriImagePolicy:
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
    tag: "1.37"
  hostPaths:
    pluginDir: /custom/nri/plugins
`)
	cfg, err := hostConfigFromValues(tree)
	if err != nil {
		t.Fatalf("hostConfigFromValues: %v", err)
	}
	if cfg.ContainerdConfigDir != "/etc/containerd" {
		t.Errorf("ContainerdConfigDir = %q, want the upstream containerd layout", cfg.ContainerdConfigDir)
	}
	if cfg.NriPluginDir != "/custom/nri/plugins" {
		t.Errorf("NriPluginDir = %q, want the values override", cfg.NriPluginDir)
	}
}

func TestImagePullSecretNames(t *testing.T) {
	tree := chartValuesTree(t, `
imagePullSecret: regcred
imagePullSecrets:
  - name: regcred
  - name: mirrorcred
`)
	got := imagePullSecretNames(tree)
	want := []string{"regcred", "mirrorcred"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imagePullSecretNames = %v, want %v (uniq, secret first)", got, want)
	}
	if got := imagePullSecretNames(map[string]any{}); len(got) != 0 {
		t.Errorf("imagePullSecretNames(empty) = %v, want none", got)
	}
}

func TestSweepImageRefRequiresPin(t *testing.T) {
	// Neither digest nor tag — never fall back to a floating default for a
	// privileged image with the host root mounted.
	tree := chartValuesTree(t, `
nriImagePolicy:
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
    tag: ""
    digest: ""
`)
	if _, err := sweepImageRef(tree); err == nil {
		t.Fatal("unpinned nriImagePolicy image: want error, got nil")
	}
}

// On a host running the fail-closed NRI plugin the sweep pod's image must
// already be admitted; the plugin's own image is the one image guaranteed
// on the allowlist (the installer ran it).
func TestSweepImageRefIsTheNriImage(t *testing.T) {
	tree := chartValuesTree(t, `
nriImagePolicy:
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
    digest: "sha256:aaa"
`)
	ref, err := sweepImageRef(tree)
	if err != nil {
		t.Fatalf("sweepImageRef: %v", err)
	}
	if ref != "ghcr.io/confidential-dot-ai/nri-image-policy@sha256:aaa" {
		t.Errorf("sweepImageRef = %q, want the NRI plugin image", ref)
	}
}

// The volume guard keys on the webhook's volume-request annotation, and only
// on pods that still have a container to hold a mapping: a Succeeded or Failed
// pod has none, so counting it would refuse an uninstall with nothing to lose.
func TestFilterVolumePodsKeepsOnlyLivePodsHoldingVolumes(t *testing.T) {
	lines := []string{
		"default\tinference-0\tRunning\tweights=/tenant-a/volumes/weights",
		"default\tweb-0\tRunning\t", // no volume annotation
		"team-a\tloader-1\tPending\tmodel=/tenant-b/volumes/model",
		"team-b\timport-0\tSucceeded\tmodel=/tenant-b/volumes/model",
		"team-c\timport-1\tFailed\tmodel=/tenant-b/volumes/model",
		"", // trailing blank line from kubectl
		"malformed-line-no-tabs",
	}
	want := []string{"default/inference-0", "team-a/loader-1"}
	if got := filterVolumePods(lines); !reflect.DeepEqual(got, want) {
		t.Errorf("filterVolumePods = %v, want %v", got, want)
	}
}

// --force does not make the leak clean, and the text has to say so: the
// operator's only other chance to learn it is a hook log that goes with the
// release.
func TestForcedVolumePodsWarning(t *testing.T) {
	got := forcedVolumePodsWarning([]string{"default/inference-0", "tenant-a/rag-1"})
	for _, want := range []string{
		"default/inference-0",
		"tenant-a/rag-1",
		"re-run the uninstall",
		"volumed sweeps",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not carry %q:\n%s", want, got)
		}
	}
}

// TestHostSweepScriptMeshNetfilterNames pins the netfilter names the sweep
// script removes to the mesh's fixed contract (internal/cmds/armtlsmesh:
// jumpRules, managedChains, managedIPSetNames + the -TMP swap variants). The
// two cleanup paths must not drift: a name added or renamed on the mesh side
// must be added here too.
func TestHostSweepScriptMeshNetfilterNames(t *testing.T) {
	names := []string{
		// Base-chain jumps (as "parent -j chain" in -D form).
		"-D OUTPUT -j ARMTLS-MESH",
		"-D PREROUTING -j ARMTLS-MESH-PREROUTING",
		"-D FORWARD -j ARMTLS-MESH-CW",
		"-D FORWARD -j ARMTLS-MESH-CW-EGRESS",
		// Chains (as "table:chain" sweep specs).
		"nat:ARMTLS-MESH",
		"nat:ARMTLS-MESH-PREROUTING",
		"filter:ARMTLS-MESH-CW",
		"filter:ARMTLS-MESH-CW-EGRESS",
		// ipsets.
		"ARMTLS-MESH-PODS",
		"ARMTLS-MESH-PODS6",
		"ARMTLS-MESH-LOCAL-PODS",
		"ARMTLS-MESH-LOCAL-PODS6",
		"ARMTLS-MESH-CW-PODS",
		"ARMTLS-MESH-CW-PODS6",
	}
	for _, name := range names {
		// Delimit the match so a suffixed sibling (ARMTLS-MESH-PODS6) cannot
		// satisfy a missing shorter name (ARMTLS-MESH-PODS).
		if !strings.Contains(hostSweepScript, name+" ") && !strings.Contains(hostSweepScript, name+"\n") {
			t.Errorf("host-sweep.sh does not sweep %q (mesh netfilter contract)", name)
		}
	}
	// The -TMP swap variants are destroyed alongside each ipset.
	if !strings.Contains(hostSweepScript, `"$s-TMP"`) {
		t.Error("host-sweep.sh does not destroy the -TMP ipset swap variants")
	}
}

func TestHostConfigFromEmbeddedChartValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	cfg, err := chartDefaultHostConfig(context.Background())
	if err != nil {
		t.Fatalf("chartDefaultHostConfig: %v", err)
	}
	if cfg.ContainerdConfigDir != "/etc/containerd" {
		t.Errorf("ContainerdConfigDir = %q, want the chart default", cfg.ContainerdConfigDir)
	}
	if want := "ghcr.io/confidential-dot-ai/nri-image-policy:main"; cfg.SweepImage != want {
		t.Errorf("SweepImage = %q, want %q", cfg.SweepImage, want)
	}
}

func TestSweepImageTag(t *testing.T) {
	for cliVersion, want := range map[string]string{
		"dev":               "main",
		"v0.1.0":            "v0.1.0",
		"v0.1.0-5-gabc1234": "main",
		"v0.92.0-beta.2":    "main",
	} {
		if got := sweepImageTag(cliVersion); got != want {
			t.Errorf("sweepImageTag(%q) = %q, want %q", cliVersion, got, want)
		}
	}
}

func TestHostSweepDaemonSetShape(t *testing.T) {
	cfg := hostUninstallConfig{
		ContainerdConfigDir: "/etc/containerd",
		RestartCommand:      hostRestartCommand,
		SweepImage:          "busybox@sha256:abc",
		NriPluginDir:        "/opt/nri/plugins",
		NriPluginFilename:   "10-nri-image-policy",
		NriConfigDir:        "/etc/nri/conf.d",
		NriRuntimeDir:       "/run/nri-image-policy",
		NriCacheDir:         "/var/lib/nri-image-policy",
		ImagePullSecretRef:  []string{"regcred"},
	}
	cfg.SweepArgv = []string{"/bin/sh", "-c", hostSweepScript}
	cfg.PauseArgv = []string{"/bin/sleep", "2147483647"}
	ds := hostSweepDaemonSet("c8s", "c8s-system", cfg)

	if ds.Name != "c8s-host-sweep" || ds.Namespace != "c8s-system" {
		t.Errorf("metadata = %s/%s, want c8s-system/c8s-host-sweep", ds.Namespace, ds.Name)
	}

	pod := ds.Spec.Template.Spec
	// The sweep must reach every linux node: the NRI installer and the mesh
	// DaemonSets are deployed on all nodes, and a node can
	// carry a previous shape's leftovers. All taints tolerated; hostPID for
	// the nsenter-driven host work.
	wantSelector := map[string]string{
		"kubernetes.io/os": "linux",
	}
	if !reflect.DeepEqual(pod.NodeSelector, wantSelector) {
		t.Errorf("nodeSelector = %v, want %v", pod.NodeSelector, wantSelector)
	}
	if len(pod.ImagePullSecrets) != 1 || pod.ImagePullSecrets[0].Name != "regcred" {
		t.Errorf("imagePullSecrets = %v, want [regcred]", pod.ImagePullSecrets)
	}
	if len(pod.Tolerations) != 1 || pod.Tolerations[0].Operator != "Exists" {
		t.Errorf("tolerations = %v, want a single operator:Exists", pod.Tolerations)
	}
	if !pod.HostPID {
		t.Error("hostPID = false, want true")
	}

	if len(pod.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(pod.InitContainers))
	}
	sweep := pod.InitContainers[0]
	if sweep.SecurityContext == nil || sweep.SecurityContext.Privileged == nil || !*sweep.SecurityContext.Privileged {
		t.Error("sweep container is not privileged; it cannot touch the host paths")
	}
	if sweep.Image != cfg.SweepImage {
		t.Errorf("sweep image = %q, want %q", sweep.Image, cfg.SweepImage)
	}
	if !reflect.DeepEqual(sweep.Command, []string{"/bin/sh", "-c", hostSweepScript}) || len(sweep.Args) != 0 {
		t.Errorf("sweep argv = %v + %v, want [/bin/sh -c host-sweep.sh]", sweep.Command, sweep.Args)
	}
	pause := pod.Containers[0]
	// The pin's other copy of this literal lives in c8s.argvPinnedEntries.
	if !reflect.DeepEqual(pause.Command, []string{"/bin/sleep", "2147483647"}) || len(pause.Args) != 0 {
		t.Errorf("pause argv = %v + %v, want [/bin/sleep 2147483647]", pause.Command, pause.Args)
	}
	// The script's env contract (see host-sweep.sh header) — every value the
	// release config carries must be plumbed.
	wantEnv := map[string]string{
		"HOST_CONTAINERD_DIR": "/etc/containerd",
		"RESTART_COMMAND":     hostRestartCommand,
		"NRI_PLUGIN_DIR":      "/opt/nri/plugins",
		"NRI_PLUGIN_FILENAME": "10-nri-image-policy",
		"NRI_CONFIG_DIR":      "/etc/nri/conf.d",
		"NRI_RUNTIME_DIR":     "/run/nri-image-policy",
		"NRI_CACHE_DIR":       "/var/lib/nri-image-policy",
	}
	gotEnv := map[string]string{}
	for _, e := range sweep.Env {
		gotEnv[e.Name] = e.Value
	}
	if !reflect.DeepEqual(gotEnv, wantEnv) {
		t.Errorf("sweep env = %v, want %v", gotEnv, wantEnv)
	}

	// The host root must be mounted where the script expects it.
	if len(pod.Volumes) != 1 || pod.Volumes[0].HostPath == nil || pod.Volumes[0].HostPath.Path != "/" {
		t.Errorf("volumes = %v, want a single hostPath /", pod.Volumes)
	}
	if len(sweep.VolumeMounts) != 1 || sweep.VolumeMounts[0].MountPath != "/host" {
		t.Errorf("sweep volume mounts = %v, want /host", sweep.VolumeMounts)
	}

	// Selector must match the template labels or the DaemonSet is rejected.
	if !reflect.DeepEqual(ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels) {
		t.Errorf("selector %v does not match template labels %v", ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels)
	}
}

// The sweep cleans the containerd layout and the plugin paths the chart
// renders as constants; the release only names the pull secrets, the sweep
// image and the two host paths a stock values file sets.
func TestHostConfigFromValues(t *testing.T) {
	tree := chartValuesTree(t, `
nriImagePolicy:
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
    digest: "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
`)
	cfg, err := hostConfigFromValues(tree)
	if err != nil {
		t.Fatalf("hostConfigFromValues: %v", err)
	}
	want := hostUninstallConfig{
		ContainerdConfigDir: "/etc/containerd",
		RestartCommand:      "systemctl restart containerd",
		SweepImage:          "ghcr.io/confidential-dot-ai/nri-image-policy@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028",
		SweepArgv:           []string{"/bin/sh", "-c", hostSweepScript},
		PauseArgv:           []string{"/bin/sleep", "2147483647"},
		NriPluginDir:        "/opt/nri/plugins",
		NriPluginFilename:   "10-nri-image-policy",
		NriConfigDir:        "/etc/nri/conf.d",
		NriRuntimeDir:       "/run/nri-image-policy",
		NriCacheDir:         "/var/lib/nri-image-policy",
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v, want %+v", cfg, want)
	}
}
