package helmchart

import (
	"path/filepath"
	"strings"
	"testing"
)

const gkePluginDir = "/home/kubernetes/bin/nri"

func requiresThePlugin(t *testing.T, containerdConfig string) bool {
	t.Helper()
	validator, _ := nriTable(t, containerdConfig)["default_validator"].(map[string]any)
	if enabled, _ := validator["enable"].(bool); !enabled {
		return false
	}
	required, _ := validator["required_plugins"].([]any)
	for _, name := range required {
		if plugin, _ := name.(string); plugin == "nri-image-policy" {
			return true
		}
	}
	return false
}

// A gke node boots with no gate: its own containerd configuration neither
// launches the plugin nor requires it, and /etc loses the plugin's files.
func TestChartGKEInstallerRestoresTheGateABootRemoved(t *testing.T) {
	t.Parallel()
	out, err := helmTemplatePlatform(t, "gke-snp")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.ReplaceAll(containerArgs(t, &ds, "install")[0], "$$", "$")

	n := newNodeFixture(t, cosContainerdConfig)
	if out, err := n.run(t, script); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	installed := n.read(t, nodeContainerdTOML)
	if !requiresThePlugin(t, installed) {
		t.Fatalf("the installed containerd config does not require the plugin\n%s", installed)
	}
	if dir := nriPluginDir(t, installed); dir != gkePluginDir {
		t.Fatalf("the installed config launches plugins from %s, not the %s a gke node keeps", dir, gkePluginDir)
	}
	plugin := filepath.Join(gkePluginDir, nodePluginFile)
	if !n.exists(plugin) {
		t.Fatalf("the installer left no plugin binary at %s", plugin)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	staged := []string{nodeBootConfigPath, cfg.Allowlist.Pull.CDSAddressFile, cfg.Allowlist.Pull.CDSMeasurementsConfig}
	for _, path := range staged {
		if !n.exists(path) {
			t.Fatalf("the installer did not stage %s", path)
		}
	}

	n.boot(t)
	if booted := n.read(t, nodeContainerdTOML); requiresThePlugin(t, booted) {
		t.Errorf("the node's own containerd config requires the plugin\n%s", booted)
	}
	if !n.exists(plugin) {
		t.Errorf("the boot took the plugin binary at %s", plugin)
	}
	for _, path := range staged {
		if n.exists(path) {
			t.Errorf("%s survived the boot, so this test does not exercise its restaging", path)
		}
	}

	if out, err := n.run(t, script); err != nil {
		t.Fatalf("install on the new boot: %v\n%s", err, out)
	}
	if got := n.read(t, nodeContainerdTOML); got != installed {
		t.Errorf("the gate is not back as it was:\n%s\nwant\n%s", got, installed)
	}
	if !n.restarted(t) {
		t.Error("the installer patched containerd's config without restarting it")
	}
	for _, path := range staged {
		if !n.exists(path) {
			t.Errorf("the plugin's %s is not back", path)
		}
	}
}

func nriPluginDir(t *testing.T, containerdConfig string) string {
	t.Helper()
	dir, named := nriTable(t, containerdConfig)["plugin_path"].(string)
	if !named {
		t.Fatalf("the NRI table names no plugin_path\n%s", containerdConfig)
	}
	return dir
}
