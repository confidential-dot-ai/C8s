package helmchart

import (
	"path/filepath"
	"strings"
	"testing"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

func nriPluginDir(t *testing.T, config string) string {
	t.Helper()
	dir, named := nriTable(t, config)["plugin_path"].(string)
	if !named {
		t.Fatalf("the NRI table names no plugin_path\n%s", config)
	}
	return dir
}

// Container-Optimized OS serves /etc from tmpfs; the plugin directory persists.
func TestChartGKEInstallsTheConfigTheLaunchedPluginReads(t *testing.T) {
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
	bootDir := nriPluginDir(t, cosContainerdConfig)
	if dir := nriPluginDir(t, n.read(t, nodeContainerdTOML)); dir != bootDir {
		t.Fatalf("the installer launches the plugin from %s, not the %s the node's own containerd launches", dir, bootDir)
	}
	plugin := filepath.Join(bootDir, filepath.Base(nodePluginPath))
	if !n.exists(plugin) {
		t.Fatalf("the installer left no plugin binary at %s", plugin)
	}
	config := nriimagepolicy.InstalledConfigPath(plugin)
	if !n.exists(config) {
		t.Fatalf("the plugin containerd launches reads %s, which the installer did not write", config)
	}

	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if dir := filepath.Dir(cfg.Allowlist.Pull.CDSAddressFile); dir != filepath.Dir(config) {
		t.Errorf("the boot config reads the CDS address from %s, outside the directory the node keeps across a boot", cfg.Allowlist.Pull.CDSAddressFile)
	}
	if dir := filepath.Dir(cfg.Allowlist.Pull.CDSMeasurementsConfig); dir != filepath.Dir(config) {
		t.Errorf("the boot config reads the CDS pin from %s, outside the directory the node keeps across a boot", cfg.Allowlist.Pull.CDSMeasurementsConfig)
	}
}
