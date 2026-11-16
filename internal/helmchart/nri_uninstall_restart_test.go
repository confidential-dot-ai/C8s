package helmchart

import (
	"strings"
	"testing"
)

// installedNode is a node the installer ran on, with the plugin running.
func installedNode(t *testing.T, installer, hostConfig string) *nodeFixture {
	t.Helper()
	n := newNodeFixture(t, hostConfig)
	if out, err := n.run(t, installer); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	n.startPlugin(t)
	return n
}

// The sweep restores the host's containerd config byte for byte, deletes every
// plugin binary before the restart so containerd launches none again, and
// leaves no plugin artifact behind: the documents the plugin renders itself and
// the directories the installer's mounts created go with it.
func TestHostSweepRestoresTheHostConfig(t *testing.T) {
	earlierPluginPath := "/opt/nri/plugins/05-nri-image-policy"
	n := installedNode(t, installerScript(t), cosContainerdConfig)
	writeTestFile(t, n.hostPath(earlierPluginPath), "an earlier install")
	writeTestFile(t, n.hostPath(nodeEnforcerDir+"/cds-pins.json"), "{}\n")
	writeTestFile(t, n.hostPath(nodeEnforcerDir+"/cds-address"), "cds.c8s-system:443\n")
	for _, path := range []string{nodeEnforcerDir, nodePluginDir, nodeConfigDir} {
		if !n.exists(path) {
			t.Fatalf("%s is not on the node the sweep runs against", path)
		}
	}

	if out, err := n.run(t, HostSweepScript()); err != nil {
		t.Fatalf("sweep: %v\n%s", err, out)
	}
	if got := n.read(t, nodeContainerdTOML); got != cosContainerdConfig {
		t.Errorf("containerd config not restored:\n%s\nwant\n%s", got, cosContainerdConfig)
	}
	calls := n.calls(t)
	if !n.restarted(t) || calledWith(calls, "plugin binary present at restart") {
		t.Errorf("want a restart after the binary is gone; calls %q", calls)
	}
	for _, path := range []string{
		earlierPluginPath,
		nodePluginPath,
		nodeBootConfigPath,
		nodeEnforcerDir,
		nodePluginDir,
		nodeConfigDir,
	} {
		if n.exists(path) {
			t.Errorf("%s left on the node", path)
		}
	}
}

// Another NRI plugin's config keeps the directory it sits in.
func TestHostSweepKeepsADirectoryAnotherPluginUses(t *testing.T) {
	n := installedNode(t, installerScript(t), cosContainerdConfig)
	foreign := nodeConfigDir + "/20-other-plugin.conf"
	writeTestFile(t, n.hostPath(foreign), "another plugin's config")

	if out, err := n.run(t, HostSweepScript()); err != nil {
		t.Fatalf("sweep: %v\n%s", err, out)
	}
	if !n.exists(foreign) {
		t.Errorf("the sweep removed %s", foreign)
	}
}

// The restart follows the host, not this run's edit: a run after one that
// stripped the block but never restarted containerd still restarts while the
// plugin runs, and a run on a clean node restarts nothing.
func TestHostSweepRestartsWhileThePluginRuns(t *testing.T) {
	n := installedNode(t, installerScript(t), cosContainerdConfig)
	out, err := n.run(t, HostSweepScript(), "RESTART_FAILS=1")
	if err == nil {
		t.Fatalf("a run whose restart failed succeeded\n%s", out)
	}
	if !n.exists(nodeBootConfigPath) {
		t.Error("an interrupted run removed the boot config a retry needs")
	}

	if out, err := n.run(t, HostSweepScript()); err != nil {
		t.Fatalf("retry: %v\n%s", err, out)
	}
	if !n.restarted(t) {
		t.Error("retry left the running plugin to the old containerd")
	}
	if n.exists(nodeBootConfigPath) {
		t.Error("retry left the boot config")
	}

	if out, err := n.run(t, HostSweepScript()); err != nil {
		t.Fatalf("run on a clean node: %v\n%s", err, out)
	}
	if n.restarted(t) {
		t.Error("restarted containerd on a clean node")
	}
}

// A plugin that outlives the restart fails the run, which keeps the artifacts
// a retry needs.
func TestHostSweepFailsWhileThePluginSurvives(t *testing.T) {
	n := installedNode(t, installerScript(t), plainContainerdConfig)
	out, err := n.run(t, HostSweepScript(), "PLUGIN_SURVIVES=1")
	if err == nil {
		t.Fatalf("succeeded with the plugin still running\n%s", out)
	}
	if !strings.Contains(out, "still runs after the containerd restart") {
		t.Errorf("failure does not name the running plugin:\n%s", out)
	}
	if !n.exists(nodeBootConfigPath) {
		t.Error("removed the boot config while the plugin still runs")
	}
}

// A plugin scan that cannot answer counts as a running plugin: the sweep
// restarts containerd and fails rather than leave the plugin to it.
func TestHostSweepTreatsAnUnknownPluginAsRunning(t *testing.T) {
	n := installedNode(t, installerScript(t), plainContainerdConfig)
	if out, err := n.run(t, HostSweepScript(), "RESTART_FAILS=1"); err == nil {
		t.Fatalf("a run whose restart failed succeeded\n%s", out)
	}
	out, err := n.run(t, HostSweepScript(), "PLUGIN_SCAN_FAILS=1")
	if err == nil {
		t.Fatalf("succeeded without knowing whether the plugin runs\n%s", out)
	}
	if !n.restarted(t) {
		t.Error("an unknown plugin state did not restart containerd")
	}
	if !n.exists(nodeBootConfigPath) {
		t.Error("removed the boot config without knowing whether the plugin runs")
	}
}

// A config whose managed-block markers are unpaired is left to the operator:
// the sweep does not guess which host lines are its own.
func TestHostSweepRefusesUnpairedMarkers(t *testing.T) {
	n := newNodeFixture(t, unpairedMarkerContainerdConfig)
	writeTestFile(t, n.hostPath(nodePluginPath), "plugin")
	out, err := n.run(t, HostSweepScript())
	if err == nil || !strings.Contains(out, "unpaired or twice") {
		t.Fatalf("sweep = %v, want a refusal naming the markers\n%s", err, out)
	}
	if n.read(t, nodeContainerdTOML) != unpairedMarkerContainerdConfig {
		t.Error("edited a config with unpaired markers")
	}
	if !n.exists(nodePluginPath) || n.restarted(t) {
		t.Error("removed the binary or restarted containerd under a config it could not restore")
	}
}

// The sweep's other steps run on a node whose plugin it could not remove.
func TestHostSweepContinuesPastThePlugin(t *testing.T) {
	n := newNodeFixture(t, unpairedMarkerContainerdConfig)
	if _, err := n.run(t, HostSweepScript()); err == nil {
		t.Fatal("sweep succeeded")
	}
	calls := n.calls(t)
	if !calledWith(calls, "for b in iptables-nft iptables; do") {
		t.Errorf("the netfilter sweep did not run; calls %q", calls)
	}
}
