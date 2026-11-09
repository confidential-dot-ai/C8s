package helmchart

import (
	"strings"
	"testing"
)

// nriRemover is one of the two scripts that take the plugin off a node: the
// chart's pre-delete hook and the CLI's host sweep.
type nriRemover struct {
	name   string
	script string
}

func nriRemovers(t *testing.T) []nriRemover {
	t.Helper()
	return []nriRemover{
		{"pre-delete hook", uninstallScript(t)},
		{"host sweep", HostSweepScript()},
	}
}

// uninstallScript is the rendered pre-delete hook's script as the kubelet runs
// it.
func uninstallScript(t *testing.T) string {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-uninstall")
	return containerArgs(t, &ds, "uninstall")[0]
}

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

// Both removers restore the host's containerd config byte for byte, delete
// every plugin binary before the restart so containerd launches none again,
// and leave no plugin artifact behind.
func TestChartNriRemoversRestoreTheHostConfig(t *testing.T) {
	installer := installerScript(t)
	earlierPluginPath := "/opt/nri/plugins/05-nri-image-policy"
	for _, r := range nriRemovers(t) {
		t.Run(r.name, func(t *testing.T) {
			n := installedNode(t, installer, cosContainerdConfig)
			writeTestFile(t, n.hostPath(earlierPluginPath), "an earlier install")
			if out, err := n.run(t, r.script); err != nil {
				t.Fatalf("remove: %v\n%s", err, out)
			}
			if got := n.read(t, nodeContainerdTOML); got != cosContainerdConfig {
				t.Errorf("containerd config not restored:\n%s\nwant\n%s", got, cosContainerdConfig)
			}
			calls := n.calls(t)
			if !n.restarted(t) || calledWith(calls, "plugin binary present at restart") {
				t.Errorf("want a restart after the binary is gone; calls %q", calls)
			}
			for _, path := range []string{earlierPluginPath, nodePluginPath, nodeBootConfigPath} {
				if n.exists(path) {
					t.Errorf("%s left on the node", path)
				}
			}
		})
	}
}

// The restart follows the host, not this run's edit: a run after one that
// stripped the block but never restarted containerd still restarts while the
// plugin runs, and a run on a clean node restarts nothing.
func TestChartNriRemoversRestartWhileThePluginRuns(t *testing.T) {
	installer := installerScript(t)
	for _, r := range nriRemovers(t) {
		t.Run(r.name, func(t *testing.T) {
			n := installedNode(t, installer, cosContainerdConfig)
			out, err := n.run(t, r.script, "RESTART_FAILS=1")
			if err == nil {
				t.Fatalf("a run whose restart failed succeeded\n%s", out)
			}
			if !n.exists(nodeBootConfigPath) {
				t.Error("an interrupted run removed the boot config a retry needs")
			}

			if out, err := n.run(t, r.script); err != nil {
				t.Fatalf("retry: %v\n%s", err, out)
			}
			if !n.restarted(t) {
				t.Error("retry left the running plugin to the old containerd")
			}
			if n.exists(nodeBootConfigPath) {
				t.Error("retry left the boot config")
			}

			if out, err := n.run(t, r.script); err != nil {
				t.Fatalf("run on a clean node: %v\n%s", err, out)
			}
			if n.restarted(t) {
				t.Error("restarted containerd on a clean node")
			}
		})
	}
}

// A plugin that outlives the restart fails the run, which keeps the artifacts
// a retry needs.
func TestChartNriRemoversFailWhileThePluginSurvives(t *testing.T) {
	installer := installerScript(t)
	for _, r := range nriRemovers(t) {
		t.Run(r.name, func(t *testing.T) {
			n := installedNode(t, installer, plainContainerdConfig)
			out, err := n.run(t, r.script, "PLUGIN_SURVIVES=1")
			if err == nil {
				t.Fatalf("succeeded with the plugin still running\n%s", out)
			}
			if !strings.Contains(out, "still runs after the containerd restart") {
				t.Errorf("failure does not name the running plugin:\n%s", out)
			}
			if !n.exists(nodeBootConfigPath) {
				t.Error("removed the boot config while the plugin still runs")
			}
		})
	}
}

// A plugin scan that cannot answer counts as a running plugin: the remover
// restarts containerd and fails rather than leave the plugin to it.
func TestChartNriRemoversTreatAnUnknownPluginAsRunning(t *testing.T) {
	installer := installerScript(t)
	for _, r := range nriRemovers(t) {
		t.Run(r.name, func(t *testing.T) {
			n := installedNode(t, installer, plainContainerdConfig)
			if out, err := n.run(t, r.script, "RESTART_FAILS=1"); err == nil {
				t.Fatalf("a run whose restart failed succeeded\n%s", out)
			}
			out, err := n.run(t, r.script, "PLUGIN_SCAN_FAILS=1")
			if err == nil {
				t.Fatalf("succeeded without knowing whether the plugin runs\n%s", out)
			}
			if !n.restarted(t) {
				t.Error("an unknown plugin state did not restart containerd")
			}
			if !n.exists(nodeBootConfigPath) {
				t.Error("removed the boot config without knowing whether the plugin runs")
			}
		})
	}
}

// A config whose managed-block markers are unpaired is left to the operator:
// no remover guesses which host lines are its own.
func TestChartNriRemoversRefuseUnpairedMarkers(t *testing.T) {
	for _, r := range nriRemovers(t) {
		t.Run(r.name, func(t *testing.T) {
			n := newNodeFixture(t, unpairedMarkerContainerdConfig)
			writeTestFile(t, n.hostPath(nodePluginPath), "plugin")
			out, err := n.run(t, r.script)
			if err == nil || !strings.Contains(out, "unpaired or twice") {
				t.Fatalf("remove = %v, want a refusal naming the markers\n%s", err, out)
			}
			if n.read(t, nodeContainerdTOML) != unpairedMarkerContainerdConfig {
				t.Error("edited a config with unpaired markers")
			}
			if !n.exists(nodePluginPath) || n.restarted(t) {
				t.Error("removed the binary or restarted containerd under a config it could not restore")
			}
		})
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
