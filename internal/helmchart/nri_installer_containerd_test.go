package helmchart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Host containerd configs the installer meets. COS ships an NRI table of its
// own, with a validator subtable, ahead of other tables.
const (
	cosContainerdConfig = `version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.10"

[plugins."io.containerd.nri.v1.nri"]
  disable = false
  plugin_path = "/home/kubernetes/bin/nri"
  socket_path = "/var/run/nri/nri.sock"

[plugins."io.containerd.nri.v1.nri".default_validator]
  enable = false

[plugins."io.containerd.grpc.v1.cri".containerd]
  default_runtime_name = "runc"
`
	v3ContainerdConfig = `version = 3

[plugins.'io.containerd.cri.v1.runtime']
  enable_selinux = false

[plugins.'io.containerd.nri.v1.nri']
  disable = true
`
	plainContainerdConfig = `version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.10"
`
	dottedNRIContainerdConfig = `version = 2

[plugins]
  "io.containerd.nri.v1.nri".disable = false
`
	v1ContainerdConfig = `[plugins.cri]
  sandbox_image = "registry.k8s.io/pause:3.10"
`
	versionBehindATableContainerdConfig = `[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry.k8s.io/pause:3.10"

version = 2
`
	unpairedMarkerContainerdConfig = plainContainerdConfig + "# BEGIN c8s-nri-image-policy (managed)\n"
)

// installerScript is the rendered install init container's script as the
// kubelet runs it.
func installerScript(t *testing.T) string {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	return strings.ReplaceAll(containerArgs(t, &ds, "install")[0], "$$", "$")
}

// nriTable is the NRI table containerd reads from config, which must parse.
func nriTable(t *testing.T, config string) map[string]any {
	t.Helper()
	var cfg struct {
		Plugins map[string]map[string]any `toml:"plugins"`
	}
	if err := toml.Unmarshal([]byte(config), &cfg); err != nil {
		t.Fatalf("containerd config does not parse: %v\n%s", err, config)
	}
	return cfg.Plugins[nriPlugin]
}

// The installer comments out the host's own NRI table, appends its block
// once, and a second run, or a run after a reboot that kept the file, changes
// nothing and restarts nothing.
func TestChartNriInstallerEditsContainerdConfigOnce(t *testing.T) {
	script := installerScript(t)
	for _, tc := range []struct {
		name, config, hostTableLine, keptLine string
	}{
		{
			"COS with an NRI table, version 2",
			cosContainerdConfig,
			`[plugins."io.containerd.nri.v1.nri".default_validator]`,
			"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd]\n  default_runtime_name = \"runc\"\n",
		},
		{
			"an NRI table, version 3",
			v3ContainerdConfig,
			`[plugins.'io.containerd.nri.v1.nri']`,
			"\n  enable_selinux = false\n",
		},
		{
			"no NRI table",
			plainContainerdConfig,
			"",
			"\n  sandbox_image = \"registry.k8s.io/pause:3.10\"\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNodeFixture(t, tc.config)
			if out, err := n.run(t, script); err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			if !n.restarted(t) {
				t.Error("installer patched containerd's config without restarting it")
			}
			patched := n.read(t, nodeContainerdTOML)
			nri := nriTable(t, patched)
			if nri["plugin_path"] != "/opt/nri/plugins" {
				t.Errorf("NRI plugin_path = %v, want the installer's /opt/nri/plugins\n%s", nri["plugin_path"], patched)
			}
			if tc.hostTableLine != "" && !strings.Contains(patched, "\n#c8s-nri-image-policy: "+tc.hostTableLine+"\n") {
				t.Errorf("host table line %q is not marked out\n%s", tc.hostTableLine, patched)
			}
			if !strings.Contains(patched, tc.keptLine) {
				t.Errorf("%q, outside the host's NRI table, was dropped\n%s", tc.keptLine, patched)
			}

			n.startPlugin(t)
			if out, err := n.run(t, script); err != nil {
				t.Fatalf("second install: %v\n%s", err, out)
			}
			if again := n.read(t, nodeContainerdTOML); again != patched {
				t.Errorf("second run changed the config:\n%s\nwant\n%s", again, patched)
			}
			if n.restarted(t) {
				t.Error("second run restarted containerd with nothing changed")
			}
		})
	}
}

// A node whose config carries the block an earlier installer appended keeps
// its bytes, so an upgrade restarts nothing for the config.
func TestChartNriInstallerKeepsAnEarlierManagedBlock(t *testing.T) {
	script := installerScript(t)
	block := "# BEGIN c8s-nri-image-policy (managed)\n" + renderedNriToml(t, script) + "\n# END c8s-nri-image-policy (managed)\n"
	earlier := plainContainerdConfig + "\n" + block
	n := newNodeFixture(t, earlier)
	n.startPlugin(t)
	if out, err := n.run(t, script); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if got := n.read(t, nodeContainerdTOML); got != earlier {
		t.Errorf("config changed:\n%s\nwant\n%s", got, earlier)
	}
	if !calledWith(n.calls(t), "nsenter -t 1 -m -- containerd --config "+nodeContainerdTOML+" config dump") {
		t.Error("did not check the effective config of the unchanged file")
	}
}

// Every run checks the config containerd runs with, so an import or a
// containerd that drops the validator after the install fails the installer.
func TestChartNriInstallerRefusesAnEffectiveConfigWithoutThePlugin(t *testing.T) {
	script := installerScript(t)
	n := newNodeFixture(t, cosContainerdConfig)
	if out, err := n.run(t, script); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	installed := n.read(t, nodeContainerdTOML)
	n.startPlugin(t)
	out, err := n.run(t, script, "CONTAINERD_REQUIRES_NO_PLUGIN=1")
	if err == nil || !strings.Contains(out, "would start containers without the plugin") {
		t.Fatalf("install = %v, want a refusal naming the missing gate\n%s", err, out)
	}
	if n.read(t, nodeContainerdTOML) != installed || n.restarted(t) {
		t.Error("the refusal changed the config or restarted containerd")
	}
}

// A run that stopped after rendering leaves a candidate file the next run
// replaces.
func TestChartNriInstallerReplacesAnInterruptedCandidate(t *testing.T) {
	n := newNodeFixture(t, cosContainerdConfig)
	writeTestFile(t, n.hostPath(nodeContainerdTOML+".c8s-new"), "garbage [\n")
	if out, err := n.run(t, installerScript(t)); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	nriTable(t, n.read(t, nodeContainerdTOML))
	if n.exists(nodeContainerdTOML + ".c8s-new") {
		t.Error("the candidate config is left beside config.toml")
	}
}

// Each check the installer runs before it touches the node refuses the
// install with the node unchanged: no boot config, no binary, the containerd
// config's bytes, and no restart.
func TestChartNriInstallerRefusalsLeaveTheNodeUntouched(t *testing.T) {
	script := installerScript(t)
	for _, tc := range []struct {
		name, config, want string
		env                []string
	}{
		{"the plugin refuses the boot config", cosContainerdConfig, "the plugin refuses the boot config", []string{"CHECK_CONFIG_RC=1"}},
		{"the host has no syslog socket", cosContainerdConfig, "no syslog socket", []string{"HOST_HAS_NO_SYSLOG=1"}},
		{"containerd cannot load the result", cosContainerdConfig, "cannot load", []string{"CONTAINERD_REFUSES_CONFIG=1"}},
		{"containerd would not require the plugin", cosContainerdConfig, "would start containers without the plugin", []string{"CONTAINERD_REQUIRES_NO_PLUGIN=1"}},
		{"NRI set by a dotted key", dottedNRIContainerdConfig, "configures NRI outside a table of its own", nil},
		{"a version 1 config", v1ContainerdConfig, "declares containerd config version 1", nil},
		{"a version key behind a table", versionBehindATableContainerdConfig, "declares containerd config version 1", nil},
		{"an unpaired managed-block marker", unpairedMarkerContainerdConfig, "unpaired or twice", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNodeFixture(t, tc.config)
			out, err := n.run(t, script, tc.env...)
			if err == nil {
				t.Fatalf("install succeeded\n%s", out)
			}
			if !strings.Contains(out, tc.want) || !strings.Contains(out, "nothing on this node was changed") {
				t.Errorf("refusal does not say %q and that the node is unchanged:\n%s", tc.want, out)
			}
			if got := n.read(t, nodeContainerdTOML); got != tc.config {
				t.Errorf("containerd config changed:\n%s", got)
			}
			for _, path := range []string{nodeBootConfigPath, nodePluginPath, nodeContainerdTOML + ".c8s-new"} {
				if n.exists(path) {
					t.Errorf("%s written", path)
				}
			}
			if n.restarted(t) {
				t.Error("containerd restarted")
			}
		})
	}
}

// The plugin's config check runs on the files and syslog socket the plugin
// opens at start, before containerd is asked to load anything.
func TestChartNriInstallerChecksTheBootConfigFirst(t *testing.T) {
	n := newNodeFixture(t, cosContainerdConfig)
	if _, err := n.run(t, installerScript(t), "CHECK_CONFIG_RC=1"); err == nil {
		t.Fatal("install succeeded")
	}
	calls := n.calls(t)
	if !calledWith(calls, "nri-image-policy check-config --config=") {
		t.Errorf("no check-config call; calls %q", calls)
	}
	if calledWith(calls, "nsenter -t 1 -m -- containerd") || n.restarted(t) {
		t.Errorf("went on to containerd after the plugin refused its config; calls %q", calls)
	}
	for _, staged := range []string{"/etc/nri/conf.d/cds-address", "/etc/nri/conf.d/cds.json"} {
		if _, err := os.Stat(filepath.Join(n.podRoot, staged)); err != nil {
			t.Errorf("%s not staged for the check: %v", staged, err)
		}
	}
	if link, err := os.Readlink(filepath.Join(n.podRoot, "dev/log")); err != nil || link != "/proc/1/root/run/systemd/journal/dev-log" {
		t.Errorf("/dev/log in the pod = %q (%v), want the host's journal socket", link, err)
	}
}

// A plugin that never turns healthy exits before its logger reaches the
// pod, so the installer's failure carries the plugin's journal.
func TestChartNriInstallerPrintsThePluginJournal(t *testing.T) {
	n := newNodeFixture(t, cosContainerdConfig)
	out, err := n.run(t, installerScript(t), "PLUGIN_HEALTH_RC=7")
	if err == nil {
		t.Fatalf("install succeeded with the plugin unhealthy\n%s", out)
	}
	if !calledWith(n.calls(t), "nsenter -t 1 -m -- journalctl -t nri-image-policy") || !strings.Contains(out, "journal: plugin exited") {
		t.Errorf("failure does not carry the plugin's journal:\n%s", out)
	}
}

// NRI starts the plugin with its output on /dev/null, so every stock boot
// config logs to the host journal through syslog, as the worker image does.
func TestChartBootConfigLogsToTheHostJournal(t *testing.T) {
	t.Parallel()
	for _, platform := range cloudPlatforms {
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			out, err := helmTemplatePlatform(t, platform)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			var cfg struct {
				Logging struct {
					Syslog string `yaml:"syslog"`
				} `yaml:"logging"`
			}
			if err := yaml.Unmarshal(bootConfigYAML(t, out, "c8s-nri-image-policy-worker"), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Logging.Syslog != "/dev/log" {
				t.Errorf("logging.syslog = %q, want /dev/log", cfg.Logging.Syslog)
			}
		})
	}
}
