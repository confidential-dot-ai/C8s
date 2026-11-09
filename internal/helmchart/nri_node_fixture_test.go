package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// nodeFixture is a node the NRI installer and its removers run against: /host
// is a temp dir, and the c8s and nri-image-policy binaries, nsenter, curl,
// date and sleep are stubs that model the host. The plugin runs while
// pluginRunning exists, and a containerd restart ends it. date and sleep share
// a clock the sleeps advance, so a script's waits cost no wall-clock time.
type nodeFixture struct {
	root          string
	bin           string
	log           string
	cdsDir        string
	podRoot       string
	pluginRunning string
	clock         string
}

const (
	nodePluginPath     = "/opt/nri/plugins/10-nri-image-policy"
	nodeBootConfigPath = "/etc/nri/conf.d/image-policy.yaml"
	nodeContainerdTOML = "/etc/containerd/config.toml"
)

// nodeStubs are the host commands the scripts call. nsenter answers the
// syslog-socket lookup, containerd's config dump (the file it loads), the
// detached restart and the journal tail; the env named in each case decides
// the outcome.
var nodeStubs = map[string]string{
	"c8s": `case "$2" in
plugin-ready) [ -e "$PLUGIN_RUNNING" ] ;;
plugin-running)
  if [ -n "${PLUGIN_SCAN_FAILS:-}" ]; then echo "cannot scan /proc" >&2; exit 2; fi
  [ -e "$PLUGIN_RUNNING" ] || exit 1 ;;
esac`,
	"curl": `printf 'ok [http 200]'
exit "${PLUGIN_HEALTH_RC:-0}"`,
	"date": `cat "$CLOCK"`,
	"nri-image-policy": `case "$1" in
check-config) exit "${CHECK_CONFIG_RC:-0}" ;;
check-containerd-config) [ -z "${CONTAINERD_REQUIRES_NO_PLUGIN:-}" ] && grep -qF 'required_plugins = ["nri-image-policy"]' ;;
esac`,
	"nsenter": `case "$*" in
*"readlink -e /dev/log"*) [ -z "${HOST_HAS_NO_SYSLOG:-}" ] && echo /run/systemd/journal/dev-log ;;
*"config dump"*)
  if [ -n "${CONTAINERD_REFUSES_CONFIG:-}" ]; then echo "invalid plugin config" >&2; exit 1; fi
  cat "$HOST_ROOT$7" ;;
*systemd-run*)
  if [ -e "$PLUGIN_BIN" ]; then echo "plugin binary present at restart" >> "$CALLS"; fi
  if [ -n "${RESTART_FAILS:-}" ]; then exit 1; fi
  if [ -z "${PLUGIN_SURVIVES:-}" ]; then rm -f "$PLUGIN_RUNNING"; fi ;;
*journalctl*) echo "journal: plugin exited" ;;
esac`,
	"sleep": `echo $(($(cat "$CLOCK") + $1)) > "$CLOCK"`,
}

func newNodeFixture(t *testing.T, containerdConfig string) *nodeFixture {
	t.Helper()
	dir := t.TempDir()
	n := &nodeFixture{
		root:          filepath.Join(dir, "host"),
		bin:           filepath.Join(dir, "bin"),
		log:           filepath.Join(dir, "calls.log"),
		cdsDir:        filepath.Join(dir, "cds"),
		podRoot:       filepath.Join(dir, "pod"),
		pluginRunning: filepath.Join(dir, "plugin-running"),
		clock:         filepath.Join(dir, "clock"),
	}
	for _, d := range []string{
		filepath.Dir(n.hostPath(nodeContainerdTOML)),
		filepath.Join(n.podRoot, "dev"),
		n.bin,
		n.cdsDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, n.hostPath(nodeContainerdTOML), containerdConfig)
	writeTestFile(t, n.clock, "1000\n")
	writeTestFile(t, filepath.Join(n.cdsDir, "cds-address"), baseCDSAddress)
	writeTestFile(t, filepath.Join(n.cdsDir, "cds.json"), "{}\n")
	for name, body := range nodeStubs {
		stub := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> \"$CALLS\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(n.bin, name), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (n *nodeFixture) hostPath(path string) string { return filepath.Join(n.root, path) }

func (n *nodeFixture) startPlugin(t *testing.T) { writeTestFile(t, n.pluginRunning, "") }

// localize points a script's host, pod and binary paths into the fixture. The
// installer stages the boot config's inputs at the absolute paths the plugin
// opens them by, which in a test are under the fixture's pod root.
func (n *nodeFixture) localize(script string) string {
	for _, r := range [][2]string{
		{"\nboot_cds_address='", "\nboot_cds_address='" + n.podRoot},
		{"\nboot_cds_pin='", "\nboot_cds_pin='" + n.podRoot},
		{"\nboot_syslog='", "\nboot_syslog='" + n.podRoot},
		{"/host/", n.root + "/"},
		{"/host${", n.root + "${"},
		{"/usr/local/bin/c8s", filepath.Join(n.bin, "c8s")},
		{"/usr/local/bin/nri-image-policy", filepath.Join(n.bin, "nri-image-policy")},
		{"/mnt/c8s-data/measurements", n.cdsDir},
		{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PATH=" + n.bin + ":/usr/bin:/bin"},
	} {
		script = strings.ReplaceAll(script, r[0], r[1])
	}
	return script
}

// run runs script on the node with the removers' environment plus env, and
// returns its output and exit error.
func (n *nodeFixture) run(t *testing.T, script string, env ...string) (string, error) {
	t.Helper()
	_ = os.Remove(n.log)
	cmd := exec.Command("/bin/sh", "-c", n.localize(script))
	cmd.Env = append([]string{
		"PATH=" + n.bin + ":/usr/bin:/bin",
		"CALLS=" + n.log,
		"CLOCK=" + n.clock,
		// The host as the stubs see it: nsenter resolves a host path under it.
		"HOST_ROOT=" + n.root,
		"PLUGIN_RUNNING=" + n.pluginRunning,
		"PLUGIN_BIN=" + n.hostPath(nodePluginPath),
		"HOST_PLUGIN_PATH=" + nodePluginPath,
		"HOST_CONFIG_PATH=" + nodeBootConfigPath,
		"HOST_CDS_ADDRESS_PATH=/etc/nri/conf.d/cds-address",
		"HOST_CDS_PIN_PATH=/etc/nri/conf.d/cds.json",
		"HOST_CONTAINERD_DIR=/etc/containerd",
		"HOST_CACHE_DIR=/var/lib/nri-image-policy",
		"HOST_HEALTH_SOCKET=/run/nri-image-policy/health.sock",
		"RESTART_COMMAND=systemctl restart containerd",
		"NRI_PLUGIN_DIR=/opt/nri/plugins",
		"NRI_PLUGIN_FILENAME=10-nri-image-policy",
		"NRI_CONFIG_DIR=/etc/nri/conf.d",
		"NRI_RUNTIME_DIR=/run/nri-image-policy",
		"NRI_CACHE_DIR=/var/lib/nri-image-policy",
	}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (n *nodeFixture) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(n.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (n *nodeFixture) restarted(t *testing.T) bool {
	t.Helper()
	return calledWith(n.calls(t), "nsenter -t 1 -m -u -i -n -p -- systemd-run")
}

func (n *nodeFixture) read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(n.hostPath(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (n *nodeFixture) exists(path string) bool {
	_, err := os.Stat(n.hostPath(path))
	return err == nil
}
