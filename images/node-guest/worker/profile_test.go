// Package profile checks the worker image's profile for internal consistency.
package profile

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/c8srunc"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// lines are path's lines, without comments and blanks.
func lines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// assignment matches a single-line shell assignment.
var assignment = regexp.MustCompile(`(?m)^([A-Z][A-Z0-9_]*)=(.*)$`)

// settings are the values path assigns, by name, unquoted.
func settings(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, m := range assignment.FindAllStringSubmatch(string(data), -1) {
		found[m[1]] = strings.Trim(m[2], `"`)
	}
	return found
}

// baked is the path of the file the worker image bakes at rel.
func baked(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("mkosi.extra", rel)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the worker image bakes no %s: %v", rel, err)
	}
	return path
}

// The wrapper the measured image's containerd runs is the binary this profile
// installs, and it execs the runtime the profile stages.
func TestTheWrapperExecsTheRuntimeTheProfileStages(t *testing.T) {
	sync := settings(t, "mkosi.sync")
	data, err := os.ReadFile(baked(t, "etc/containerd/conf.d/10-c8s-runc.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var dropIn struct {
		Plugins map[string]struct {
			Containerd struct {
				Runtimes map[string]struct {
					Options struct {
						BinaryName string `toml:"BinaryName"`
					} `toml:"options"`
				} `toml:"runtimes"`
			} `toml:"containerd"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &dropIn); err != nil {
		t.Fatal(err)
	}
	var handlers []string
	for _, plugin := range dropIn.Plugins {
		for name, runtime := range plugin.Containerd.Runtimes {
			if runtime.Options.BinaryName != sync["RUNC_WRAPPER"] {
				t.Errorf("handler %s runs %q, want the wrapper %s this profile installs", name, runtime.Options.BinaryName, sync["RUNC_WRAPPER"])
			}
			handlers = append(handlers, name)
		}
	}
	if len(handlers) == 0 {
		t.Fatal("the drop-in points no runtime handler at the wrapper")
	}
	realRunc := c8srunc.New(io.Discard).RealRunc
	staged := strings.Fields(strings.Trim(sync["RUNTIME_BINARIES"], "()"))
	dir, name := path.Split(realRunc)
	if strings.TrimSuffix(dir, "/") != sync["RUNTIME_BIN_DIR"] || !slices.Contains(staged, name) {
		t.Errorf("the wrapper execs %s, which this profile stages as neither of %v under %s", realRunc, staged, sync["RUNTIME_BIN_DIR"])
	}
}

// flagOfExecStart is the value the unit's ExecStart gives flag, written
// `--flag=value` or `--flag value`; a flag it leaves out, or gives twice, is a
// failure rather than an empty string. Only ExecStart is read, so a flag named
// in a comment cannot answer. A value never starts with a dash, so the flag
// that follows a switch is not read as its value.
var execFlagPattern = regexp.MustCompile(`--([a-z0-9-]+)[=\s]+([^-\s]\S*)`)

func flagOfExecStart(t *testing.T, path, flag string) string {
	t.Helper()
	var found []string
	for _, m := range execFlagPattern.FindAllStringSubmatch(unitValue(t, path, "ExecStart"), -1) {
		if m[1] == flag {
			found = append(found, m[2])
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s names --%s %d times in its ExecStart, want once", path, flag, len(found))
	}
	return found[0]
}

// unitValue is the value path assigns to a unit key; a key it leaves out, or
// assigns twice, is a failure.
func unitValue(t *testing.T, path, key string) string {
	t.Helper()
	var found []string
	for _, line := range lines(t, path) {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			found = append(found, strings.TrimSpace(value))
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s names %s %d times, want once", path, key, len(found))
	}
	return found[0]
}

// unitList are the units path names under key, as systemd accumulates them
// over repeated lines. An empty assignment resets a systemd list, which no
// unit of this image does, so it is a failure here.
func unitList(t *testing.T, path, key string) []string {
	t.Helper()
	var out []string
	for _, line := range lines(t, path) {
		value, ok := strings.CutPrefix(line, key+"=")
		if !ok {
			continue
		}
		if value = strings.TrimSpace(value); value == "" {
			t.Fatalf("%s resets its %s list", path, key)
		}
		out = append(out, strings.Fields(value)...)
	}
	return out
}

// tmpfilesDirs are the directories path creates.
func tmpfilesDirs(t *testing.T, path string) map[string]bool {
	t.Helper()
	dirs := map[string]bool{}
	for _, line := range lines(t, path) {
		fields := strings.Fields(line)
		if len(fields) > 1 && slices.Contains([]string{"d", "D"}, fields[0]) {
			dirs[strings.TrimSuffix(fields[1], "/")] = true
		}
	}
	return dirs
}

// The volume service runs only while the kubelet's pod directory exists, and
// only after staging: the watch that starts it is what the preset enables.
func TestVolumedWaitsForTheKubeletsPodDirectoryBehindStaging(t *testing.T) {
	watch := baked(t, "etc/systemd/system/volumed.path")
	service := baked(t, "etc/systemd/system/volumed.service")
	pods := flagOfExecStart(t, service, "kubelet-root") + "/pods"
	if got := unitValue(t, watch, "PathExists"); got != pods {
		t.Errorf("the watch waits for %q, want the pod directory under volumed's kubelet root, %q", got, pods)
	}
	if got := unitValue(t, watch, "Unit"); got != "volumed.service" {
		t.Errorf("the watch starts %q, want volumed.service", got)
	}
	if got := unitValue(t, service, "ConditionPathExists"); got != pods {
		t.Errorf("the service runs on condition %q, want %q, so nothing else can start it without one", got, pods)
	}
	if got := unitValue(t, service, "Restart"); got != "always" {
		t.Errorf("Restart = %q, want always: a worker serves volumes for as long as it runs", got)
	}
	if got := unitList(t, service, "Requires"); !slices.Contains(got, "worker-stage.service") {
		t.Errorf("the service requires %v, want worker-stage.service: volumed holds every volume key", got)
	}
	if got := unitList(t, service, "After"); !slices.Contains(got, "worker-stage.service") {
		t.Errorf("the service starts after %v, want worker-stage.service among them", got)
	}
	if !slices.Contains(lines(t, baked(t, "usr/lib/systemd/system-preset/50-worker.preset")), "enable volumed.path") {
		t.Error("the preset does not enable volumed.path; an unenabled watch never starts volumed")
	}
}

// volumed serves in the directory the plugin mounts into a workload's
// sidecar, which this image's tmpfiles create.
func TestVolumedServesWhereTheTmpfilesCreate(t *testing.T) {
	socketDir := flagOfExecStart(t, baked(t, "etc/systemd/system/volumed.service"), "socket-dir")
	if !tmpfilesDirs(t, baked(t, "etc/tmpfiles.d/c8s-worker.conf"))[socketDir] {
		t.Errorf("--socket-dir = %q, which the image's tmpfiles do not create", socketDir)
	}
}

// containerd launches its plugin_path only when it starts itself, so systemd
// runs the admission plugin containerd requires and brings it back whenever it
// exits, and containerd launches no second copy.
func TestSystemdRestartsTheRequiredPlugin(t *testing.T) {
	service := baked(t, "etc/systemd/system/nri-image-policy.service")
	if got := unitValue(t, service, "Restart"); got != "always" {
		t.Errorf("Restart = %q, want always: containerd never relaunches a plugin it dropped", got)
	}
	if got := unitValue(t, service, "StartLimitIntervalSec"); got != "0" {
		t.Errorf("StartLimitIntervalSec = %q, want 0, so systemd never gives up", got)
	}
	if !slices.Contains(lines(t, baked(t, "usr/lib/systemd/system-preset/50-worker.preset")), "enable nri-image-policy.service") {
		t.Error("the preset does not enable nri-image-policy.service")
	}
	var cfg struct {
		Plugins map[string]struct {
			PluginPath string `toml:"plugin_path"`
		} `toml:"plugins"`
	}
	data, err := os.ReadFile(baked(t, containerdDropIns+"/nri-image-policy.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	pluginPath := cfg.Plugins["io.containerd.nri.v1.nri"].PluginPath
	if plugin := unitValue(t, service, "ExecStart"); filepath.Dir(plugin) == pluginPath {
		t.Errorf("plugin_path = %q, from which containerd would launch a second copy of %s", pluginPath, plugin)
	}
}

// Every unit containerd requires, and every unit the presets enable, is one
// the worker image has or its base provides.
func TestUnitsNameUnitsTheImageHas(t *testing.T) {
	units := map[string]bool{"attestation-api.service": true, "systemd-timesyncd.service": true, "systemd-time-wait-sync.service": true, "apparmor.service": true}
	own, err := filepath.Glob("mkosi.extra/etc/systemd/system/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range own {
		units[filepath.Base(path)] = true
	}
	var named []string
	for _, line := range lines(t, "mkosi.extra/etc/systemd/system/containerd.service") {
		if value, ok := strings.CutPrefix(line, "Requires="); ok {
			named = append(named, strings.Fields(value)...)
		}
	}
	for _, line := range lines(t, "mkosi.extra/usr/lib/systemd/system-preset/50-worker.preset") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("preset line %q is not <verb> <unit>", line)
		}
		named = append(named, fields[1])
	}
	if !slices.Contains(named, "gpu-cc-enforce.service") || !slices.Contains(named, "kubelet.service") {
		t.Fatalf("named units = %v, want containerd's gates and the presets", named)
	}
	for _, unit := range named {
		if !units[unit] {
			t.Errorf("%s is no unit of the worker image", unit)
		}
	}
}

// containerdConfig is the configuration the image's containerd reads, and
// conf.d the drop-ins it imports.
const (
	containerdConfig  = "etc/containerd/config.toml"
	containerdDropIns = "etc/containerd/conf.d"
)

// The versions the profile pins are the ones the rest of the tree is written
// against: the wrapper's view of runc's command line, and the Kubernetes
// version the static pods run.
func TestThePinnedVersionsAreTheOnesTheTreeNames(t *testing.T) {
	sync := settings(t, "mkosi.sync")
	if got := sync["RUNC_VERSION"]; got != c8srunc.RuncVersion {
		t.Errorf("the profile stages runc %s, and the wrapper parses the global options of %s", got, c8srunc.RuncVersion)
	}
	proxy, err := os.ReadFile(testutil.RepoPath("charts", "worker", "files", "static-pods", "kube-proxy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	image := regexp.MustCompile(`image: \S+/kube-proxy:(\S+)@sha256:`).FindSubmatch(proxy)
	if image == nil {
		t.Fatal("the kube-proxy static pod names no kube-proxy image pinned by tag and digest")
	}
	if got := string(image[1]); got != sync["KUBERNETES_VERSION"] {
		t.Errorf("kube-proxy runs %s, and the profile stages the kubelet of %s", got, sync["KUBERNETES_VERSION"])
	}
}

// bakedContainerd is the worker image's containerd configuration, in the
// fields the rest of the image names. Every plugin table decodes into one
// shape; a plugin that holds none of these keys leaves them empty.
type bakedContainerd struct {
	Root    string   `toml:"root"`
	Imports []string `toml:"imports"`
	Plugins map[string]struct {
		Address             string `toml:"address"`
		Snapshotter         string `toml:"snapshotter"`
		StreamServerAddress string `toml:"stream_server_address"`
		CNI                 struct {
			BinDirs []string `toml:"bin_dirs"`
			ConfDir string   `toml:"conf_dir"`
		} `toml:"cni"`
		Containerd struct {
			Runtimes map[string]struct {
				PodAnnotations []string `toml:"pod_annotations"`
			} `toml:"runtimes"`
		} `toml:"containerd"`
	} `toml:"plugins"`
}

// bakedContainerdConfig is the configuration the image's containerd reads.
func bakedContainerdConfig(t *testing.T) bakedContainerd {
	t.Helper()
	data, err := os.ReadFile(baked(t, containerdConfig))
	if err != nil {
		t.Fatal(err)
	}
	var cfg bakedContainerd
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// stateDirs are the directories the profile declares writable under the
// immutable root, as absolute paths.
func stateDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	for _, line := range lines(t, baked(t, "usr/lib/confai/state.d/60-worker.conf")) {
		dirs = append(dirs, "/"+strings.Trim(line, "/"))
	}
	if len(dirs) == 0 {
		t.Fatal("the profile declares no writable state")
	}
	return dirs
}

// writableState reports whether dir is one of the declared state directories
// or lies under one; anything else is read-only on a booted worker.
func writableState(state []string, dir string) bool {
	for _, declared := range state {
		if dir == declared || strings.HasPrefix(dir, declared+"/") {
			return true
		}
	}
	return false
}

// Settings the image's own files rest on are stated in the measured
// configuration, not inherited from the pinned containerd's defaults.
func TestTheConfigStatesWhatTheImageRestsOn(t *testing.T) {
	cfg := bakedContainerdConfig(t)
	if got := cfg.Plugins["io.containerd.cri.v1.images"].Snapshotter; got != "overlayfs" {
		t.Errorf("the image snapshotter is %q, and containerd-data-disk.service backs %s because the overlayfs one cannot stack on an overlay", got, cfg.Root)
	}
	stream := cfg.Plugins["io.containerd.grpc.v1.cri"].StreamServerAddress
	if ip := net.ParseIP(stream); ip == nil || !ip.IsLoopback() {
		t.Errorf("the CRI stream server binds %q, want a loopback address: no exec or port-forward stream may reach a node address", stream)
	}
	cni := cfg.Plugins["io.containerd.cri.v1.runtime"].CNI
	state := stateDirs(t)
	sync, err := os.ReadFile("mkosi.sync")
	if err != nil {
		t.Fatal(err)
	}
	dirs := append(slices.Clone(cni.BinDirs), cni.ConfDir)
	if len(dirs) != 2 {
		t.Fatalf("the config names %d CNI directories, want the plugin and the configuration directory", len(dirs))
	}
	for _, dir := range dirs {
		if !writableState(state, dir) {
			t.Errorf("containerd reads CNI from %q, which the profile does not declare writable (%v); Cilium installs itself there at boot", dir, state)
		}
		if !strings.Contains(string(sync), strings.TrimPrefix(dir, "/")) {
			t.Errorf("containerd reads CNI from %q, which mkosi.sync does not create; the initrd overlays only directories the image bakes", dir)
		}
	}
}

// The runtime's unit, its data disk, the NRI floor and the drop-ins all name
// one containerd layout.
func TestOneContainerdLayout(t *testing.T) {
	cfg := bakedContainerdConfig(t)
	unit := baked(t, "etc/systemd/system/containerd.service")
	if got, want := flagOfExecStart(t, unit, "config"), "/"+containerdConfig; got != want {
		t.Errorf("containerd reads %s, want the config the image bakes at %s", got, want)
	}
	if got, want := cfg.Imports, []string{"/" + containerdDropIns + "/*.toml"}; !slices.Equal(got, want) {
		t.Errorf("the config imports %v, want %v, the drop-ins the image bakes", got, want)
	}
	if _, err := os.Stat(filepath.Join("mkosi.extra", containerdDropIns)); err != nil {
		t.Errorf("the worker image bakes no %s: %v", containerdDropIns, err)
	}
	disk := settings(t, baked(t, "usr/local/bin/containerd-data-disk.sh"))["DIR"]
	if disk == "" {
		t.Fatal("containerd-data-disk.sh assigns no DIR; the mount and containerd's root cannot be compared")
	}
	if cfg.Root != disk {
		t.Errorf("containerd's root is %s, which containerd-data-disk.sh does not back (it mounts %s)", cfg.Root, disk)
	}
	socket := cfg.Plugins["io.containerd.server.v1.grpc"].Address
	if floor := floorSocket(t); socket != floor {
		t.Errorf("containerd binds %s, and the NRI floor dials %s", socket, floor)
	}
}

// floorSocket is the containerd socket the floor template pins.
func floorSocket(t *testing.T) string {
	t.Helper()
	var template struct {
		Containerd struct {
			Socket string `yaml:"socket"`
		} `yaml:"containerd"`
	}
	data, err := os.ReadFile("image-policy.yaml.in")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &template); err != nil {
		t.Fatal(err)
	}
	return template.Containerd.Socket
}

// The runtime every static pod runs under passes the kubelet's static pod
// mark into the bundle, where c8s-runc's floor reads it.
func TestContainerdPassesTheStaticPodMark(t *testing.T) {
	cfg := bakedContainerdConfig(t)
	runc := cfg.Plugins["io.containerd.cri.v1.runtime"].Containerd.Runtimes["runc"]
	if !slices.Contains(runc.PodAnnotations, "kubernetes.io/config.source") {
		t.Fatalf("runc pod_annotations = %v, want the kubelet's kubernetes.io/config.source", runc.PodAnnotations)
	}
}

// A worker has no window in which a container runs before admission: its
// containerd requires the plugin from boot, through a drop-in the image bakes,
// and a container found running at the plugin's first registration powers the
// node off.
func TestWorkerRequiresTheImagePolicyPluginFromBoot(t *testing.T) {
	var dropIn nriimagepolicy.ContainerdNRIConfig
	data, err := os.ReadFile(baked(t, containerdDropIns+"/nri-image-policy.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(data, &dropIn); err != nil {
		t.Fatal(err)
	}
	validator := dropIn.Plugins[nriimagepolicy.NRIPluginID].DefaultValidator
	if !validator.Enable || !slices.Equal(validator.RequiredPlugins, []string{"nri-image-policy"}) {
		t.Errorf("NRI default_validator = %+v, want enabled and requiring nri-image-policy", validator)
	}

	var policy struct {
		Policy struct {
			FatalExisting bool `json:"fatal_existing"`
		} `json:"policy"`
	}
	data, err = os.ReadFile("image-policy.yaml.in")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	if !policy.Policy.FatalExisting {
		t.Error("image-policy.yaml.in does not set policy.fatal_existing")
	}
}
