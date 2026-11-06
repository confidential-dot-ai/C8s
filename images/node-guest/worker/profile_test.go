// Package profile checks the worker image's profile for internal consistency.
package profile

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/confidential-dot-ai/c8s/internal/cmds/c8srunc"
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
	data, err := os.ReadFile(baked(t, "var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/10-c8s-runc.toml"))
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
	if strings.TrimSuffix(dir, "/") != sync["RKE2_BIN_LINK"] || !slices.Contains(staged, name) {
		t.Errorf("the wrapper execs %s, which this profile stages as neither of %v under %s", realRunc, staged, sync["RKE2_BIN_LINK"])
	}
}

// flagOfExecStart is the value the unit's ExecStart gives flag; a flag it leaves out,
// or gives twice, is a failure rather than an empty string. Only ExecStart is
// read, so a flag named in a comment cannot answer.
var execFlagPattern = regexp.MustCompile(`--([a-z0-9-]+)=(\S+)`)

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

// The runtime every static pod runs under passes the kubelet's static pod
// mark into the bundle, where c8s-runc's floor reads it.
func TestContainerdPassesTheStaticPodMark(t *testing.T) {
	data, err := os.ReadFile("mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Plugins map[string]struct {
			Containerd struct {
				Runtimes map[string]struct {
					PodAnnotations []string `toml:"pod_annotations"`
				} `toml:"runtimes"`
			} `toml:"containerd"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	runc := cfg.Plugins["io.containerd.cri.v1.runtime"].Containerd.Runtimes["runc"]
	if !slices.Contains(runc.PodAnnotations, "kubernetes.io/config.source") {
		t.Fatalf("runc pod_annotations = %v, want the kubelet's kubernetes.io/config.source", runc.PodAnnotations)
	}
}
