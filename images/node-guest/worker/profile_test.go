// Package profile checks the worker profile against the c8s profile whose
// files and pins it shares.
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

const c8sProfile = "../c8s"

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

// The worker image unpacks the RKE2 release and renders with the Helm the
// node image pins, and narrows the same attester.
func TestPinsAndFinalizeAreTheC8sProfiles(t *testing.T) {
	worker, node := settings(t, "mkosi.sync"), settings(t, filepath.Join(c8sProfile, "mkosi.sync"))
	for _, pin := range []string{"RKE2_VERSION", "RKE2_IMAGES_CORE_SHA256", "HELM_VERSION", "HELM_LINUX_AMD64_SHA256"} {
		if worker[pin] == "" {
			t.Errorf("the worker profile states no %s", pin)
		}
		if node[pin] != worker[pin] {
			t.Errorf("%s = %s, want the c8s profile's %s", pin, worker[pin], node[pin])
		}
	}
	finalize, err := os.ReadFile("mkosi.finalize")
	if err != nil {
		t.Fatal(err)
	}
	if nodeFinalize, err := os.ReadFile(filepath.Join(c8sProfile, "mkosi.finalize")); err != nil || !bytes.Equal(finalize, nodeFinalize) {
		t.Errorf("mkosi.finalize differs from the c8s profile's: %v", err)
	}
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

// Every unit containerd requires, and every unit the presets enable, is one
// the worker image has or its base provides.
func TestUnitsNameUnitsTheImageHas(t *testing.T) {
	units := map[string]bool{"attestation-api.service": true, "systemd-timesyncd.service": true, "systemd-time-wait-sync.service": true, "apparmor.service": true}
	own, err := filepath.Glob("mkosi.extra/etc/systemd/system/*.service")
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
