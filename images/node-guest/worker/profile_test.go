// Package profile checks the worker profile against the c8s profile whose
// files and pins it shares.
package profile

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
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

// Each shared file is the c8s profile's, and the worker profile holds no copy
// whose precedence over it would be undefined.
func TestSharedFilesAreTheC8sProfiles(t *testing.T) {
	for _, shared := range lines(t, "shared") {
		if info, err := os.Stat(filepath.Join(c8sProfile, "mkosi.extra", shared)); err != nil || !info.Mode().IsRegular() {
			t.Errorf("shared %s is not a file of the c8s profile: %v", shared, err)
		}
		if _, err := os.Lstat(filepath.Join("mkosi.extra", shared)); err == nil {
			t.Errorf("the worker profile also bakes shared %s", shared)
		}
	}
}

// The worker image unpacks the RKE2 release and renders with the Helm the
// node image pins, and narrows the same attester.
func TestPinsAndFinalizeAreTheC8sProfiles(t *testing.T) {
	pin := regexp.MustCompile(`(?m)^(RKE2_VERSION|RKE2_IMAGES_CORE_SHA256|HELM_VERSION|HELM_LINUX_AMD64_SHA256)=(.*)$`)
	pins := func(path string) map[string]string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]string{}
		for _, m := range pin.FindAllStringSubmatch(string(data), -1) {
			found[m[1]] = m[2]
		}
		return found
	}
	worker, node := pins("mkosi.sync"), pins(filepath.Join(c8sProfile, "mkosi.sync"))
	if len(worker) != 4 {
		t.Fatalf("worker pins = %v, want four", worker)
	}
	for name, value := range worker {
		if node[name] != value {
			t.Errorf("%s = %s, want the c8s profile's %s", name, value, node[name])
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

// Every unit containerd requires, and every unit the presets enable, is one
// the worker image has or its base provides.
func TestUnitsNameUnitsTheImageHas(t *testing.T) {
	units := map[string]bool{"attestation-api.service": true, "systemd-timesyncd.service": true, "systemd-time-wait-sync.service": true, "apparmor.service": true}
	for _, shared := range lines(t, "shared") {
		units[filepath.Base(shared)] = true
	}
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
