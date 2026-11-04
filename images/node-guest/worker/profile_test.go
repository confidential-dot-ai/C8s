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

// baseUnits are the units the worker image's base packages provide.
var baseUnits = []string{"attestation-api.service", "systemd-timesyncd.service", "systemd-time-wait-sync.service", "apparmor.service"}

// Every unit containerd requires, and every unit the presets enable, is one
// the worker image has or its base provides.
func TestUnitsNameUnitsTheImageHas(t *testing.T) {
	units := map[string]bool{}
	for _, unit := range baseUnits {
		units[unit] = true
	}
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

// bootGates are the services the worker image defines that start before
// staging: staging itself, the boot gates and the disks containerd mounts.
var bootGates = []string{
	"worker-stage.service",
	"apparmor-enforce.service",
	"c8s-modules-latch.service",
	"scratch-enforce.service",
	"gpu-cc-enforce.service",
	"containerd-data-disk.service",
	"models-disk.service",
}

// enabledUnits are the units 50-worker.preset enables.
func enabledUnits(t *testing.T) []string {
	t.Helper()
	var enabled []string
	for _, line := range lines(t, "mkosi.extra/usr/lib/systemd/system-preset/50-worker.preset") {
		if unit, ok := strings.CutPrefix(line, "enable "); ok {
			enabled = append(enabled, strings.TrimSpace(unit))
		}
	}
	return enabled
}

// unitFile is unit's file in the worker image: the c8s profile's when the
// worker shares it, otherwise the worker profile's.
func unitFile(t *testing.T, unit string) string {
	t.Helper()
	if slices.Contains(lines(t, "shared"), "etc/systemd/system/"+unit) {
		return filepath.Join(c8sProfile, "mkosi.extra/etc/systemd/system", unit)
	}
	return filepath.Join("mkosi.extra/etc/systemd/system", unit)
}

// dropIns are unit's drop-ins in the worker image: the worker profile's and
// any the worker shares.
func dropIns(t *testing.T, unit string) []string {
	t.Helper()
	dir := "etc/systemd/system/" + unit + ".d/"
	paths, err := filepath.Glob(filepath.Join("mkosi.extra", dir, "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, shared := range lines(t, "shared") {
		if strings.HasPrefix(shared, dir) {
			paths = append(paths, filepath.Join(c8sProfile, "mkosi.extra", shared))
		}
	}
	return paths
}

// unitDirectives maps each key of unit and its drop-ins, as systemd merges
// them in the worker image, to the whitespace-separated words of its values.
func unitDirectives(t *testing.T, unit string) map[string][]string {
	t.Helper()
	directives := map[string][]string{}
	for _, path := range append([]string{unitFile(t, unit)}, dropIns(t, unit)...) {
		for _, line := range lines(t, path) {
			if key, value, ok := strings.Cut(line, "="); ok {
				directives[key] = append(directives[key], strings.Fields(value)...)
			}
		}
	}
	return directives
}

func waitsForStaging(directives map[string][]string) bool {
	return slices.Contains(directives["Requires"], "worker-stage.service") &&
		slices.Contains(directives["After"], "worker-stage.service")
}

// namesRoleVerdict reports whether a directive's word names the node image's
// role verdict or the unit that stages it, neither of which a worker has.
func namesRoleVerdict(word string) bool {
	return word == "rke2-role.service" || strings.Contains(word, "/run/confos/role-")
}

func waitsOnRoleVerdict(directives map[string][]string) bool {
	for _, words := range directives {
		if slices.ContainsFunc(words, namesRoleVerdict) {
			return true
		}
	}
	return false
}

// A worker shares a c8s profile service only to run it.
func TestSharedServicesAreEnabled(t *testing.T) {
	enabled := enabledUnits(t)
	for _, shared := range lines(t, "shared") {
		unit, ok := strings.CutPrefix(shared, "etc/systemd/system/")
		if ok && strings.HasSuffix(unit, ".service") && !slices.Contains(enabled, unit) {
			t.Errorf("shared %s is not enabled in 50-worker.preset", unit)
		}
	}
}

// Every service the worker image defines, other than a boot gate, requires
// staging and starts after it.
func TestServicesStartAfterStaging(t *testing.T) {
	for _, unit := range enabledUnits(t) {
		if slices.Contains(baseUnits, unit) || slices.Contains(bootGates, unit) {
			continue
		}
		if !waitsForStaging(unitDirectives(t, unit)) {
			t.Errorf("%s does not require and start after worker-stage.service", unit)
		}
	}
}

// No service the worker image defines waits on the node image's role verdict.
func TestNoServiceWaitsOnRoleVerdict(t *testing.T) {
	for _, unit := range enabledUnits(t) {
		if slices.Contains(baseUnits, unit) {
			continue
		}
		if waitsOnRoleVerdict(unitDirectives(t, unit)) {
			t.Errorf("%s waits on the node image's role verdict", unit)
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
