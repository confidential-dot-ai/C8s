package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"
)

// CDI devices reach this plugin already expanded: containerd injects the
// edits of the devices a container requests (the CRI CDIDevices field and
// the cdi.k8s.io annotations) into the OCI spec before NRI sees it, so the
// device nodes, hooks and bind mounts they add arrive unattributed. The
// sandbox policy re-expands the requested devices from the node's own spec
// files and sets aside exactly those edits; anything else is still judged.
//
// The spec directories are written only by node-TCB code: the image's
// nvidia-cdi-generate.service and the NVIDIA device plugin. A spec that
// changed between containerd's read and this one makes the edits differ, and
// the container is then refused, not admitted.

// cdiSpecDirs are containerd's default CDI spec directories.
var cdiSpecDirs = []string{"/etc/cdi", "/var/run/cdi"}

// cdiTrustedKinds are the device kinds whose edits the sandbox policy sets
// aside: the NVIDIA device plugin's own spec and the node's nvidia-ctk spec.
var cdiTrustedKinds = []string{"k8s.device-plugin.nvidia.com/gpu", "nvidia.com/gpu"}

// cdiSpec is the part of a CDI spec file the sandbox policy reads.
type cdiSpec struct {
	Kind           string      `yaml:"kind"`
	Devices        []cdiDevice `yaml:"devices"`
	ContainerEdits cdiEdits    `yaml:"containerEdits"`
}

type cdiDevice struct {
	Name           string   `yaml:"name"`
	ContainerEdits cdiEdits `yaml:"containerEdits"`
}

type cdiEdits struct {
	DeviceNodes []struct {
		Path string `yaml:"path"`
	} `yaml:"deviceNodes"`
	Hooks []struct {
		HookName string   `yaml:"hookName"`
		Path     string   `yaml:"path"`
		Args     []string `yaml:"args"`
		Env      []string `yaml:"env"`
	} `yaml:"hooks"`
	Mounts []struct {
		HostPath      string   `yaml:"hostPath"`
		ContainerPath string   `yaml:"containerPath"`
		Options       []string `yaml:"options"`
	} `yaml:"mounts"`
}

// cdiHook is one expanded hook: its OCI stage and the process it runs.
type cdiHook struct {
	stage string
	path  string
	args  []string
	env   []string
}

// cdiMount is one expanded bind mount.
type cdiMount struct {
	source, destination string
	readOnly            bool
}

// cdiExpansion is what the trusted devices a container requested add to its
// spec. names lists those devices.
type cdiExpansion struct {
	names   []string
	devices []string
	hooks   []cdiHook
	mounts  []cdiMount
}

// requestedCDIDevices returns the qualified device names a container
// requested through the CRI field and the cdi.k8s.io annotations.
func requestedCDIDevices(ctr *api.Container) []string {
	var names []string
	for _, d := range ctr.GetCDIDevices() {
		names = append(names, d.GetName())
	}
	for key, value := range ctr.GetAnnotations() {
		if !strings.HasPrefix(key, cdiAnnotationPrefix) {
			continue
		}
		for _, name := range strings.Split(value, ",") {
			names = append(names, strings.TrimSpace(name))
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// expandCDI expands the trusted devices ctr requested from the spec files
// in dirs. Devices of another kind are left out, so their edits stay
// violations. A trusted device that no spec, or more than one spec, defines
// fails the expansion: the container is then judged without it.
func expandCDI(ctr *api.Container, dirs []string) (cdiExpansion, error) {
	var trusted []string
	for _, name := range requestedCDIDevices(ctr) {
		kind, _, ok := strings.Cut(name, "=")
		if ok && slices.Contains(cdiTrustedKinds, kind) {
			trusted = append(trusted, name)
		}
	}
	var exp cdiExpansion
	if len(trusted) == 0 {
		return exp, nil
	}
	specs, err := readCDISpecs(dirs)
	if err != nil {
		return exp, err
	}
	used := map[int]bool{}
	for _, name := range trusted {
		kind, device, _ := strings.Cut(name, "=")
		var found []cdiEdits
		for i, spec := range specs {
			if spec.Kind != kind {
				continue
			}
			for _, d := range spec.Devices {
				if d.Name == device {
					found = append(found, d.ContainerEdits)
					used[i] = true
				}
			}
		}
		if len(found) != 1 {
			return cdiExpansion{}, fmt.Errorf("CDI device %s is defined %d times in %v", name, len(found), dirs)
		}
		exp.add(found[0])
		exp.names = append(exp.names, name)
	}
	for i := range specs {
		if used[i] {
			exp.add(specs[i].ContainerEdits)
		}
	}
	return exp, nil
}

func (e *cdiExpansion) add(edits cdiEdits) {
	for _, d := range edits.DeviceNodes {
		e.devices = append(e.devices, d.Path)
	}
	for _, h := range edits.Hooks {
		e.hooks = append(e.hooks, cdiHook{stage: h.HookName, path: h.Path, args: h.Args, env: h.Env})
	}
	for _, m := range edits.Mounts {
		e.mounts = append(e.mounts, cdiMount{
			source:      m.HostPath,
			destination: m.ContainerPath,
			readOnly:    endsReadOnly(&api.Mount{Options: m.Options}),
		})
	}
}

// readCDISpecs parses every .json and .yaml file in dirs. A missing
// directory holds no specs; a file that does not parse fails the read.
func readCDISpecs(dirs []string) ([]cdiSpec, error) {
	var specs []cdiSpec
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			ext := filepath.Ext(entry.Name())
			if entry.IsDir() || (ext != ".json" && ext != ".yaml") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, err
			}
			var spec cdiSpec
			if err := yaml.Unmarshal(data, &spec); err != nil {
				return nil, fmt.Errorf("CDI spec %s: %w", filepath.Join(dir, entry.Name()), err)
			}
			specs = append(specs, spec)
		}
	}
	return specs, nil
}

// hook reports whether the expansion added a hook equal to h at stage.
func (e cdiExpansion) hook(stage string, h *api.Hook) bool {
	return slices.ContainsFunc(e.hooks, func(x cdiHook) bool {
		return x.stage == stage && x.path == h.GetPath() && slices.Equal(x.args, h.GetArgs()) && slices.Equal(x.env, h.GetEnv())
	})
}

// mount reports whether the expansion added m: same source and destination,
// and read-only when the spec makes it read-only.
func (e cdiExpansion) mount(m *api.Mount) bool {
	return slices.ContainsFunc(e.mounts, func(x cdiMount) bool {
		return x.source == m.GetSource() && x.destination == m.GetDestination() && (!x.readOnly || endsReadOnly(m))
	})
}
