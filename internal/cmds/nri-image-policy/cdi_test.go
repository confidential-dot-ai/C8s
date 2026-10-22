package nriimagepolicy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// gpuSpec is the shape of the spec the NVIDIA device plugin writes to
// /var/run/cdi: per-device nodes and a by-path hook, and common device
// nodes, hooks and read-only driver mounts.
const gpuSpec = `{
  "cdiVersion": "0.5.0",
  "kind": "k8s.device-plugin.nvidia.com/gpu",
  "devices": [
    {"name": "GPU-1", "containerEdits": {
      "deviceNodes": [{"path": "/dev/nvidia0"}],
      "hooks": [{"hookName": "createContainer", "path": "/usr/bin/nvidia-cdi-hook",
        "args": ["nvidia-cdi-hook", "create-symlinks", "--link", "../card1::/dev/dri/by-path/pci-0000:01:00.0-card"]}]}},
    {"name": "GPU-2", "containerEdits": {"deviceNodes": [{"path": "/dev/nvidia1"}]}}
  ],
  "containerEdits": {
    "env": ["NVIDIA_VISIBLE_DEVICES=void"],
    "deviceNodes": [{"path": "/dev/nvidiactl"}, {"path": "/dev/nvidia-uvm"}],
    "hooks": [
      {"hookName": "createContainer", "path": "/usr/bin/nvidia-cdi-hook",
        "args": ["nvidia-cdi-hook", "update-ldcache", "--folder", "/usr/lib/x86_64-linux-gnu"],
        "env": ["NVIDIA_CTK_DEBUG=false"]}
    ],
    "mounts": [
      {"hostPath": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05",
        "containerPath": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05",
        "options": ["ro", "nosuid", "nodev", "rbind", "rprivate"]}
    ]
  }
}`

// otherSpec defines a device of a kind the sandbox policy does not trust.
const otherSpec = `kind: example.com/dev
devices:
  - name: x
    containerEdits:
      deviceNodes: [{path: /dev/mem}]
`

func writeCDISpecs(t *testing.T, specs map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range specs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return []string{dir, filepath.Join(dir, "missing")}
}

// gpuContainer is an ordinary container that requested GPU-1 through the
// device plugin's annotation and carries what containerd injected for it.
func cdiGPUContainer() *api.Container {
	ctr := sandboxedContainer()
	ctr.Annotations = map[string]string{"cdi.k8s.io/nvidia-device-plugin_abc": "k8s.device-plugin.nvidia.com/gpu=GPU-1"}
	ctr.Linux.Devices = []*api.LinuxDevice{{Path: "/dev/nvidia0"}, {Path: "/dev/nvidiactl"}, {Path: "/dev/nvidia-uvm"}}
	ctr.Hooks = &api.Hooks{CreateContainer: []*api.Hook{
		{Path: "/usr/bin/nvidia-cdi-hook", Args: []string{"nvidia-cdi-hook", "create-symlinks", "--link", "../card1::/dev/dri/by-path/pci-0000:01:00.0-card"}},
		{Path: "/usr/bin/nvidia-cdi-hook", Args: []string{"nvidia-cdi-hook", "update-ldcache", "--folder", "/usr/lib/x86_64-linux-gnu"}, Env: []string{"NVIDIA_CTK_DEBUG=false"}},
	}}
	ctr.Mounts = append(ctr.Mounts, &api.Mount{
		Destination: "/usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05", Type: "bind",
		Source:  "/usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05",
		Options: []string{"ro", "nosuid", "nodev", "rbind", "rprivate"},
	})
	return ctr
}

func cdiViolations(t *testing.T, ctr *api.Container, dirs []string) []string {
	t.Helper()
	cdi, _ := expandCDI(ctr, dirs)
	return observeSandbox(sandboxedPod(), ctr, nodeMounts{}, nil, nil, cdi).violations()
}

func TestCDIExpansionSetsAsideExactlyTheRequestedDevices(t *testing.T) {
	dirs := writeCDISpecs(t, map[string]string{"k8s.device-plugin.nvidia.com-gpu.json": gpuSpec, "other.yaml": otherSpec})
	tests := []struct {
		name string
		edit func(*api.Container)
		want string // a violation the result must hold; empty wants none
	}{
		{name: "the device plugin's injection"},
		{
			name: "the CRI field instead of the annotation",
			edit: func(c *api.Container) {
				c.Annotations = nil
				c.CDIDevices = []*api.CDIDevice{{Name: "k8s.device-plugin.nvidia.com/gpu=GPU-1"}}
			},
		},
		{
			name: "a device node of another GPU",
			edit: func(c *api.Container) {
				c.Linux.Devices = append(c.Linux.Devices, &api.LinuxDevice{Path: "/dev/nvidia1"})
			},
			want: "host device node",
		},
		{
			name: "an explicit device node",
			edit: func(c *api.Container) { c.Linux.Devices = append(c.Linux.Devices, &api.LinuxDevice{Path: "/dev/mem"}) },
			want: "host device node",
		},
		{
			name: "a spec hook with other arguments",
			edit: func(c *api.Container) {
				c.Hooks.CreateContainer[1].Args = []string{"nvidia-cdi-hook", "update-ldcache", "--folder", "/"}
			},
			want: "OCI hook",
		},
		{
			name: "a spec hook with other env",
			edit: func(c *api.Container) { c.Hooks.CreateContainer[1].Env = []string{"LD_PRELOAD=/x.so"} },
			want: "OCI hook",
		},
		{
			name: "a spec hook at another stage",
			edit: func(c *api.Container) {
				c.Hooks.Prestart = c.Hooks.CreateContainer[1:]
			},
			want: "OCI hook",
		},
		{
			name: "another hook",
			edit: func(c *api.Container) {
				c.Hooks.CreateContainer = append(c.Hooks.CreateContainer, &api.Hook{Path: "/bin/sh", Args: []string{"sh", "-c", "id"}})
			},
			want: "OCI hook",
		},
		{
			name: "a spec mount made writable",
			edit: func(c *api.Container) { c.Mounts[len(c.Mounts)-1].Options = []string{"rbind", "rw"} },
			want: "host path bind mount",
		},
		{
			name: "a spec mount at another destination",
			edit: func(c *api.Container) { c.Mounts[len(c.Mounts)-1].Destination = "/etc/ld.so.preload" },
			want: "host path bind mount",
		},
		{
			name: "the same edits without a request",
			edit: func(c *api.Container) { c.Annotations = nil },
			want: "OCI hook",
		},
		{
			name: "a device the spec does not define",
			edit: func(c *api.Container) {
				c.Annotations["cdi.k8s.io/nvidia-device-plugin_abc"] = "k8s.device-plugin.nvidia.com/gpu=GPU-9"
			},
			want: "host device node",
		},
		{
			name: "an untrusted kind",
			edit: func(c *api.Container) {
				c.Annotations["cdi.k8s.io/other"] = "example.com/dev=x"
				c.Linux.Devices = append(c.Linux.Devices, &api.LinuxDevice{Path: "/dev/mem"})
			},
			want: "host device node",
		},
		{
			name: "an untrusted kind in the CRI field",
			edit: func(c *api.Container) { c.CDIDevices = []*api.CDIDevice{{Name: "example.com/dev=x"}} },
			want: "CDI device injection",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctr := cdiGPUContainer()
			if tt.edit != nil {
				tt.edit(ctr)
			}
			got := cdiViolations(t, ctr, dirs)
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("violations = %v, want none", got)
				}
				return
			}
			if !slices.Contains(got, tt.want) {
				t.Fatalf("violations = %v, want %q", got, tt.want)
			}
		})
	}
}

// A device two specs define, or a spec that does not parse, expands nothing.
func TestCDIExpansionFailsClosed(t *testing.T) {
	for name, specs := range map[string]map[string]string{
		"defined twice":   {"a.json": gpuSpec, "b.json": gpuSpec},
		"unparsable spec": {"a.json": gpuSpec, "b.yaml": "kind: [unterminated"},
		"no spec at all":  {},
	} {
		t.Run(name, func(t *testing.T) {
			dirs := writeCDISpecs(t, specs)
			if _, err := expandCDI(cdiGPUContainer(), dirs); err == nil {
				t.Fatal("expandCDI succeeded")
			}
			if got := cdiViolations(t, cdiGPUContainer(), dirs); !slices.Contains(got, "OCI hook") {
				t.Fatalf("violations = %v, want the hooks counted", got)
			}
		})
	}
}

// Under enforce, the GPU container is admitted with its injection and
// refused once it carries anything more.
func TestCheckSandboxAdmitsTrustedCDIInjection(t *testing.T) {
	dirs := writeCDISpecs(t, map[string]string{"gpu.json": gpuSpec})
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce}}
	p := newTestPlugin(cfg)
	p.cdiSpecDirs = dirs
	pod := sandboxedPod()

	ctr := cdiGPUContainer()
	if verdict, reason := p.checkSandbox(context.Background(), cfg, pod, ctr, "registry/repo:tag", nil, nil); verdict != verdictAllow {
		t.Fatalf("checkSandbox(GPU container) = %d %q, want allow", verdict, reason)
	}
	ctr.Linux.Devices = append(ctr.Linux.Devices, &api.LinuxDevice{Path: "/dev/mem"})
	if verdict, _ := p.checkSandbox(context.Background(), cfg, pod, ctr, "registry/repo:tag", nil, nil); verdict != verdictDeny {
		t.Fatalf("checkSandbox(GPU container + /dev/mem) = %d, want deny", verdict)
	}
}
