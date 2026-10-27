package nriimagepolicy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

// gpuAllowlist holds the GPU workload's entry: argv pinned when pinned,
// otherwise open; mounts and env open.
func gpuAllowlist(pinned bool) *allowlist.Allowlist {
	c := allowlist.Container{
		Digest:  mustDigestOrPanic(pushDigestA),
		Image:   "gpu",
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
	}
	if pinned {
		c.Command = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/server"}}
		c.Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}
	}
	return &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{
		"gpu": {Label: "gpu", Containers: []allowlist.Container{c}},
	}}
}

func gpuPlugin(t *testing.T, served *allowlist.Allowlist) (*plugin, *config) {
	t.Helper()
	cfg := &config{Policy: policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce}}
	p := newTestPlugin(cfg)
	p.policy.apply(served, 1)
	p.cdiSpecDirs = writeCDISpecs(t, map[string]string{"gpu.json": gpuSpec})
	return p, cfg
}

func servedGPUContainer() *api.Container {
	ctr := cdiGPUContainer()
	ctr.Args = []string{"/server"}
	ctr.Annotations[annotationImageName] = testFloorImage
	return ctr
}

// Under enforce, a GPU container a served entry pins is admitted with its
// injection and refused once it carries anything more.
func TestCheckSandboxAdmitsTrustedCDIInjection(t *testing.T) {
	p, cfg := gpuPlugin(t, gpuAllowlist(true))
	pod, ctr := sandboxedPod(), servedGPUContainer()
	if verdict, reason := p.checkSandbox(context.Background(), cfg, pod, ctr, testFloorImage, nil, nil); verdict != verdictAllow {
		t.Fatalf("checkSandbox(GPU container) = %d %q, want allow", verdict, reason)
	}
	ctr.Linux.Devices = append(ctr.Linux.Devices, &api.LinuxDevice{Path: "/dev/mem"})
	if verdict, _ := p.checkSandbox(context.Background(), cfg, pod, ctr, testFloorImage, nil, nil); verdict != verdictDeny {
		t.Fatalf("checkSandbox(GPU container + /dev/mem) = %d, want deny", verdict)
	}
}

// An entry that leaves the argv open never receives a GPU: an open floor
// image restaged with a CDI annotation keeps its device nodes and hooks.
func TestOpenEntryGetsNoCDIExpansion(t *testing.T) {
	p, cfg := gpuPlugin(t, gpuAllowlist(false))
	pod, ctr := sandboxedPod(), servedGPUContainer()
	verdict, reason := p.checkSandbox(context.Background(), cfg, pod, ctr, testFloorImage, nil, nil)
	if verdict != verdictDeny || !strings.Contains(reason, "host device node") {
		t.Fatalf("checkSandbox(open entry with GPU) = %d %q, want a device-node denial", verdict, reason)
	}
}

// Create-time hooks are judged at creation, before the runtime runs them.
func TestCreateHooksAreCheckedAtCreation(t *testing.T) {
	t.Run("trusted CDI hooks of a pinned launch", func(t *testing.T) {
		p, cfg := gpuPlugin(t, gpuAllowlist(true))
		if verdict, reason := p.checkCreateHooks(context.Background(), cfg, sandboxedPod(), servedGPUContainer(), testFloorImage); verdict != verdictAllow {
			t.Fatalf("checkCreateHooks = %d %q, want allow", verdict, reason)
		}
	})
	t.Run("an injected hook", func(t *testing.T) {
		p, cfg := gpuPlugin(t, gpuAllowlist(true))
		ctr := servedGPUContainer()
		ctr.Hooks.CreateRuntime = []*api.Hook{{Path: "/bin/sh", Args: []string{"sh", "-c", "id"}}}
		verdict, reason := p.checkCreateHooks(context.Background(), cfg, sandboxedPod(), ctr, testFloorImage)
		if verdict != verdictDeny || !strings.Contains(reason, "OCI hook") {
			t.Fatalf("checkCreateHooks = %d %q, want an OCI hook denial", verdict, reason)
		}
	})
	t.Run("CDI hooks of an open entry", func(t *testing.T) {
		p, cfg := gpuPlugin(t, gpuAllowlist(false))
		if verdict, _ := p.checkCreateHooks(context.Background(), cfg, sandboxedPod(), servedGPUContainer(), testFloorImage); verdict != verdictDeny {
			t.Fatalf("checkCreateHooks = %d, want deny", verdict)
		}
	})
	t.Run("through CreateContainer", func(t *testing.T) {
		p, _ := gpuPlugin(t, gpuAllowlist(true))
		p.SetReady()
		ctr := servedGPUContainer()
		ctr.Hooks.Prestart = []*api.Hook{{Path: "/usr/bin/evil"}}
		pod := sandboxedPod()
		if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil || !strings.Contains(err.Error(), "OCI hook") {
			t.Fatalf("CreateContainer(prestart hook) = %v, want an OCI hook refusal", err)
		}
	})
}
