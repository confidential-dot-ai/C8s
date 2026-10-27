package nriimagepolicy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// launchCapture is a booted node's record of the Cilium containers
// (crictl inspect), which the Cilium entry in the measured base pins.
const launchCapture = "testdata/cilium-launch"

type capturedLaunch struct {
	Status struct {
		Labels   map[string]string `json:"labels"`
		ImageRef string            `json:"imageRef"`
	} `json:"status"`
	Info struct {
		SandboxID   string `json:"sandboxID"`
		RuntimeSpec struct {
			Process struct {
				Args []string `json:"args"`
				Env  []string `json:"env"`
			} `json:"process"`
			Mounts []*api.Mount `json:"mounts"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

// capturedContainers rebuilds what NRI handed the plugin for each recorded
// Cilium container: a host-network pod, and the container's own argv, env and
// mounts. Each is privileged in the strongest sense the policy can see.
func capturedContainers(t *testing.T) map[string]struct {
	pod *api.PodSandbox
	ctr *api.Container
	ref string
} {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(launchCapture, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no captured launches: %v", err)
	}
	out := map[string]struct {
		pod *api.PodSandbox
		ctr *api.Container
		ref string
	}{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c capturedLaunch
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		pod := &api.PodSandbox{
			Id: c.Info.SandboxID, Uid: c.Status.Labels["io.kubernetes.pod.uid"],
			Name: c.Status.Labels["io.kubernetes.pod.name"], Namespace: "kube-system",
			Linux: &api.LinuxPodSandbox{Namespaces: []*api.LinuxNamespace{{Type: "ipc"}, {Type: "pid"}}},
		}
		ctr := &api.Container{
			Id: c.Status.Labels["io.kubernetes.container.name"], Name: c.Status.Labels["io.kubernetes.container.name"],
			PodSandboxId: c.Info.SandboxID, Args: c.Info.RuntimeSpec.Process.Args, Env: c.Info.RuntimeSpec.Process.Env,
			Mounts: c.Info.RuntimeSpec.Mounts,
			Linux:  &api.LinuxContainer{Devices: []*api.LinuxDevice{{Path: "/dev/vda"}}},
		}
		out[ctr.Name] = struct {
			pod *api.PodSandbox
			ctr *api.Container
			ref string
		}{pod, ctr, c.Status.ImageRef}
	}
	return out
}

// The measured base's Cilium pins admit, under an enforcing sandbox, every
// Cilium container exactly as the node launched it, and nothing restaged from
// those images: another argv, another mount or an extra variable.
func TestPinnedSystemLaunchesAdmitExactlyTheRecordedCilium(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sandboxMode() != SandboxEnforce {
		t.Fatalf("the baked policy.sandbox is %q, want enforce", cfg.sandboxMode())
	}
	p := newTestPlugin(cfg)
	check := func(pod *api.PodSandbox, ctr *api.Container, ref string) (imageVerdict, string) {
		mounts := newMountObserver(fixedStorage(allowlist.MountEncrypted), nodeMounts{}).Observe(pod, ctr)
		return p.checkSandbox(context.Background(), cfg, pod, ctr, ref, containerEnv(ctr), mounts)
	}
	launches := capturedContainers(t)
	if len(launches) != 8 {
		t.Fatalf("captured %d Cilium containers, want 8", len(launches))
	}
	for name, l := range launches {
		t.Run(name, func(t *testing.T) {
			if verdict, reason := check(l.pod, l.ctr, l.ref); verdict != verdictAllow {
				t.Fatalf("the recorded launch is refused: %s", reason)
			}
			restaged := func(edit func(*api.Container)) *api.Container {
				c := &api.Container{
					Id: l.ctr.Id, Name: l.ctr.Name, PodSandboxId: l.ctr.PodSandboxId, Linux: l.ctr.Linux,
					Args:   append([]string{}, l.ctr.Args...),
					Env:    append([]string{}, l.ctr.Env...),
					Mounts: append([]*api.Mount{}, l.ctr.Mounts...),
				}
				edit(c)
				return c
			}
			for what, ctr := range map[string]*api.Container{
				"a shell": restaged(func(c *api.Container) { c.Args = []string{"/bin/sh", "-c", "id"} }),
				"the host root": restaged(func(c *api.Container) {
					c.Mounts = append(c.Mounts, &api.Mount{Destination: "/host", Type: "bind", Source: "/", Options: []string{"rbind", "rw"}})
				}),
				"a shell function": restaged(func(c *api.Container) { c.Env = append(c.Env, "BASH_ENV=/hostproc/1/root/tmp/x") }),
			} {
				if verdict, _ := check(l.pod, ctr, l.ref); verdict != verdictDeny {
					t.Errorf("restaged with %s: admitted", what)
				}
			}
		})
	}
}

// The kubelet's service links vary with the Services that existed when a
// container started, so the pins admit them by shape, and only them.
func TestPinnedSystemLaunchesAdmitServiceLinks(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPlugin(cfg)
	l := capturedContainers(t)["cilium-agent"]
	var env []string
	for _, e := range l.ctr.Env {
		if !strings.HasPrefix(e, "RKE2_COREDNS_") {
			env = append(env, e)
		}
	}
	env = append(env, "HUBBLE_PEER_SERVICE_HOST=10.53.0.20", "HUBBLE_PEER_SERVICE_PORT=443")
	ctr := &api.Container{Id: l.ctr.Id, Name: l.ctr.Name, PodSandboxId: l.ctr.PodSandboxId, Linux: l.ctr.Linux, Args: l.ctr.Args, Mounts: l.ctr.Mounts, Env: env}
	mounts := newMountObserver(fixedStorage(allowlist.MountEncrypted), nodeMounts{}).Observe(l.pod, ctr)
	if verdict, reason := p.checkSandbox(context.Background(), cfg, l.pod, ctr, l.ref, containerEnv(ctr), mounts); verdict != verdictAllow {
		t.Fatalf("other service links: %s", reason)
	}
}
