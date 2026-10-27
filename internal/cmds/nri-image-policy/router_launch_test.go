package nriimagepolicy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// routerLaunch is a booted baked node's record of the router pod under an
// enforcing sandbox: the node's boot config with the chart seed merged, the
// pod sandbox and the containers that started, as crictl reported them.
const routerLaunch = "testdata/router-launch"

type recordedSandbox struct {
	Status struct {
		ID          string            `json:"id"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"status"`
	Info struct {
		RuntimeSpec struct {
			Linux struct {
				Namespaces []*api.LinuxNamespace `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

type recordedLaunch struct {
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
				User struct {
					UID uint32 `json:"uid"`
					GID uint32 `json:"gid"`
				} `json:"user"`
			} `json:"process"`
			Mounts []*api.Mount `json:"mounts"`
			Linux  struct {
				Namespaces []*api.LinuxNamespace `json:"namespaces"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

func readRecorded(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// The router's credential containers carry the binds the plugin adds to the
// credentials identity. c8s-cert-wait's seed entry names none of them, so an
// enforcing node refused it until the inventory socket bind counted as the
// plugin's own, like the CDS pins and address.
func TestRecordedRouterLaunchesPassAnEnforcingSandbox(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(routerLaunch, "image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sandboxMode() != SandboxEnforce {
		t.Fatalf("the recorded node runs sandbox %q, want enforce", cfg.sandboxMode())
	}
	p := newTestPlugin(cfg)
	p.cdsPins = filepath.Join(enforcerRuntimeDir, "cds-pins.json")
	p.cdsAddress = filepath.Join(enforcerRuntimeDir, "cds-address")

	var sb recordedSandbox
	readRecorded(t, filepath.Join(routerLaunch, "sandbox.json"), &sb)
	pod := &api.PodSandbox{
		Id: sb.Status.ID, Uid: sb.Status.Labels["io.kubernetes.pod.uid"],
		Name: sb.Status.Labels["io.kubernetes.pod.name"], Namespace: sb.Status.Labels["io.kubernetes.pod.namespace"],
		Annotations: sb.Status.Annotations,
		Linux:       &api.LinuxPodSandbox{Namespaces: sb.Info.RuntimeSpec.Linux.Namespaces},
	}
	files, err := filepath.Glob(filepath.Join(routerLaunch, "containers", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no recorded router containers: %v", err)
	}
	for _, f := range files {
		var c recordedLaunch
		readRecorded(t, f, &c)
		name := c.Status.Labels["io.kubernetes.container.name"]
		t.Run(name, func(t *testing.T) {
			ctr := &api.Container{
				Id: name, Name: name, PodSandboxId: c.Info.SandboxID,
				User:   &api.User{Uid: c.Info.RuntimeSpec.Process.User.UID, Gid: c.Info.RuntimeSpec.Process.User.GID},
				Args:   c.Info.RuntimeSpec.Process.Args,
				Env:    c.Info.RuntimeSpec.Process.Env,
				Mounts: c.Info.RuntimeSpec.Mounts,
				Linux:  &api.LinuxContainer{Namespaces: c.Info.RuntimeSpec.Linux.Namespaces},
			}
			own := nodeMounts{socketDir: cfg.WorkloadClaims.SocketDir, cdsPins: p.cdsPins, cdsAddress: p.cdsAddress}
			mounts := newMountObserver(fixedStorage(allowlist.MountMemory), own).Observe(pod, ctr)
			ctx := context.Background()
			if verdict, reason := p.checkContainerObserved(ctx, cfg, pod, ctr, c.Status.ImageRef, launchFinal, containerEnv(ctr), mounts); verdict == verdictDeny {
				t.Fatalf("allowlist refuses the recorded launch: %s", reason)
			}
			if verdict, reason := p.checkSandbox(ctx, cfg, pod, ctr, c.Status.ImageRef, containerEnv(ctr), mounts); verdict != verdictAllow {
				t.Fatalf("an enforcing sandbox refuses the recorded launch: %s", reason)
			}
		})
	}
}

// The socket bind counts as the plugin's own only for the credentials
// identity, read-only, from the node's own socket directory.
func TestCredentialSocketBindIsTheCredentialsIdentitysOnly(t *testing.T) {
	own := nodeMounts{socketDir: "/run/nri-image-policy"}
	bind := func(src string, opts ...string) *api.Mount {
		return &api.Mount{Destination: "/run/c8s/workload-claims", Type: "bind", Source: src, Options: opts}
	}
	credentials := &api.Container{User: &api.User{Uid: 1338}}
	for _, tc := range []struct {
		name string
		ctr  *api.Container
		m    *api.Mount
		want bool
	}{
		{"the plugin's bind", credentials, bind("/run/nri-image-policy", "rbind", "ro"), true},
		{"writable", credentials, bind("/run/nri-image-policy", "rbind", "rw"), false},
		{"another source", credentials, bind("/run", "rbind", "ro"), false},
		{"another identity", &api.Container{User: &api.User{Uid: 0}}, bind("/run/nri-image-policy", "rbind", "ro"), false},
	} {
		if got := credentialSocketBind(tc.ctr, tc.m, own); got != tc.want {
			t.Errorf("%s: credentialSocketBind = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The same binds reach the credential sidecars of every pod the webhook
// adopts: an adopted pod's probe-file gate holds no host privilege of its own.
func TestAdoptedCredentialGateHoldsNoHostPrivilege(t *testing.T) {
	own := nodeMounts{
		socketDir:  "/run/nri-image-policy",
		cdsPins:    "/run/c8s-enforcer/cds-pins.json",
		cdsAddress: "/run/c8s-enforcer/cds-address",
	}
	pod := sandboxedPod()
	injectedPod(pod)
	ctr := sandboxedContainer()
	ctr.Name = "c8s-cert-wait"
	ctr.PodSandboxId = pod.Id
	ctr.User = &api.User{Uid: 1338, Gid: 1338}
	ctr.Mounts = append(ctr.Mounts,
		readOnlyBind(own.cdsAddress, "/run/c8s/cds-address"),
		readOnlyBind(own.cdsPins, "/run/c8s/cds-pins.json"),
		readOnlyBind(own.socketDir, "/run/c8s/workload-claims"),
	)
	if got := observeSandbox(pod, ctr, own, nil, nil, cdiExpansion{}).violations(); len(got) != 0 {
		t.Fatalf("violations = %v, want none", got)
	}
}
