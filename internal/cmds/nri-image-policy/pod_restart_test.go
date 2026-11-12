package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// A plugin restart within one boot ends the Pod identity: the containers the
// runtime still runs are stopped, so the kubelet reports them terminated, and
// no later start of the Pod is admitted.
func TestPodPluginRestartStopsTheRunningContainers(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	pod := makePod("tenant", "assigned")
	pod.Uid = "runtime-uid"
	newPodPlugin := func(stop func(ctx context.Context, containerID string) error) *plugin {
		cfg := measureFixture(t, &fakeRegister{value: launchSeed})
		cfg.Pod = &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"init": pushDigestA}}
		cfg.Allowlist = allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "app"})}
		cfg.Policy = policyConfig{Mode: ModeFailClosed, FatalExisting: true, BootMarkerPath: marker}
		measurer, err := openMeasurer(cfg, discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		p := newTestPlugin(cfg)
		p.measurer = measurer
		p.boot = newBootGate(cfg, slog.Default())
		p.boot.powerOff = func() error { t.Fatal("a plugin restart powered the guest off"); return nil }
		p.boot.exit = func(int) { t.Fatal("a plugin restart exited the plugin") }
		p.containerd = &fakeContainerd{stop: stop, verify: func(ctx context.Context, _, _, _ string) error { return ctx.Err() }}
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		p.podBroker = &podCredentialBroker{ctx: ctx, cancel: cancel}
		return p
	}

	first := newPodPlugin(nil)
	if _, err := first.Synchronize(t.Context(), nil, nil); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if first.podBroker.terminal != nil {
		t.Fatalf("the first registration ended the identity: %v", first.podBroker.terminal)
	}

	var stopped []string
	restarted := newPodPlugin(func(ctx context.Context, containerID string) error {
		stopped = append(stopped, containerID)
		if containerID == "app-id" {
			return errors.New("task already exited")
		}
		return nil
	})
	running := makeCtrWithImage(pod.Id, "mesh", "image@"+pushDigestA)
	running.State = api.ContainerState_CONTAINER_RUNNING
	exited := makeCtrWithImage(pod.Id, "app", "image@"+pushDigestA)
	exited.State = api.ContainerState_CONTAINER_RUNNING
	created := makeCtrWithImage(pod.Id, "init", "image@"+pushDigestA)
	created.State = api.ContainerState_CONTAINER_CREATED
	if _, err := restarted.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{running, exited, created}); err != nil {
		t.Fatalf("restart registration: %v", err)
	}
	if len(stopped) != 2 || stopped[0] != "mesh-id" || stopped[1] != "app-id" {
		t.Fatalf("stopped %v, want the two running containers in runtime order", stopped)
	}
	if restarted.podBroker.terminal == nil || restarted.podBroker.ctx.Err() == nil {
		t.Fatal("the restart left the Pod identity live")
	}
	err := restarted.StartContainer(t.Context(), pod, created)
	if err == nil || !strings.Contains(err.Error(), "plugin restart") {
		t.Fatalf("a container created before the restart started under the ended identity: %v", err)
	}
}

// A Pod guest's first registration finds no runtime, so one that does is refused.
func TestFreshPodRegistrationRefusesAnExistingRuntime(t *testing.T) {
	pod := makePod("tenant", "assigned")
	pod.Uid = "runtime-uid"
	ctr := makeCtrWithImage(pod.Id, "app", "image@"+pushDigestA)
	ctr.State = api.ContainerState_CONTAINER_RUNNING

	guest := podCVMPlugin(t, pod)
	if _, err := guest.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err == nil ||
		!strings.Contains(err.Error(), "fresh Pod registration found an existing runtime") {
		t.Fatalf("a fresh Pod registration accepted an existing runtime: %v", err)
	}
	if guest.podRegistered.Load() {
		t.Fatal("a refused registration registered the Pod")
	}

	clean := podCVMPlugin(t, pod)
	if _, err := clean.Synchronize(t.Context(), nil, nil); err != nil {
		t.Fatalf("an empty first registration: %v", err)
	}
	if !clean.podRegistered.Load() {
		t.Fatal("the assigned first registration did not register the Pod")
	}

	node := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	node.inventory = newAdmissionInventory(t.TempDir())
	if _, err := node.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
		t.Fatalf("a node refused the containers it was given: %v", err)
	}
	if node.podRegistered.Load() {
		t.Fatal("a node registered a Pod")
	}
}
