package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// meshStartPlugin is a node with the exits allowlist served, a real inventory
// and one mesh-hosted sandbox whose ruleset writes are recorded.
func meshStartPlugin(t *testing.T, ready bool) (*plugin, *api.PodSandbox, *int) {
	t.Helper()
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, exitsAllowlist(t, ""))
	if ready {
		p.SetReady()
	}
	p.inventory = newAdmissionInventory(t.TempDir())
	pod := meshPod("default", "pod", testNetNS)
	p.inventory.recordSandbox(pod.GetId())
	p.mesh.pods[pod.GetId()] = &protectedPod{netns: testNamespace(), kubeNamespace: "default"}
	extensions := 0
	p.mesh.extend = func(podNamespace, meshPolicy, string, []exit) error { extensions++; return nil }
	p.mesh.nodeAddress = func() (netip.Addr, error) { return netip.MustParseAddr("10.0.2.15"), nil }
	return p, pod, &extensions
}

// A start before the first pull settles decides exits as a ready one does: the
// collector's entry grants its exit, and a container the decision refuses does
// not run.
func TestStartContainerBindsExitsWhileInitializing(t *testing.T) {
	p, pod, extensions := meshStartPlugin(t, false)
	if p.Ready() {
		t.Fatal("the fixture is ready, so this start does not take the initializing path")
	}
	collector := makeCtrWithImageArgs(pod.GetId(), "collector", "registry/repo@"+collectorDigest, []string{"/run"})
	if err := p.StartContainer(context.Background(), pod, collector); err != nil {
		t.Fatal(err)
	}
	if got := p.mesh.grantedExits(pod.GetId()); !slices.Equal(got, relayExit) || *extensions != 1 {
		t.Fatalf("granted exits = %v after %d extensions, want %v once", got, *extensions, relayExit)
	}
	foreign := makeCtrWithImageArgs(pod.GetId(), "app", "registry/repo@"+appDigest, []string{"/run"})
	err := p.StartContainer(context.Background(), pod, foreign)
	if err == nil || !strings.Contains(err.Error(), "mesh gate: container") {
		t.Fatalf("err = %v, want a mesh gate refusal of the foreign container", err)
	}
}

// A Pod CVM records every refusal, including one the plugin issues while
// initializing: the sandbox asserts no identity afterwards.
func TestPodStartRecordsAPolicyRefusalWhileInitializing(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, false)
	p.policy = newPolicyStore(nil)
	err := p.StartContainer(t.Context(), pod, ctr)
	if err == nil || !strings.Contains(err.Error(), "initializing") {
		t.Fatalf("err = %v, want a refusal naming the initializing plugin", err)
	}
	if p.inventory.denial(pod.Id) == nil {
		t.Fatal("the Pod's sandbox kept its identity after a refused start")
	}
}

// A node does not hold a failed measurement against the sandbox: the start is
// refused and the sandbox keeps its identity, on both paths.
func TestNodeMeasureFailureRefusesTheStartWithoutRecordingIt(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprintf("ready=%v", ready), func(t *testing.T) {
			reg := &fakeRegister{value: launchSeed}
			measurer, err := openMeasurer(measureFixture(t, reg), discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{
				Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "app"})},
				Policy:    policyConfig{Mode: ModeFailClosed},
			}, anyAllowlist(map[string]string{pushDigestA: "app"}))
			if ready {
				p.SetReady()
			}
			p.measurer = measurer
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			p.inventory.recordSandbox(pod.Id)
			reg.fail = errors.New("tsm write failed")
			ctr := makeCtrWithImageArgs(pod.Id, "app", "registry/repo@"+pushDigestA, []string{"/app"})
			if err := p.StartContainer(context.Background(), pod, ctr); err == nil {
				t.Fatal("a failed measurement admitted the container")
			}
			if denial := p.inventory.denial(pod.Id); denial != nil {
				t.Fatalf("a node recorded a transient measurement failure: %v", denial)
			}
		})
	}
}
