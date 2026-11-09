package nriimagepolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestInventoryIgnoresUnidentifiedRecords(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.recordSandbox("")
	inv.recordObserved("", "pod", "app", pushDigestA, "", nil, nil, nil)
	inv.recordObserved("ctr", "", "app", pushDigestA, "", nil, nil, nil)
	inv.denyOnRecord("", "app", errors.New("refused"))
	inv.denyOnRecord("pod", "app", nil)
	inv.removeSandbox("")
	if len(inv.sandboxes) != 0 || len(inv.containers) != 0 || len(inv.denied) != 0 || inv.revision != 0 {
		t.Fatalf("unidentified records changed the inventory: %d sandboxes, %d containers, %d denials, revision %d",
			len(inv.sandboxes), len(inv.containers), len(inv.denied), inv.revision)
	}
}

func TestCreationDenialKeepsTheFirstReasonPerName(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.recordCreationDenial("pod", "app", errors.New("first refusal"))
	revision := inv.revision
	inv.recordCreationDenial("pod", "app", errors.New("second refusal"))
	if err := inv.denial("pod"); err == nil || err.Error() != "first refusal" || inv.revision != revision {
		t.Fatalf("denial %v at revision %d -> %d", err, revision, inv.revision)
	}
}

func TestValidateContainerAdjustmentRefusesIncompleteRequests(t *testing.T) {
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	if err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: sandboxedPod()}); err == nil ||
		!strings.Contains(err.Error(), "missing container or sandbox") {
		t.Fatalf("no container: %v", err)
	}
	p.cfg.Pod = &podConfig{}
	p.podStartDisconnected.Store(true)
	req := &api.ValidateContainerAdjustmentRequest{Pod: sandboxedPod(), Container: &api.Container{Id: "ctr"}}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err == nil || !strings.Contains(err.Error(), "connection ended") {
		t.Fatalf("disconnected Pod runtime: %v", err)
	}
}

func TestMeasureRefusesAnUnidentifiedDigest(t *testing.T) {
	m, err := openMeasurer(measureFixture(t, &fakeRegister{value: launchSeed}), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.MeasureOnce("busybox:latest"); err == nil {
		t.Fatal("a reference without a digest was measured")
	}
	if _, err := m.MeasureOnce(testDigest); err != nil {
		t.Fatal(err)
	}
	if got := m.Digests(); len(got) != 1 || got[0] != testDigest {
		t.Fatalf("measured digests %v", got)
	}
	p := &plugin{measurer: m, containerd: &fakeContainerd{resolve: func(context.Context, string) (string, error) { return "", nil }}}
	if err := p.measureStarted(t.Context(), "busybox:latest"); err == nil || !strings.Contains(err.Error(), "no digest") {
		t.Fatalf("empty resolution: %v", err)
	}
}

func TestPodStartRequiresTheContainerInTheLiveInventory(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	err := p.requirePodStart(t.Context(), podStartRequest(pod, ctr))
	if err == nil || !strings.Contains(err.Error(), "absent from the live admission inventory") {
		t.Fatalf("got %v", err)
	}
}

func TestFinishPodStartStopsAtAFailedCredentialStart(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	p.podBroker = nil
	if err := p.finishPodStart(t.Context(), pod, ctr, "/credentials"); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("got %v", err)
	}
	if len(p.podStarts) != 0 {
		t.Fatal("a failed credential start issued a start permission")
	}
}
