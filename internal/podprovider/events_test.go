package podprovider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func TestStatusTransitionsRecordOneEventEach(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	recorder := events.NewFakeRecorder(10)
	r.recorder = recorder
	// The guest first reports Pending: verified status still counts while
	// its containers start.
	phase := corev1.PodPending
	r.guest = func(_ context.Context, rec *record, _ string) (podstatus.PodProjection, error) {
		projection := fixtureProjection(rec)
		projection.Status.Phase = phase
		return projection, nil
	}
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in = instanceFor(req)
		cloud.in.Status = "provisioning"
		return cloud.in, nil
	}
	steps := []struct {
		change func()
		want   string
	}{
		{func() {}, "Normal InstanceStarting The Pod CVM instance is starting"},
		{func() {}, ""},
		{func() { cloud.in.Status = "running" }, "Normal PodCVMVerified The Pod CVM reports verified status"},
		{func() { phase = corev1.PodRunning }, ""},
		{func() { cloud.in.Boot.Count = 2 }, "Warning GuestRebooted The Pod CVM rebooted"},
		{func() { cloud.in.Status = "terminated" }, ""},
	}
	for i, step := range steps {
		step.change()
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		status := getPod(t, r, pod).Status
		if status.Message != statusMessages[status.Reason] {
			t.Fatalf("step %d: reason %q has message %q", i, status.Reason, status.Message)
		}
		select {
		case got := <-recorder.Events:
			if got != step.want {
				t.Fatalf("step %d: event %q, want %q", i, got, step.want)
			}
		default:
			if step.want != "" {
				t.Fatalf("step %d: no event, want %q", i, step.want)
			}
		}
	}
}
