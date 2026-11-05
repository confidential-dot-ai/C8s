package podprovider

import (
	"strings"
	"testing"

	"k8s.io/client-go/tools/events"
)

func TestStatusTransitionsEmitOneEventEach(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	recorder := events.NewFakeRecorder(10)
	r.recorder = recorder
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in = instanceFor(req)
		cloud.in.Status = "provisioning"
		return cloud.in, nil
	}
	steps := []struct {
		change func()
		want   string
	}{
		{func() {}, "Normal InstanceStarting"},
		{func() {}, ""},
		{func() { cloud.in.Status = "running" }, "Normal PodCVMVerified"},
		{func() {}, ""},
		{func() { cloud.in.Boot.Count = 2 }, "Warning GuestRebooted"},
		{func() { cloud.in.Status = "terminated" }, ""},
	}
	for i, step := range steps {
		step.change()
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-recorder.Events:
			if step.want == "" || !strings.HasPrefix(got, step.want) {
				t.Fatalf("step %d: event %q, want %q", i, got, step.want)
			}
		default:
			if step.want != "" {
				t.Fatalf("step %d: no event, want %q", i, step.want)
			}
		}
	}
}
