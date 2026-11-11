package podprovider

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// An instance the cloud returns under another provider's label is not the
// one the record created: the pod ends with InstanceIdentityMismatch at
// once, not with the verification timeout later.
func TestForeignInstanceLabelsEndThePodAsIdentityMismatch(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in = instanceFor(req)
		cloud.in.Status = "running"
		return cloud.in, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	cloud.in.Labels = map[string]string{"podcvm-provider": "another-provider"}
	// Teardown refuses to destroy an instance that is not the record's, so
	// the pod stays held and the pass reports that; the decision stands.
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("a foreign instance was destroyed or released")
	}
	status := getPod(t, r, pod).Status
	if status.Phase != corev1.PodFailed || status.Reason != "InstanceIdentityMismatch" {
		t.Fatalf("pod is %s with reason %q, want Failed with InstanceIdentityMismatch", status.Phase, status.Reason)
	}
	if cloud.deleteCalls != 0 {
		t.Fatalf("%d delete calls for an instance the record does not own", cloud.deleteCalls)
	}
}

// Before the record holds an instance identity, a foreign result of the
// create is retried as unavailable, not treated as a mismatch.
func TestForeignCreateResultBeforeIdentityIsRecordedIsUnavailable(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		in := instanceFor(req)
		in.Labels["podcvm-provider"] = "another-provider"
		return in, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	status := getPod(t, r, pod).Status
	if status.Phase != corev1.PodPending || status.Reason != "CloudUnavailable" {
		t.Fatalf("pod is %s with reason %q, want Pending with CloudUnavailable", status.Phase, status.Reason)
	}
}
