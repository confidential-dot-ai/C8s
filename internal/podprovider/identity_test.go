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

// An answer that names no instance, such as an empty body from something in
// front of the cloud API, shows nothing about the recorded instance: the pod
// keeps its phase and the read is retried as unavailable. Another identity
// under the recorded one ends the pod.
func TestAnswerNamingNoInstanceIsRetriedAndAnotherIdentityEndsThePod(t *testing.T) {
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
	cloud.get = func(string) (*instance, error) { return &instance{}, nil }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if status := getPod(t, r, pod).Status; status.Phase == corev1.PodFailed || status.Reason != "CloudUnavailable" {
		t.Fatalf("pod is %s with reason %q, want it held with CloudUnavailable", status.Phase, status.Reason)
	}
	cloud.get = func(string) (*instance, error) {
		other := *cloud.in
		other.ID = "i-another"
		return &other, nil
	}
	if err := reconcile(t, r, pod); err == nil {
		t.Fatal("an instance under another identity was destroyed or released")
	}
	if status := getPod(t, r, pod).Status; status.Phase != corev1.PodFailed || status.Reason != "InstanceIdentityMismatch" || cloud.deleteCalls != 0 {
		t.Fatalf("pod is %s with reason %q after %d deletes, want Failed with InstanceIdentityMismatch and none", status.Phase, status.Reason, cloud.deleteCalls)
	}
}
