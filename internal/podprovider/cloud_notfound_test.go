package podprovider

import (
	"net/http"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// A deletion keeps the record of an instance Cloud did not itself report
// absent: a 404 without Cloud's code on the read, or any 404 on the lookup
// by idempotency key, which Cloud answers with a list.
func TestDeletionKeepsTheRecordOnA404ThatIsNotCloudsAnswer(t *testing.T) {
	t.Run("read without a code", func(t *testing.T) {
		pod := fixturePod()
		r, cloud := fixtureReconciler(t, pod)
		runToRunning(t, r, pod)
		if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
			t.Fatal(err)
		}
		cloud.get = func(string) (*instance, error) { return nil, &cloudProblem{status: http.StatusNotFound} }
		err := reconcile(t, r, pod)
		if rec := getRecord(t, r, pod); err == nil || rec.Deleted || !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) {
			t.Fatalf("reconcile error %v, record deleted %t", err, rec.Deleted)
		}
	})
	t.Run("lookup", func(t *testing.T) {
		r, cloud, pod, _ := deleteUnresolvedCreate(t, &cloudProblem{status: http.StatusConflict, code: "idempotency_in_flight"})
		cloud.find = func(string) (*instance, error) {
			return nil, &cloudProblem{status: http.StatusNotFound, code: "not_found"}
		}
		replays := cloud.createCalls
		err := reconcile(t, r, pod)
		if rec := getRecord(t, r, pod); err == nil || rec.Deleted || cloud.createCalls != replays {
			t.Fatalf("reconcile error %v, record deleted %t, replays %d", err, rec.Deleted, cloud.createCalls-replays)
		}
	})
}
