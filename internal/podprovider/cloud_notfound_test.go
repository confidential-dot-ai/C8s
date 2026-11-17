package podprovider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// bareCloud404 answers every instance read as the client reports a 404 that
// carries no Cloud problem code.
func bareCloud404(cloud *fakeCloud) {
	cloud.get = func(string) (*instance, error) { return nil, &cloudProblem{status: http.StatusNotFound} }
}

func TestRunningPodKeepsItsInstanceWhenCloudAnswersABare404(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	bareCloud404(cloud)
	err := reconcile(t, r, pod)
	if live := getPod(t, r, pod); err == nil || live.Status.Phase == corev1.PodFailed || live.Status.Reason == "InstanceGone" {
		t.Fatalf("reconcile error %v, phase %s, reason %q", err, live.Status.Phase, live.Status.Reason)
	}
}

func TestDeletionKeepsTheRecordWhenCloudAnswersABare404(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	bareCloud404(cloud)
	err := reconcile(t, r, pod)
	if rec := getRecord(t, r, pod); err == nil || rec.Deleted || !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) {
		t.Fatalf("reconcile error %v, record deleted %t", err, rec.Deleted)
	}
}

func TestCloudDeleteReportsABare404(t *testing.T) {
	for body, wantErr := range map[string]bool{`{"code":"not_found"}`: false, ``: true, `<html>404</html>`: true} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(body))
		}))
		c := newCloudClient(fixtureConfig(t))
		c.base = srv.URL
		c.http.Transport = srv.Client().Transport
		err := c.Delete(t.Context(), "inst_1")
		srv.Close()
		if (err != nil) != wantErr || errors.Is(err, errCloudNotFound) {
			t.Errorf("body %q: delete error %v", body, err)
		}
	}
}
