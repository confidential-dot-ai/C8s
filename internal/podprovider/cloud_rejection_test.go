package podprovider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// refusingCloud is an HTTP Cloud that holds no instance and answers every
// create with status and body.
func refusingCloud(t *testing.T, r *Reconciler, status int, body string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c := newCloudClient(r.cfg)
	c.base = srv.URL
	c.http.Transport = srv.Client().Transport
	r.cloud = c
}

// reconcileLogged reconciles with a logger that collects every line.
func reconcileLogged(t *testing.T, r *Reconciler, pod *corev1.Pod) (string, error) {
	t.Helper()
	var lines strings.Builder
	logger := funcr.New(func(prefix, args string) { lines.WriteString(prefix + " " + args + "\n") }, funcr.Options{})
	ctx := logr.NewContext(context.Background(), logger)
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	return lines.String(), err
}

// A create Cloud refuses as invalid is a definitive end with its own fixed
// reason, never CloudUnavailable; Cloud's code reaches the log and the body
// reaches neither.
func TestCloudRejectedCreateEndsThePod(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	refusingCloud(t, r, http.StatusBadRequest, `{"code":"invalid_request","detail":"trust.initData: secret launch input"}`)
	logs, _ := reconcileLogged(t, r, pod)
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodFailed || got.Status.Reason != "CloudRejectedRequest" || got.Status.Message != "Cloud rejected the provider's request" {
		t.Fatalf("400 published as %s %s %q", got.Status.Phase, got.Status.Reason, got.Status.Message)
	}
	if !strings.Contains(logs, "cloud rejected the Pod CVM request") || !strings.Contains(logs, "HTTP 400 (invalid_request)") {
		t.Fatalf("provider log lacks Cloud's code:\n%s", logs)
	}
	if strings.Contains(logs, "secret launch input") {
		t.Fatalf("provider log carries the Cloud body:\n%s", logs)
	}
	if rec := getRecord(t, r, pod); rec.TerminalStatus == nil || !rec.Deleted {
		t.Fatalf("definitive refusal left the record unresolved: terminal %t, deleted %t", rec.TerminalStatus != nil, rec.Deleted)
	}
}

// A refusal that proves nothing about the create, such as a rejected
// credential, keeps the pod pending under the same reason and its deadline.
func TestCloudRejectedCredentialIsNotAnOutage(t *testing.T) {
	pod := fixturePod()
	r, _ := fixtureReconciler(t, pod)
	refusingCloud(t, r, http.StatusUnauthorized, `{"code":"unauthenticated"}`)
	logs, _ := reconcileLogged(t, r, pod)
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodPending || got.Status.Reason != "CloudRejectedRequest" {
		t.Fatalf("401 published as %s %s", got.Status.Phase, got.Status.Reason)
	}
	if !strings.Contains(logs, "HTTP 401 (unauthenticated)") {
		t.Fatalf("provider log lacks Cloud's code:\n%s", logs)
	}
	if rec := getRecord(t, r, pod); rec.TerminalStatus != nil || rec.VerificationDeadline == nil {
		t.Fatal("a rejected credential must run the verification deadline, not end or hold the pod")
	}
}

func TestCloudRejectedClassification(t *testing.T) {
	for _, tc := range []struct {
		status   int
		code     string
		rejected bool
	}{
		{http.StatusBadRequest, "invalid_request", true},
		{http.StatusUnprocessableEntity, "unsupported_combination", true},
		{http.StatusForbidden, "forbidden", true},
		{http.StatusNotFound, "not_found", false},
		{http.StatusTooManyRequests, "rate_limited", false},
		{http.StatusConflict, "insufficient_capacity", false},
		{http.StatusConflict, "idempotency_in_flight", false},
		{http.StatusServiceUnavailable, "unavailable", false},
	} {
		if got := cloudRejected(&cloudProblem{status: tc.status, code: tc.code}); got != tc.rejected {
			t.Errorf("HTTP %d %s: rejected %t", tc.status, tc.code, got)
		}
	}
}
