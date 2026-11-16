package podprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestCloudProblemCodes(t *testing.T) {
	for _, tc := range []struct {
		status          int
		body, code      string
		refused, absent bool
	}{
		{http.StatusConflict, `{"code":"insufficient_capacity","detail":"none fits now","retryable":true}`, "insufficient_capacity", true, false},
		{http.StatusBadRequest, `{"code":"invalid_request"}`, "invalid_request", true, false},
		{http.StatusUnprocessableEntity, `{"code":"unsupported_combination"}`, "unsupported_combination", true, false},
		{http.StatusNotFound, `{"code":"not_found"}`, "not_found", true, true},
		{http.StatusNotFound, ``, "", false, true},
		{http.StatusConflict, `{"code":"idempotency_in_flight","retryable":true}`, "idempotency_in_flight", false, false},
		{http.StatusTooManyRequests, `{"code":"rate_limited","retryable":true}`, "rate_limited", false, false},
		{http.StatusUnauthorized, `{"code":"unauthenticated"}`, "unauthenticated", false, false},
		{http.StatusServiceUnavailable, `{"code":"unavailable","retryable":true}`, "unavailable", false, false},
		{http.StatusInternalServerError, `{"code":"insufficient_capacity"}`, "insufficient_capacity", false, false},
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		c := newCloudClient(fixtureConfig(t))
		c.base = srv.URL
		c.http.Transport = srv.Client().Transport
		_, err := c.Create(context.Background(), "frozen-key", createRequest{})
		srv.Close()
		if problemCode(err) != tc.code || createRefused(err) != tc.refused || errors.Is(err, errCloudNotFound) != tc.absent {
			t.Errorf("HTTP %d %s: code %q, refused %t, absent %t", tc.status, tc.body, problemCode(err), createRefused(err), errors.Is(err, errCloudNotFound))
		}
	}
}

func TestInsufficientCapacityRetriesWithinTheDeadline(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	now := time.Now()
	r.now = func() time.Time { return now }
	cloud.create = func(string, createRequest) (*instance, error) {
		return nil, &cloudProblem{status: http.StatusConflict, code: "insufficient_capacity"}
	}
	for range 2 {
		if err := reconcile(t, r, pod); err != nil {
			t.Fatal(err)
		}
		got := getPod(t, r, pod)
		if got.Status.Phase != corev1.PodPending || got.Status.Reason != "InsufficientCapacity" || got.Status.Message != "No Cloud host has room for this Pod CVM size" {
			t.Fatalf("capacity refusal published as %s %q", got.Status.Reason, got.Status.Message)
		}
	}
	if cloud.createCalls != 2 || getRecord(t, r, pod).TerminalStatus != nil {
		t.Fatal("capacity refusal was not retried")
	}
	// The deadline still ends the pod; the refused create left nothing to
	// destroy.
	now = getRecord(t, r, pod).VerificationDeadline.Add(time.Second)
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	assertVerificationFailed(t, r, pod)
	if !getRecord(t, r, pod).Deleted || cloud.deleteCalls != 0 {
		t.Fatal("expired capacity refusal was not resolved as no instance")
	}
}

func TestCapacityLimitAndLaunchRefusalAreDistinct(t *testing.T) {
	for _, tc := range []struct{ name, reason, message string }{
		{"unlaunchable", "LaunchRefused", "The provider refused to launch the Pod"},
		{"over-maxPods", "CapacityLimit", "The provider's maxPods limit is reached"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := fixturePod()
			if tc.reason == "LaunchRefused" {
				pod.Spec.Containers[0].Image = "busybox:latest"
			}
			r, cloud := fixtureReconciler(t, pod)
			if tc.reason == "CapacityLimit" {
				r.cfg.MaxPods = 0
			}
			if err := reconcile(t, r, pod); err == nil {
				t.Fatal("record written")
			}
			if got := getPod(t, r, pod); got.Status.Reason != tc.reason || got.Status.Message != tc.message || cloud.createCalls != 0 {
				t.Fatalf("reported %s %q", got.Status.Reason, got.Status.Message)
			}
		})
	}
}

// deleteUnresolvedCreate leaves the pod with a create that was attempted but
// never observed, deletes it and replays the create with the outcome given.
func deleteUnresolvedCreate(t *testing.T, replay error) (*Reconciler, *fakeCloud, *corev1.Pod, error) {
	t.Helper()
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.find = func(string) (*instance, error) { return nil, nil }
	cloud.create = func(string, createRequest) (*instance, error) { return nil, errors.New("response lost") }
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	if rec := getRecord(t, r, pod); !rec.CreateAttempted || rec.InstanceID != "" {
		t.Fatal("create was not left unresolved")
	}
	if err := r.client.Delete(context.Background(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	cloud.create = func(string, createRequest) (*instance, error) { return nil, replay }
	return r, cloud, pod, reconcile(t, r, pod)
}

func TestDeletionReleasesAPodWhoseCreateReplayIsRefused(t *testing.T) {
	for _, code := range []string{"insufficient_capacity", "invalid_request", "unsupported_combination", "not_found"} {
		t.Run(code, func(t *testing.T) {
			status := map[string]int{"insufficient_capacity": 409, "invalid_request": 400, "unsupported_combination": 422, "not_found": 404}[code]
			r, cloud, pod, err := deleteUnresolvedCreate(t, &cloudProblem{status: status, code: code})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.client.Get(context.Background(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
				t.Fatalf("refused create did not release the Pod: %v", err)
			}
			if _, _, err := r.loadRecord(context.Background(), identityKey(r.cfg.ProviderID, string(pod.UID))); !apierrors.IsNotFound(err) {
				t.Fatalf("record retained: %v", err)
			}
			if cloud.deleteCalls != 0 {
				t.Fatal("refused create destroyed an instance")
			}
		})
	}
}

func TestDeletionHoldsAPodWhoseCreateReplayIsUnresolved(t *testing.T) {
	for name, replay := range map[string]error{
		"transport":             errors.New("connection reset"),
		"idempotency_in_flight": &cloudProblem{status: http.StatusConflict, code: "idempotency_in_flight"},
		"rate_limited":          &cloudProblem{status: http.StatusTooManyRequests, code: "rate_limited"},
		"unauthenticated":       &cloudProblem{status: http.StatusUnauthorized, code: "unauthenticated"},
		"internal_error":        &cloudProblem{status: http.StatusInternalServerError, code: "internal_error"},
		"unavailable":           &cloudProblem{status: http.StatusServiceUnavailable, code: "unavailable"},
		"no-body-404":           &cloudProblem{status: http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			r, _, pod, err := deleteUnresolvedCreate(t, replay)
			if err == nil {
				t.Fatal("unresolved replay finished deletion")
			}
			if !controllerutil.ContainsFinalizer(getPod(t, r, pod), finalizer) || getRecord(t, r, pod).Deleted {
				t.Fatal("unresolved replay released the Pod")
			}
		})
	}
}
