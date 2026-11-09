package podprovider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// rateLimitingCloud is an HTTP Cloud that answers every request with 429
// rate_limited, with the given Retry-After header when it is not empty.
func rateLimitingCloud(t *testing.T, r *Reconciler, retryAfter string) *int {
	t.Helper()
	calls := new(int)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"code":"rate_limited","retryable":true}`)
	}))
	t.Cleanup(srv.Close)
	c := newCloudClient(r.cfg)
	c.base = srv.URL
	c.http.Transport = srv.Client().Transport
	r.cloud = c
	return calls
}

func reconcileResult(t *testing.T, r *Reconciler, pod *corev1.Pod) ctrl.Result {
	t.Helper()
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertRateLimited(t *testing.T, r *Reconciler, pod *corev1.Pod) {
	t.Helper()
	got := getPod(t, r, pod)
	if got.Status.Phase != corev1.PodPending || got.Status.Reason != "RateLimited" || got.Status.Message != "Cloud is rate limiting this provider's requests" {
		t.Fatalf("429 published as %s %s %q", got.Status.Phase, got.Status.Reason, got.Status.Message)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"":                              0,
		"7":                             7 * time.Second,
		"0":                             0,
		"-3":                            0,
		"soon":                          0,
		"86400":                         maxRateLimitBackoff,
		"Sun, 08 Nov 2026 12:00:42 GMT": 42 * time.Second,
		"Sun, 08 Nov 2026 11:59:00 GMT": 0,
	} {
		if got := parseRetryAfter(value, now); got != want {
			t.Errorf("Retry-After %q: %s, want %s", value, got, want)
		}
	}
}

// A throttled create waits as Cloud asked, plus jitter capped at a quarter of
// the wait and at maxRateLimitJitter, and never runs into CloudUnavailable.
func TestRateLimitedCreateHonoursRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name, retryAfter string
		want             time.Duration
	}{
		{"with Retry-After", "30", 30*time.Second + maxRateLimitJitter},
		{"short Retry-After", "4", 5 * time.Second},
		{"without Retry-After", "", pollInterval + pollInterval/4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := fixturePod()
			r, _ := fixtureReconciler(t, pod)
			r.jitter = func(n time.Duration) time.Duration { return n }
			calls := rateLimitingCloud(t, r, tc.retryAfter)
			if got := reconcileResult(t, r, pod).RequeueAfter; got != tc.want {
				t.Fatalf("requeued after %s, want %s", got, tc.want)
			}
			assertRateLimited(t, r, pod)
			if *calls == 0 || getRecord(t, r, pod).TerminalStatus != nil {
				t.Fatal("throttled create ended the pod")
			}
		})
	}
}

// Throttled polling keeps the deadline it had: the wait is cut at the
// deadline, the deadline does not move, and expiry still ends the pod.
func TestRateLimitedPollingKeepsTheVerificationDeadline(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.jitter = func(n time.Duration) time.Duration { return n }
	cloud.create = func(_ string, req createRequest) (*instance, error) {
		cloud.in = instanceFor(req)
		cloud.in.Status = "provisioning"
		return cloud.in, nil
	}
	if err := reconcile(t, r, pod); err != nil {
		t.Fatal(err)
	}
	deadline := getRecord(t, r, pod).VerificationDeadline
	if deadline == nil {
		t.Fatal("starting instance began no verification deadline")
	}
	rateLimitingCloud(t, r, "300")
	now = deadline.Add(-20 * time.Second)
	if got := reconcileResult(t, r, pod).RequeueAfter; got != 20*time.Second {
		t.Fatalf("throttled poll requeued after %s, past the deadline", got)
	}
	assertRateLimited(t, r, pod)
	if got := getRecord(t, r, pod).VerificationDeadline; got == nil || !got.Equal(*deadline) {
		t.Fatalf("deadline moved from %s to %v", deadline, got)
	}
	rateLimitingCloud(t, r, "")
	if got := reconcileResult(t, r, pod).RequeueAfter; got != pollInterval+pollInterval/4 {
		t.Fatalf("throttled poll without Retry-After requeued after %s", got)
	}
	// Expiry ends the pod even while Cloud still throttles the cleanup.
	now = deadline.Add(time.Second)
	_ = reconcile(t, r, pod)
	assertVerificationFailed(t, r, pod)
}

// A real outage stays CloudUnavailable.
func TestCloudOutageIsNotRateLimited(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	cloud.find = func(string) (*instance, error) {
		return nil, &cloudProblem{status: http.StatusServiceUnavailable, code: "unavailable", retryAfter: time.Minute}
	}
	_ = reconcile(t, r, pod)
	if got := getPod(t, r, pod); got.Status.Reason != "CloudUnavailable" {
		t.Fatalf("503 published as %s", got.Status.Reason)
	}
}
