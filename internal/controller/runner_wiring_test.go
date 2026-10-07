package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	crreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func confidentialWorkloadResources() *metav1.APIResourceList {
	return &metav1.APIResourceList{APIResources: []metav1.APIResource{
		{Name: "confidentialworkloads", Kind: "ConfidentialWorkload"},
	}}
}

func TestSetupManagerStatusMirrorDiscovery(t *testing.T) {
	notFound := apierrors.NewNotFound(schema.GroupResource{
		Group:    v1alpha2.GroupVersion.Group,
		Resource: "confidentialworkloads",
	}, "")
	tests := []struct {
		name    string
		dc      *fakeServerResources
		wantErr string
	}{
		{"crd available wires the mirror", &fakeServerResources{resources: confidentialWorkloadResources()}, ""},
		{"crd absent is tolerated", &fakeServerResources{err: notFound}, ""},
		{"discovery failure surfaces", &fakeServerResources{err: errors.New("boom")}, "discover ConfidentialWorkload CRD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := setupManager(context.Background(), newTestManager(t), tc.dc, Options{}, logr.Discard())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("setupManager: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// The webhook must register whenever get-cert injection is wanted.
func TestSetupManagerWebhookRegisters(t *testing.T) {
	mgr := newTestManager(t)
	opts := Options{
		DisableStatusMirror: true,
		GetCertImage:        "ghcr.io/c8s/c8s:latest",
		CDSURL:              "https://cds.c8s-system.svc",
	}
	if err := setupManager(context.Background(), mgr, nil, opts, logr.Discard()); err != nil {
		t.Fatalf("setupManager: %v", err)
	}
	mux := mgr.GetWebhookServer().WebhookMux()
	if mux == nil {
		t.Fatal("webhook server mux is nil")
	}
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, "/mutate-pods", nil))
	if pattern != "/mutate-pods" {
		t.Fatalf("mux pattern for /mutate-pods = %q, want an exact registration", pattern)
	}
}

// newTestManagerNameChecked is newTestManager with controller-name validation
// left on, so registrations claim names in the process-global registry.
func newTestManagerNameChecked(t *testing.T) manager.Manager {
	t.Helper()
	opts := managerOptions(Options{MetricsAddr: "0", HealthAddr: "0"})
	opts.MapperProvider = func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
		return testRESTMapper(), nil
	}
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// Registration of the per-kind workload-service reconcilers is gated on
// get-cert injection being enabled. The runnable set is unexported, so the
// registration is observed through the process-global controller-name
// registry: pre-claiming the Deployment reconciler's name makes a real
// registration attempt fail loudly.
func TestSetupManagerRegistersWorkloadServiceReconcilers(t *testing.T) {
	claim := ctrl.NewControllerManagedBy(newTestManagerNameChecked(t)).
		For(&appsv1.Deployment{}).
		Named("workload-service-deployment").
		Complete(crreconcile.Func(func(context.Context, crreconcile.Request) (crreconcile.Result, error) {
			return crreconcile.Result{}, nil
		}))
	// A previous run in this process may already hold the claim; that still
	// forces the conflict the test relies on.
	if claim != nil && !strings.Contains(claim.Error(), "already exists") {
		t.Fatalf("claim controller name: %v", claim)
	}

	opts := Options{DisableStatusMirror: true, GetCertImage: "ghcr.io/c8s/c8s:latest"}
	err := setupManager(context.Background(), newTestManagerNameChecked(t), nil, opts, logr.Discard())
	if err == nil || !strings.Contains(err.Error(), "setup workload-service reconciler") {
		t.Fatalf("err = %v, want the workload-service registration to be attempted and collide", err)
	}
}

// An explicit webhook Service namespace must win over the leader-election
// namespace fallback: the serving cert's SANs are built from it.
func TestBootstrapWebhookPKIUsesExplicitServiceNamespace(t *testing.T) {
	dir := stubWebhookCertDir(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mutatingWebhookConfig("c8s-mutating"), validatingWebhookConfig("c8s-mutating")).Build()
	stubDirectClient(t, fc, nil)

	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "explicit-ns",
		LeaderElectionNS:        "lead-ns",
	}
	if err := bootstrapWebhookPKI(context.Background(), newTestManager(t), opts); err != nil {
		t.Fatalf("bootstrapWebhookPKI: %v", err)
	}

	crtPEM, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crtPEM)
	if block == nil {
		t.Fatal("tls.crt is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"c8s-webhook.explicit-ns.svc", "c8s-webhook.explicit-ns.svc.cluster.local"}
	if !slices.Equal(leaf.DNSNames, want) {
		t.Fatalf("leaf DNSNames = %v, want %v", leaf.DNSNames, want)
	}
}

// waitLogEntry blocks until the recorder captures an entry or the deadline hits.
func waitLogEntry(t *testing.T, rec *logRecorder) logEntry {
	t.Helper()
	select {
	case e := <-rec.ch:
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a rotator log entry")
		return logEntry{}
	}
}

// stopRotator cancels the rotator loop and waits for it to exit.
func stopRotator(t *testing.T, cancel context.CancelFunc, done chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rotator did not stop after cancel")
	}
}

// A successful rotation logs the success message with the regular interval; a
// failing one logs the error with the shortened retry interval. Both intervals
// derive from the leaf TTL: interval = TTL*2/3, retry = interval/2 when the
// hourly default exceeds it.
func TestWebhookCertRotatorLogsOutcomes(t *testing.T) {
	leafTTL := 30 * time.Millisecond
	wantInterval := 20 * time.Millisecond
	wantRetry := 10 * time.Millisecond

	t.Run("success", func(t *testing.T) {
		ca, err := issuer.NewCA("test webhook", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		certDir := t.TempDir()
		rec := newLogRecorder()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = webhookCertRotator(ca, []string{"svc.ns.svc"}, certDir, leafTTL, rec.logger())(ctx)
			close(done)
		}()
		e := waitLogEntry(t, rec)
		stopRotator(t, cancel, done)

		if e.err != nil {
			t.Fatalf("entry = %+v, want a success entry", e)
		}
		// The rotation's observable outcome: a serving pair on disk.
		for _, f := range []string{"tls.crt", "tls.key"} {
			if _, err := os.Stat(filepath.Join(certDir, f)); err != nil {
				t.Fatalf("rotated %s not written: %v", f, err)
			}
		}
		if next, ok := e.kv["next"].(time.Duration); !ok || next != wantInterval {
			t.Fatalf("next = %v, want %v (leafTTL*2/3)", e.kv["next"], wantInterval)
		}
	})

	t.Run("failure retries sooner", func(t *testing.T) {
		certDir := t.TempDir()
		rec := newLogRecorder()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			// No hostnames: every rotation attempt fails.
			_ = webhookCertRotator(nil, nil, certDir, leafTTL, rec.logger())(ctx)
			close(done)
		}()
		e := waitLogEntry(t, rec)
		stopRotator(t, cancel, done)

		if e.err == nil {
			t.Fatalf("entry = %+v, want a failure entry carrying its error", e)
		}
		if _, err := os.Stat(filepath.Join(certDir, "tls.crt")); err == nil {
			t.Fatal("failed rotation still wrote a serving cert")
		}
		if retry, ok := e.kv["retry"].(time.Duration); !ok || retry != wantRetry {
			t.Fatalf("retry = %v, want %v (fast retry, not the full interval)", e.kv["retry"], wantRetry)
		}
	})
}
