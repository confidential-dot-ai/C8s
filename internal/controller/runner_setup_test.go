package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// testRESTMapper is a static mapper covering the kinds the package wires up,
// so manager construction never needs API discovery.
func testRESTMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{
		corev1.SchemeGroupVersion.WithKind("Service"),
		corev1.SchemeGroupVersion.WithKind("Pod"),
		appsv1.SchemeGroupVersion.WithKind("Deployment"),
		appsv1.SchemeGroupVersion.WithKind("StatefulSet"),
		appsv1.SchemeGroupVersion.WithKind("DaemonSet"),
		v1alpha2.GroupVersion.WithKind("ConfidentialWorkload"),
	} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	return m
}

// newTestManager builds a real — never started — manager against a dead REST
// endpoint. With the static mapper, construction is fully offline; nothing
// contacts the API server until Start, which these tests never call.
func newTestManager(t *testing.T) manager.Manager {
	t.Helper()
	opts := managerOptions(Options{MetricsAddr: "0", HealthAddr: "0"})
	opts.MapperProvider = func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
		return testRESTMapper(), nil
	}
	// Several tests wire the same controller names onto fresh managers; the
	// uniqueness check is process-global.
	skip := true
	opts.Controller.SkipNameValidation = &skip
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, opts)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// stubDirectClient replaces the package's direct-client factory for the test.
func stubDirectClient(t *testing.T, c client.Client, err error) {
	t.Helper()
	orig := newDirectClient
	newDirectClient = func(manager.Manager) (client.Client, error) { return c, err }
	t.Cleanup(func() { newDirectClient = orig })
}

// stubWebhookCertDir redirects serving-cert writes into a temp dir.
func stubWebhookCertDir(t *testing.T) string {
	t.Helper()
	orig := webhookCertDir
	dir := t.TempDir()
	webhookCertDir = dir
	t.Cleanup(func() { webhookCertDir = orig })
	return dir
}

func mutatingWebhookConfig(name string) *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		Name: name,
		Webhooks: []admissionv1.MutatingWebhook{
			{Name: "pods.c8s.dev"},
			{Name: "other.c8s.dev"},
		},
	}
}

// validatingWebhookConfig is the pod validator's configuration, which the
// operator patches beside the injector's and cannot come up without.
func validatingWebhookConfig(injectorName string) *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		Name:     validatorConfigName(injectorName),
		Webhooks: []admissionv1.ValidatingWebhook{{Name: "pods-validate.c8s.dev"}},
	}
}

func TestSetupManagerFullWiring(t *testing.T) {
	dir := stubWebhookCertDir(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mutatingWebhookConfig("c8s-mutating"), validatingWebhookConfig("c8s-mutating")).Build()
	stubDirectClient(t, fc, nil)

	mgr := newTestManager(t)
	opts := Options{
		DisableStatusMirror: true,
		GetCertImage:        "ghcr.io/c8s/c8s:latest",
		CDSURL:              "https://cds.c8s-system.svc",
		WebhookConfigName:   "c8s-mutating",
		WebhookServiceName:  "c8s-webhook",
		LeaderElectionNS:    "c8s-system",
		ExcludeNamespaces:   []string{"skip-me"},
	}
	if err := setupManager(context.Background(), mgr, nil, opts, logr.Discard()); err != nil {
		t.Fatalf("setupManager: %v", err)
	}

	// The webhook serving certs must be minted on disk.
	for _, f := range []string{"tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("serving cert %s not written: %v", f, err)
		}
	}
	// The CA bundle must be patched onto every webhook entry.
	var got admissionv1.MutatingWebhookConfiguration
	if err := fc.Get(context.Background(), types.NamespacedName{Name: "c8s-mutating"}, &got); err != nil {
		t.Fatal(err)
	}
	for _, wh := range got.Webhooks {
		if len(wh.ClientConfig.CABundle) == 0 {
			t.Fatalf("webhook %q caBundle not patched", wh.Name)
		}
	}

	// The pod-mutating admission handler must be registered on the webhook
	// server's mux at its fixed path (webhook.Register wires /mutate-pods).
	mux := mgr.GetWebhookServer().WebhookMux()
	if mux == nil {
		t.Fatal("webhook server mux is nil; no handler was registered")
	}
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, "/mutate-pods", nil))
	if pattern != "/mutate-pods" {
		t.Fatalf("mux pattern for /mutate-pods = %q, want an exact registration", pattern)
	}

	// Not asserted, deliberately: (a) the healthz/readyz registrations —
	// controller-runtime stores the checks in an unexported map that only
	// materializes as an HTTP handler on Start, and AddHealthzCheck silently
	// overwrites duplicates, so there is no observable to probe; (b) the
	// reinject-sweep runnable and the controller registrations — both go
	// through mgr.Add, whose runnable set is likewise unexported with no
	// accessor short of Start()ing the manager against a live API server.
	// Neither can be observed without adding a production seam.
}

func TestBootstrapWebhookPKISkipsWithoutConfigName(t *testing.T) {
	if err := bootstrapWebhookPKI(context.Background(), nil, Options{}); err != nil {
		t.Fatalf("bootstrapWebhookPKI without config name: %v", err)
	}
}

func TestBootstrapWebhookPKIRequiresServiceName(t *testing.T) {
	err := bootstrapWebhookPKI(context.Background(), nil, Options{WebhookConfigName: "c8s-mutating"})
	if err == nil || !strings.Contains(err.Error(), "webhook-service-name is required") {
		t.Fatalf("err = %v, want webhook-service-name requirement", err)
	}
}

func TestBootstrapWebhookPKIDirectClientError(t *testing.T) {
	stubWebhookCertDir(t)
	stubDirectClient(t, nil, errors.New("no client"))
	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "c8s-system",
	}
	err := bootstrapWebhookPKI(context.Background(), nil, opts)
	if err == nil || !strings.Contains(err.Error(), "build bootstrap client") {
		t.Fatalf("err = %v, want build bootstrap client failure", err)
	}
}

func TestBootstrapWebhookPKIPatchFailure(t *testing.T) {
	stubWebhookCertDir(t)
	// No MutatingWebhookConfiguration in the fake: the patch's Get fails.
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	stubDirectClient(t, fc, nil)
	opts := Options{
		WebhookConfigName:       "c8s-mutating",
		WebhookServiceName:      "c8s-webhook",
		WebhookServiceNamespace: "c8s-system",
	}
	err := bootstrapWebhookPKI(context.Background(), nil, opts)
	if err == nil || !strings.Contains(err.Error(), "MutatingWebhookConfiguration") {
		t.Fatalf("err = %v, want a caBundle patch failure", err)
	}
}

func TestWebhookCertRotatorRetriesOnFailure(t *testing.T) {
	ca, err := issuer.NewCA("test webhook", webhook.WebhookCATTL)
	if err != nil {
		t.Fatal(err)
	}
	// certDir under a regular file: BootstrapServingCert cannot create it, so
	// every rotation attempt fails and the retry branch runs.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(blocker, "certs")

	var mu sync.Mutex
	failures := 0
	logger := funcr.New(func(prefix, args string) {
		mu.Lock()
		failures++
		mu.Unlock()
	}, funcr.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Tiny TTL: interval ≈ 20ms and retry = interval/2, so failures accrue fast.
		_ = webhookCertRotator(ca, []string{"svc.ns.svc"}, certDir, 30*time.Millisecond, logger)(ctx)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := failures
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rotation failures to be retried")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rotator did not stop after cancel")
	}
}

// A mesh image with no image for the credential containers would inject an
// endpoint with nothing to publish the credentials it reads, so the operator
// refuses to start instead of injecting half a mesh.
func TestSetupManagerRefusesMeshImageWithoutGetCertImage(t *testing.T) {
	mgr := newTestManager(t)
	opts := Options{
		DisableStatusMirror: true,
		MeshImage:           "ghcr.io/c8s/armtls-mesh:latest",
		LeaderElectionNS:    "c8s-system",
	}
	err := setupManager(context.Background(), mgr, nil, opts, logr.Discard())
	if err == nil || !strings.Contains(err.Error(), "--mesh-image needs --get-cert-image") {
		t.Fatalf("err = %v, want the missing get-cert image refused", err)
	}
}
