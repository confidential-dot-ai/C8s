package podprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestGuestReaderRefusesUnattestedStatusAndRemovesTrustFiles(t *testing.T) {
	cfg := fixtureConfig(t)
	req, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	rec := &record{Request: req, Manifest: cfg.manifest}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"uid":"11111111-1111-1111-1111-111111111111"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}`))
	}))
	defer server.Close()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	projection, err := readGuest(ctx, rec, strings.TrimPrefix(server.URL, "https://"))
	if err == nil || projection.Status.Phase != "" {
		t.Fatalf("unattested Ready accepted: projection=%+v, error=%v", projection, err)
	}
	if err.Error() != "guest status attestation unavailable" {
		t.Fatalf("verification error exposed endpoint or trust details: %v", err)
	}
	files, err := os.ReadDir(tmp)
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary trust files retained: %v, %v", files, err)
	}
}

func TestSetupRegistersWithoutNetworkEffectsBeforeLeadership(t *testing.T) {
	cfg := fixtureConfig(t)
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg.CloudURL = server.URL
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{corev1.SchemeGroupVersion})
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Pod"), meta.RESTScopeNamespace)
	mgr, err := ctrl.NewManager(&rest.Config{Host: server.URL}, ctrl.Options{
		Scheme:                  scheme,
		MapperProvider:          func(*rest.Config, *http.Client) (meta.RESTMapper, error) { return mapper, nil },
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:  "0",
		LeaderElection:          true,
		LeaderElectionID:        "provider-registration-test",
		LeaderElectionNamespace: cfg.Namespace,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*Config{nil, {}} {
		if err := Setup(mgr, invalid); err == nil {
			t.Fatal("provider registered without loaded trust")
		}
	}
	if err := Setup(mgr, cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("registration contacted Kubernetes or Cloud before manager leadership")
	}
}
