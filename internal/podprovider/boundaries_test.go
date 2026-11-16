package podprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

func TestGuestReaderRefusesUnattestedStatusAndRemovesTrustFiles(t *testing.T) {
	cfg := fixtureConfig(t)
	req, _, _, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	rec := &record{instanceIntent: instanceIntent{Request: req, Manifest: cfg.manifest}}
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

// A status read accepts only the serving key the assignment was signed over:
// another guest from the same launch document passes attestation but not this.
func TestStatusReadIsPinnedToTheAssignedServingKey(t *testing.T) {
	var invalid atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != podstatus.PodPath:
			w.WriteHeader(http.StatusNotFound)
		case invalid.Load():
			_, _ = w.Write([]byte(`{"metadata":`))
		default:
			_, _ = w.Write([]byte(`{"metadata":{"uid":"pinned"}}`))
		}
	}))
	defer server.Close()
	assigned, err := x509.MarshalPKIXPublicKey(server.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	attested := func() *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}}
	}
	old := attest
	t.Cleanup(func() { attest = old })
	attest = func(context.Context, podstatus.AttestConfig) (*podstatus.Report, *http.Client, error) {
		return &podstatus.Report{}, attested(), nil
	}
	cfg := fixtureConfig(t)
	req, _, _, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(server.URL, "https://")
	rec := &record{instanceIntent: instanceIntent{Request: req, Manifest: cfg.manifest}, ServingKey: foreign}
	if _, err := readGuest(t.Context(), rec, address); err == nil || err.Error() != "guest status unavailable" {
		t.Fatalf("another guest's serving key answered the status read: %v", err)
	}
	rec.ServingKey = assigned
	projection, err := readGuest(t.Context(), rec, address)
	if err != nil || projection.Metadata.UID != "pinned" {
		t.Fatalf("assigned serving key refused: %+v, %v", projection, err)
	}
	rec.ServingKey = nil
	if _, err := readGuest(t.Context(), rec, address); err != nil {
		t.Fatalf("unassigned guest refused before any key was frozen: %v", err)
	}
	invalid.Store(true)
	if _, err := readGuest(t.Context(), rec, address); err == nil || err.Error() != "guest status projection is invalid" {
		t.Fatalf("invalid projection accepted: %v", err)
	}
	if _, err := get(t.Context(), attested(), server.URL+"/missing"); err == nil {
		t.Fatal("non-OK status accepted")
	}
	if _, err := pinServingKey(&http.Client{Transport: http.NewFileTransport(http.Dir(t.TempDir()))}, assigned); err == nil {
		t.Fatal("pinned a client without a TLS transport")
	}
	if err := servingKeyIs(tls.ConnectionState{}, assigned); err == nil {
		t.Fatal("connection without a certificate accepted")
	}
}

// A guest answer past maxGuestBody is refused where it is read, so no status
// projection is parsed out of its prefix.
func TestGuestStatusReadRefusesAnOversizedAnswer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxGuestBody+1))
	}))
	defer server.Close()
	if _, err := get(t.Context(), server.Client(), server.URL+podstatus.PodPath); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("get = %v, want a refused read", err)
	}
}
