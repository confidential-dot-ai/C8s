package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// stubStartManager delegates everything to a real test manager but makes
// Start deterministic instead of running the control loops.
type stubStartManager struct {
	manager.Manager
	startErr error
}

func (m stubStartManager) Start(context.Context) error { return m.startErr }

func stubRunWiring(t *testing.T, mgr manager.Manager, mgrErr error) {
	t.Helper()
	origConfig, origManager := getKubeConfig, newManager
	getKubeConfig = func(string) (*rest.Config, error) { return &rest.Config{}, nil }
	newManager = func(*rest.Config, ctrl.Options) (manager.Manager, error) { return mgr, mgrErr }
	t.Cleanup(func() { getKubeConfig, newManager = origConfig, origManager })
}

func stubNewDiscoveryClient(t *testing.T, err error) *int {
	t.Helper()
	calls := new(int)
	orig := newDiscoveryClient
	newDiscoveryClient = func(*rest.Config) (*discovery.DiscoveryClient, error) {
		*calls++
		return nil, err
	}
	t.Cleanup(func() { newDiscoveryClient = orig })
	return calls
}

// fullWiringOptions mirrors TestSetupManagerFullWiring so Run can get through
// setupManager against fakes.
func fullWiringOptions(t *testing.T) Options {
	t.Helper()
	stubWebhookCertDir(t)
	fc := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mutatingWebhookConfig("c8s-mutating"), validatingWebhookConfig("c8s-mutating")).Build()
	stubDirectClient(t, fc, nil)
	return Options{
		GetCertImage:          "ghcr.io/c8s/c8s:latest",
		MeshImage:             "ghcr.io/c8s/armtls-mesh:latest",
		WebhookConfigName:     "c8s-mutating",
		WorkloadClaimsHostDir: "/run/nri-image-policy",
		WebhookServiceName:    "c8s-webhook",
		LeaderElectionNS:      "c8s-system",
	}
}

func TestRunManagerCreateError(t *testing.T) {
	stubRunWiring(t, nil, errors.New("boom"))
	err := Run(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "create manager: boom") {
		t.Fatalf("Run error = %v, want wrapped create-manager error", err)
	}
}

func TestRunWebhookHostRequiresInjectionImages(t *testing.T) {
	for name, opts := range map[string]Options{
		"both images missing": {},
		"get-cert missing":    {MeshImage: "mesh"},
		"mesh missing":        {GetCertImage: "get-cert"},
	} {
		t.Run(name, func(t *testing.T) {
			original := getKubeConfig
			getKubeConfig = func(string) (*rest.Config, error) {
				t.Fatal("loaded Kubernetes credentials before rejecting missing webhook images")
				return nil, nil
			}
			t.Cleanup(func() { getKubeConfig = original })

			opts.WebhookHost = "127.0.0.1"
			err := Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "--get-cert-image") || !strings.Contains(err.Error(), "--mesh-image") {
				t.Fatalf("Run error = %v, want the external webhook's required image flags", err)
			}
		})
	}
}

func TestDefaultAttestationApiURL(t *testing.T) {
	cases := map[string]struct {
		opts Options
		want string
	}{
		"worker mode derives the node socket": {
			opts: Options{WorkloadClaimsHostDir: "/run/nri-image-policy"},
			want: "unix:///run/nri-image-policy/attestation-api.sock",
		},
		"explicit flag overrides the derived default": {
			opts: Options{
				WorkloadClaimsHostDir: "/run/nri-image-policy",
				AttestationApiURL:     "http://attestation-api.c8s-system.svc:8400",
			},
			want: "http://attestation-api.c8s-system.svc:8400",
		},
		"chart mode (explicit flag, no host dir) is unchanged": {
			opts: Options{AttestationApiURL: "http://attestation-api.c8s-system.svc:8400"},
			want: "http://attestation-api.c8s-system.svc:8400",
		},
		"neither flag set stays empty": {
			opts: Options{},
			want: "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := defaultAttestationApiURL(tc.opts); got != tc.want {
				t.Fatalf("defaultAttestationApiURL(%+v) = %q, want %q", tc.opts, got, tc.want)
			}
		})
	}
}

func TestRunRejectsMalformedAttestationAPIURL(t *testing.T) {
	original := getKubeConfig
	getKubeConfig = func(string) (*rest.Config, error) {
		t.Fatal("loaded Kubernetes credentials before rejecting a malformed --attestation-api-url")
		return nil, nil
	}
	t.Cleanup(func() { getKubeConfig = original })

	err := Run(context.Background(), Options{AttestationApiURL: "ftp://attestation-api"})
	if err == nil || !strings.Contains(err.Error(), "--attestation-api-url") {
		t.Fatalf("Run error = %v, want a rejected --attestation-api-url", err)
	}
}

func TestRunDiscoveryClientError(t *testing.T) {
	stubRunWiring(t, stubStartManager{Manager: newTestManager(t)}, nil)
	stubNewDiscoveryClient(t, errors.New("no api server"))
	opts := fullWiringOptions(t)
	opts.DisableStatusMirror = false
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "create discovery client") {
		t.Fatalf("Run error = %v, want wrapped discovery-client error", err)
	}
}

func TestRunMirrorDisabledSkipsDiscovery(t *testing.T) {
	stubRunWiring(t, stubStartManager{Manager: newTestManager(t)}, nil)
	calls := stubNewDiscoveryClient(t, errors.New("must not be called"))
	opts := fullWiringOptions(t)
	opts.DisableStatusMirror = true
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("discovery client built %d times with the status mirror disabled, want 0", *calls)
	}
}

func TestRunManagerStartError(t *testing.T) {
	stubRunWiring(t, stubStartManager{Manager: newTestManager(t), startErr: errors.New("boom")}, nil)
	opts := fullWiringOptions(t)
	opts.DisableStatusMirror = true
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "manager exited: boom") {
		t.Fatalf("Run error = %v, want wrapped manager-exit error", err)
	}
}

func TestRunDisablesClientRateLimit(t *testing.T) {
	stubRunWiring(t, nil, errors.New("stop"))
	var qps float32
	newManager = func(c *rest.Config, _ ctrl.Options) (manager.Manager, error) {
		qps = c.QPS
		return nil, errors.New("stop")
	}
	_ = Run(context.Background(), Options{}) // Only the config handed to newManager matters.
	if qps >= 0 {
		t.Fatalf("newManager config QPS = %v, want < 0", qps)
	}
}
