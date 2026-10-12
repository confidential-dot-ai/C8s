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
	getKubeConfig = func() *rest.Config { return &rest.Config{} }
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
		GetCertImage:       "ghcr.io/c8s/c8s:latest",
		CDSURL:             "https://cds.c8s-system.svc",
		WebhookConfigName:  "c8s-mutating",
		WebhookServiceName: "c8s-webhook",
		LeaderElectionNS:   "c8s-system",
	}
}

func TestRunManagerCreateError(t *testing.T) {
	stubRunWiring(t, nil, errors.New("boom"))
	err := Run(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "create manager: boom") {
		t.Fatalf("Run error = %v, want wrapped create-manager error", err)
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
