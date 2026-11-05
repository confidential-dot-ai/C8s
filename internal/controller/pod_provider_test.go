package controller

import (
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/confidential-dot-ai/c8s/internal/podprovider"
)

func TestPodProviderSetupRequiresTrustedNamespaceAndWebhooks(t *testing.T) {
	oldLoad, oldRegister := loadPodCVMProvider, registerPodCVMProvider
	t.Cleanup(func() { loadPodCVMProvider, registerPodCVMProvider = oldLoad, oldRegister })
	for _, tc := range []struct {
		name                   string
		path, image, namespace string
		disableElection        bool
		wantLoad, wantSetup    bool
		wantError              string
	}{
		{name: "no webhooks", path: "/config.json", wantError: "requires the pod admission webhooks"},
		{name: "no leader election", path: "/config.json", image: "image", disableElection: true, wantError: "requires --leader-elect=true"},
		{name: "namespace mismatch", path: "/config.json", image: "image", namespace: "tenant", wantLoad: true, wantError: "namespace must match"},
		{name: "configured", path: "/config.json", image: "image", namespace: "system", wantLoad: true, wantSetup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded, registered := false, false
			cfg := &podprovider.Config{Namespace: tc.namespace}
			loadPodCVMProvider = func(path string) (*podprovider.Config, error) {
				loaded = true
				if path != tc.path {
					t.Fatalf("loaded %q", path)
				}
				return cfg, nil
			}
			registerPodCVMProvider = func(_ manager.Manager, got *podprovider.Config) error {
				registered = true
				if got != cfg {
					t.Fatal("configuration replaced")
				}
				return nil
			}
			err := setupPodCVMProvider(nil, Options{PodCVMProviderConfig: tc.path, GetCertImage: tc.image, LeaderElectionNS: "system", LeaderElection: !tc.disableElection})
			if (tc.wantError == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error=%v, want %q", err, tc.wantError)
			}
			if loaded != tc.wantLoad || registered != tc.wantSetup {
				t.Fatalf("load=%t setup=%t", loaded, registered)
			}
		})
	}
}
