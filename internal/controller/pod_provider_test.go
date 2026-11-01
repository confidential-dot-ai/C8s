package controller

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
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
		loadErr, setupErr      error
		wantLoad, wantSetup    bool
		wantError              string
	}{
		{name: "disabled"},
		{name: "no webhooks", path: "/config.json", wantError: "requires the pod admission webhooks"},
		{name: "no leader election", path: "/config.json", image: "image", disableElection: true, wantError: "requires --leader-elect=true"},
		{name: "unreadable config", path: "/config.json", image: "image", wantLoad: true, loadErr: errors.New("invalid configuration"), wantError: "load pod CVM provider"},
		{name: "namespace mismatch", path: "/config.json", image: "image", namespace: "tenant", wantLoad: true, wantError: "namespace must match"},
		{name: "setup failure", path: "/config.json", image: "image", namespace: "system", wantLoad: true, wantSetup: true, setupErr: errors.New("registration failed"), wantError: "setup pod CVM provider"},
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
				return cfg, tc.loadErr
			}
			registerPodCVMProvider = func(_ manager.Manager, got *podprovider.Config) error {
				registered = true
				if got != cfg {
					t.Fatal("configuration replaced")
				}
				return tc.setupErr
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

func TestPodProviderSecretCacheStaysInItsNamespace(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		opts := Options{LeaderElectionNS: "system"}
		if enabled {
			opts.PodCVMProviderConfig = "/config.json"
		}
		configured := false
		for object, scope := range managerOptions(opts).Cache.ByObject {
			if _, ok := object.(*corev1.Secret); !ok {
				continue
			}
			configured = true
			if len(scope.Namespaces) != 1 {
				t.Fatalf("Secret cache scope=%v", scope.Namespaces)
			}
			if _, ok := scope.Namespaces["system"]; !ok {
				t.Fatal("Secret cache includes another namespace")
			}
		}
		if configured != enabled {
			t.Fatalf("Secret cache configured=%t, enabled=%t", configured, enabled)
		}
	}
}
