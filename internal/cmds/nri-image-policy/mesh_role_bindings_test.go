package nriimagepolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestMeshRoleBindingsAfterCredentialEndpoint(t *testing.T) {
	cfg := meshConfigForLoad(t)
	cfg.Allowlist.NodeTCB = false
	cfg.Allowlist.Base = roleBase(t, pushDigestB, CredentialRole, []string{"/usr/local/bin/c8s", "get-cert"})
	cfg.WorkloadClaims.AdvertiseHost = "10.0.0.7"
	cfg.WorkloadClaims.CDSNodePort = 30808
	if _, err := parseConfig(meshConfigDocument(t, cfg)); err != nil {
		t.Fatalf("static config rejected before credential binding: %v", err)
	}
	loaded, err := loadMeshConfigDocument(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := loaded.credentialRole()
	if !ok || bound.Destinations[0].String() != "10.0.0.7:30808" {
		t.Fatalf("credential role = %+v, bound = %v", bound, ok)
	}
	cfg.WorkloadClaims.CDSNodePort = 0
	if _, err := loadMeshConfigDocument(t, cfg); err == nil {
		t.Fatal("unbound credentials role loaded")
	}
}

func loadMeshConfigDocument(t *testing.T, cfg *config) (*config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, meshConfigDocument(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConfig(path)
}

func TestNodeImageBootConfigRequiresCredentialBinding(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMeshConfigDocument(t, cfg); err == nil {
		t.Fatal("unstaged boot config loaded without a credential binding")
	}
	cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:30808")},
	})
	if _, err := loadMeshConfigDocument(t, cfg); err != nil {
		t.Fatalf("boot config with a staged credential binding: %v", err)
	}
}
