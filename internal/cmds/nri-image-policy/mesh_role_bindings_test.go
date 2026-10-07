package nriimagepolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

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
