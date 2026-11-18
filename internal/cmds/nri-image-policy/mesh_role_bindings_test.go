package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func TestMeshRoleBindingsAfterCredentialEndpoint(t *testing.T) {
	cfg := meshConfigForLoad(t)
	cfg.Allowlist.NodeTCB = false
	cfg.Allowlist.Base = roleBase(t, pushDigestB, allowlist.RoleCredentials, []string{"/usr/local/bin/c8s", "get-cert"})
	cfg.WorkloadClaims.AdvertiseHost = "10.0.0.7"
	cfg.Allowlist.Pull = installedTAAddress(t, "cds.example.org:8443").Pull
	cfg.Allowlist.Pull.Interval, cfg.Allowlist.Pull.Timeout = time.Second, time.Second
	cfg.Allowlist.Pull.AttestationApiURL = "http://127.0.0.1:8400"
	if _, err := parseConfig(meshConfigDocument(t, cfg)); err != nil {
		t.Fatalf("static config rejected before credential binding: %v", err)
	}
	loaded, err := loadMeshConfigDocument(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := loaded.credentialRole()
	if !ok || bound.Port != 8443 {
		t.Fatalf("credential role = %+v, bound = %v", bound, ok)
	}
	cfg.Allowlist.Pull.TAAddressFile = ""
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
	cfg, err := parseConfig([]byte(renderWorkerImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMeshConfigDocument(t, cfg); err == nil {
		t.Fatal("unstaged boot config loaded without a credential binding")
	}
	cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
		Name: allowlist.RoleCredentials,
		UID:  workloadclaims.CredentialsUID,
		Port: 30808,
	})
	if _, err := loadMeshConfigDocument(t, cfg); err != nil {
		t.Fatalf("boot config with a staged credential binding: %v", err)
	}
}

func TestMeshRoleBindingsIncludeCompiledRoles(t *testing.T) {
	for role := range meshRoles().reservedIdentities() {
		t.Run(role, func(t *testing.T) {
			cfg := meshConfigForLoad(t)
			cfg.Allowlist.Base = roleBase(t, pushDigestB, role, []string{"/usr/local/bin/c8s"})
			if _, err := loadMeshConfigDocument(t, cfg); err != nil {
				t.Fatalf("role %s refused at load: %v", role, err)
			}
		})
	}
}

// A component set in force binds a role exactly as the measured base does: the
// router namespace, which admits a platform role only under a declaration that
// pins its mounts, reads either binding, and none once the set has ended.
func TestComponentSetRoleGatesTheRouterNamespace(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	argv := []string{"/usr/local/bin/c8s", "router"}
	launch := componentLaunch(pushDigestB, argv)
	store := newPolicyStore(anyAllowlist(map[string]string{}), newTAClock(func() time.Time { return taTime }))
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	store.apply(componentDocument(t, retiring, componentContainer(t, pushDigestB, allowlist.RoleRouter, argv)), 1)
	p := &plugin{policy: store}
	gated := func() gatedContainer {
		role := p.roleOf(launch)
		return gatedContainer{
			role:         role,
			mountsPinned: p.bindsRoleMounts(launch, role),
			digest:       launch.Digest,
			argv:         launch.Argv,
		}
	}
	pod := &protectedPod{kubeNamespace: routerNamespace}

	if err := pod.requireRoleOnlyPod(gated()); err != nil {
		t.Fatalf("the router role the set binds does not run in its own namespace: %v", err)
	}

	taTime = deadline
	store.rebuildEndedSets()
	if err := pod.requireRoleOnlyPod(gated()); err == nil {
		t.Fatal("a launch the ended set alone bound still runs in the router namespace")
	}
}
