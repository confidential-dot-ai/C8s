package nriimagepolicy

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"
)

func TestMeshGateRequiresNonrootContainers(t *testing.T) {
	for _, ctrCase := range []struct {
		name string
		role string
		uid  uint32
	}{
		{
			name: "app",
			uid:  testWorkloadUID,
		},
		{
			name: "init",
			uid:  testWorkloadUID,
		},
		{
			name: "c8s-mesh",
			role: meshRole,
			uid:  testMeshUID,
		},
		{
			name: "c8s-cert",
			role: testCertRole,
			uid:  testCertUID,
		},
	} {
		for _, user := range []*api.User{nil, {Uid: 0}, {Uid: ctrCase.uid}} {
			t.Run(ctrCase.name+"/"+user.String(), func(t *testing.T) {
				pod := meshPod("default", "pod", testNetNS)
				gate, state := gateWithPod(pod)
				state.meshStarted = true
				ctr := &api.Container{
					Name: ctrCase.name,
					User: user,
					Linux: &api.LinuxContainer{
						Namespaces: []*api.LinuxNamespace{{Type: pidNamespace}},
					},
				}
				_, _, err := gate.admissible(pod, ctr, gatedContainer{role: ctrCase.role})
				if (err != nil) != (user.GetUid() == 0) {
					t.Fatalf("admission error = %v for user %v", err, user)
				}
			})
		}
	}
}

// A pod CVM runs one pod, so its gate admits a root workload container. A
// role's container still runs as its reserved uid, and no container claims
// an identity reserved for a role it does not hold.
func TestPodGateAdmitsRootWorkloads(t *testing.T) {
	policy := *meshRoles()
	policy.Pod = &podMeshPolicy{}
	pod := meshPod("default", "pod", testNetNS)
	gate := newMeshGate(policy, slog.Default())
	gate.pods[pod.GetId()] = &protectedPod{
		netns:         testNamespace(),
		kubeNamespace: pod.GetNamespace(),
		meshStarted:   true,
	}
	for _, tc := range []struct {
		name     string
		role     string
		user     *api.User
		admitted bool
	}{
		{name: "root app", user: &api.User{Uid: 0}, admitted: true},
		{name: "root app in the mesh group", user: &api.User{Uid: 0, Gid: testMeshUID}},
		{name: "app claiming the mesh uid", user: &api.User{Uid: testMeshUID}},
		{name: "root endpoint", role: meshRole, user: &api.User{Uid: 0}},
		{name: "endpoint", role: meshRole, user: &api.User{Uid: testMeshUID}, admitted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := &api.Container{
				Name: tc.name,
				User: tc.user,
				Linux: &api.LinuxContainer{
					Namespaces: []*api.LinuxNamespace{{Type: pidNamespace}},
				},
			}
			_, _, err := gate.admissible(pod, ctr, gatedContainer{role: tc.role})
			if (err == nil) != tc.admitted {
				t.Fatalf("admission error = %v, want admitted %v", err, tc.admitted)
			}
		})
	}
}

func TestInitializingDenialDoesNotRefuseSandbox(t *testing.T) {
	for _, phase := range []string{"create", "start"} {
		t.Run(phase, func(t *testing.T) {
			p, store := newCachedPlugin(&config{
				Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "image-a"})},
				Policy:    policyConfig{Mode: ModeFailClosed},
			}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
			pod := meshPod("default", "pod", testNetNS)
			procRoot := t.TempDir()
			p.inventory = newAdmissionInventory(procRoot)
			p.inventory.record(cidGetCert, pod.GetId(), "c8s-cert", digestOther, nil, nil)
			writeCgroup(t, procRoot, 4242, cidGetCert)
			ctr := makeCtrWithImage(pod.GetId(), "app", "registry/repo@"+pushDigestB)
			var err error
			if phase == "create" {
				_, _, err = p.CreateContainer(context.Background(), pod, ctr)
			} else {
				err = p.StartContainer(context.Background(), pod, ctr)
			}
			if err == nil || !strings.Contains(err.Error(), "initializing") {
				t.Fatalf("initial admission = %v, want initializing denial", err)
			}
			if refusal := p.inventory.denial(pod.GetId()); refusal != nil {
				t.Errorf("initializing denial persisted: %v", refusal)
			}
			store.apply(anyAllowlist(map[string]string{pushDigestB: "image-b"}), 2)
			p.SetReady()
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("retry creation: %v", err)
			}
			if err := p.StartContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("retry start: %v", err)
			}
			if refusal := p.inventory.denial(pod.GetId()); refusal != nil {
				t.Fatalf("the initializing denial held after readmission: %v", refusal)
			}
		})
	}
}

func TestMeshConfigRejectsUnboundBaseRoles(t *testing.T) {
	for _, role := range []string{"", meshRole, testCertRole, "unknown-role"} {
		t.Run(role, func(t *testing.T) {
			cfg := meshConfigForLoad(t)
			cfg.Allowlist.Base = roleBase(t, pushDigestB, role, []string{"/usr/local/bin/c8s"})
			_, err := loadMeshConfigDocument(t, cfg)
			if role == "unknown-role" {
				if err == nil || !strings.Contains(err.Error(), role) {
					t.Fatalf("load = %v, want unbound role error", err)
				}
			} else if err != nil {
				t.Fatalf("valid role refused: %v", err)
			}
		})
	}
	t.Run("no base", func(t *testing.T) {
		cfg := meshConfigForLoad(t)
		cfg.Allowlist.Base = nil
		if err := cfg.validateMeshRoleBindings(); err != nil {
			t.Fatalf("config without a base: %v", err)
		}
	})
}

func TestMeshConfigRejectsInvalidRulesetInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*meshPolicy)
	}{
		{
			name: "outbound equals inbound",
			change: func(p *meshPolicy) {
				p.Capture.Inbound = p.Capture.Outbound
			},
		},
		{
			name: "outbound equals health",
			change: func(p *meshPolicy) {
				p.Capture.Health = p.Capture.Outbound
			},
		},
		{
			name: "inbound equals health",
			change: func(p *meshPolicy) {
				p.Capture.Health = p.Capture.Inbound
			},
		},
		{
			name: "mesh uid zero",
			change: func(p *meshPolicy) {
				p.Roles[0].UID = 0
			},
		},
		{
			name: "credential uid zero",
			change: func(p *meshPolicy) {
				p.Roles[1].UID = 0
			},
		},
		{
			name: "destination port zero",
			change: func(p *meshPolicy) {
				p.Roles[1].Destinations = append(p.Roles[1].Destinations, netip.MustParseAddrPort("10.43.0.6:0"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := meshConfigForLoad(t)
			tc.change(cfg.Mesh)
			if _, err := loadMeshConfigDocument(t, cfg); err == nil {
				t.Fatal("invalid ruleset policy loaded")
			}
		})
	}
}

func meshConfigForLoad(t *testing.T) *config {
	t.Helper()
	return &config{
		Allowlist: allowlistConfig{
			Base:    roleBase(t, pushDigestB, testCertRole, []string{"/usr/local/bin/c8s"}),
			NodeTCB: true,
		},
		Policy: policyConfig{
			Mode:            ModeFailClosed,
			EnforceExisting: true,
			FatalExisting:   true,
			BootMarkerPath:  "/run/nri-image-policy/registered",
		},
		Mesh: meshRoles(),
	}
}

func meshConfigDocument(t *testing.T, cfg *config) []byte {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
