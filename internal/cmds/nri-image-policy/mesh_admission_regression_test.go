package nriimagepolicy

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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
				}
				_, _, err := gate.admissible(pod, ctr, gatedContainer{role: ctrCase.role})
				if (err != nil) != (user.GetUid() == 0) {
					t.Fatalf("admission error = %v for user %v", err, user)
				}
			})
		}
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
			caller, err := p.SandboxForPeer(workloadclaims.PeerForPID(4242))
			if err != nil {
				t.Fatal(err)
			}
			if caller.Refusal != nil {
				t.Fatalf("sandbox refused after readmission: %v", caller.Refusal)
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
	for _, omit := range []string{"base", "mesh"} {
		t.Run("no "+omit, func(t *testing.T) {
			cfg := meshConfigForLoad(t)
			if omit == "base" {
				cfg.Allowlist.Base = nil
			} else {
				cfg.Mesh = nil
			}
			if err := cfg.validateMeshRoleBindings(); err != nil {
				t.Fatalf("config without %s: %v", omit, err)
			}
		})
	}
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
