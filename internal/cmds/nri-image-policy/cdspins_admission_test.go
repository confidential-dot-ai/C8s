package nriimagepolicy

import (
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestNodePolicyMountAdmission(t *testing.T) {
	const pins = "/run/node-cds-policy.json"
	const address = "/run/node-cds-address"
	for _, tc := range []struct {
		name        string
		destination string
		source      string
		consumer    string
		options     []string
		injected    bool
		allowed     bool
	}{
		{
			name:     "node pins without inventory sockets",
			source:   pins,
			consumer: workloadclaims.CertContainerName,
			options:  []string{"rbind", "ro"},
			injected: true,
			allowed:  true,
		},
		{
			name:     "foreign pins",
			source:   "/other-node/pins.json",
			consumer: workloadclaims.CertContainerName,
			options:  []string{"rbind", "ro"},
			injected: true,
		},
		{
			name:     "writable pins",
			source:   pins,
			consumer: workloadclaims.CertContainerName,
			options:  []string{"rbind", "rw"},
			injected: true,
		},
		{
			name:     "application pins",
			source:   pins,
			consumer: "app",
			options:  []string{"rbind", "ro"},
			injected: true,
		},
		{
			name:     "uninjected pins",
			source:   pins,
			consumer: workloadclaims.CertContainerName,
			options:  []string{"rbind", "ro"},
		},
		{
			name:        "node address without inventory sockets",
			destination: workloadclaims.CDSAddressPath,
			source:      address,
			consumer:    workloadclaims.CertContainerName,
			options:     []string{"rbind", "ro"},
			injected:    true,
			allowed:     true,
		},
		{
			name:        "foreign address",
			destination: workloadclaims.CDSAddressPath,
			source:      "/other-node/address",
			consumer:    workloadclaims.CertContainerName,
			options:     []string{"rbind", "ro"},
			injected:    true,
		},
		{
			name:        "writable address",
			destination: workloadclaims.CDSAddressPath,
			source:      address,
			consumer:    workloadclaims.CertContainerName,
			options:     []string{"rbind", "rw"},
			injected:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{
				Policy: allowlist.PolicyExact,
				Rules: []allowlist.MountRule{
					{
						Destination: "/cache",
						Kind:        allowlist.MountHost,
						Source:      "/etc/service",
						ReadOnly:    true,
					},
				},
			}
			p, _ := newCachedPlugin(&config{
				Policy: policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{
					Pull: pullConfig{URL: "https://cds"},
				},
			}, al)
			p.SetReady()
			p.cdsPins = pins
			p.cdsAddress = address
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			pod.Uid = "pod-uid"
			if tc.injected {
				pod.Annotations = map[string]string{workloadclaims.AnnotationInjected: "true"}
			}
			ctr := makeCtrWithImage(pod.Id, tc.consumer, "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app"}
			cache := &api.Mount{
				Source:      "/etc/service",
				Destination: "/cache",
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			}
			destination := tc.destination
			if destination == "" {
				destination = workloadclaims.CDSPinsPath
			}
			policy := &api.Mount{
				Source:      tc.source,
				Destination: destination,
				Type:        "bind",
				Options:     tc.options,
			}
			ctr.Mounts = []*api.Mount{cache}
			err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{
				Pod:       pod,
				Container: ctr,
				Adjust:    &api.ContainerAdjustment{Mounts: []*api.Mount{policy}},
			})
			if (err == nil) != tc.allowed {
				t.Errorf("adjustment admission error=%v, want allowed=%v", err, tc.allowed)
			}
			ctr.Mounts = append(ctr.Mounts, policy)
			err = p.StartContainer(t.Context(), pod, ctr)
			if (err == nil) != tc.allowed {
				t.Fatalf("start admission error=%v, want allowed=%v", err, tc.allowed)
			}
			if !tc.allowed {
				return
			}
			_, containers, _, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || len(containers) != 1 || len(containers[0].Mounts) != 2 {
				t.Fatalf("inventory=%+v, error=%v", containers, err)
			}
			mount := containers[0].Mounts[1]
			if mount.Destination != destination || mount.Class != allowlist.MountPlatform || !mount.ReadOnly {
				t.Fatalf("node policy inventory evidence=%+v", mount)
			}
		})
	}
}
