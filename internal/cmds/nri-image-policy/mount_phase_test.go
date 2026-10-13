package nriimagepolicy

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestMountAdmissionUsesFinalStartSpec(t *testing.T) {
	const platformSource = kubeletRoot + "/pods/pod-uid/etc-hosts"
	for _, tc := range []struct {
		name, initialSource, finalSource string
		policy                           allowlist.MountPolicy
		want                             bool
	}{
		{"platform baseline", platformSource, platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, true},
		{"later host injection", platformSource, "/host/hosts", allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, false},
		{"later foreign pod injection", platformSource, kubeletRoot + "/pods/another-pod/etc-hosts", allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, false},
		{"later correction", "/host/hosts", platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyDeny}, true},
		{"explicit unrestricted mounts", platformSource, "/host/hosts", allowlist.MountPolicy{Policy: allowlist.PolicyAny}, true},
		{"exact rule missing", platformSource, platformSource, allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/cache", Kind: allowlist.MountEmptyDir}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = tc.policy
			p, _ := newCachedPlugin(&config{
				Policy:    policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}},
			}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			pod.Uid = "pod-uid"
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			ctr.Mounts = []*api.Mount{{Source: tc.initialSource, Destination: "/etc/hosts", Type: "bind"}}
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatalf("preliminary admission considered unfinished mount table: %v", err)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("preliminary mount evidence recorded")
			}
			ctr.Mounts = []*api.Mount{{Source: tc.finalSource, Destination: "/etc/hosts", Type: "bind"}}
			err := p.StartContainer(context.Background(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("final admission error=%v, want allowed=%v", err, tc.want)
			}
			_, containers, _, inventoryErr := p.inventory.DigestsForSandbox(pod.Id)
			if !tc.want {
				if len(containers) != 0 {
					t.Fatal("denied final mount table recorded as admitted")
				}
				return
			}
			if inventoryErr != nil || len(containers) != 1 || len(containers[0].Mounts) != 1 {
				t.Fatalf("missing final mount evidence: containers=%+v error=%v", containers, inventoryErr)
			}
			wantClass := allowlist.MountHost
			if tc.finalSource == platformSource {
				wantClass = allowlist.MountPlatform
			}
			if got := containers[0].Mounts[0]; got.Destination != "/etc/hosts" || got.Class != wantClass || got.Storage != allowlist.MountUnknown {
				t.Fatalf("final mount evidence=%+v, want /etc/hosts %s/unknown", got, wantClass)
			}
		})
	}
}

func TestExactHostMountAdmissionUsesFinalStartSpec(t *testing.T) {
	for _, tc := range []struct {
		name, source, destination string
		options                   []string
		policyReadOnly, allowed   bool
	}{
		{"read-only", "/etc/service", "/config", []string{"rbind", "ro"}, true, true},
		{"writable", "/etc/service", "/config", []string{"rw"}, false, true},
		{"default writable", "/etc/service", "/config", nil, false, true},
		{"last read-only", "/etc/service", "/config", []string{"rw", "ro"}, true, true},
		{"last writable", "/etc/service", "/config", []string{"ro", "rw"}, false, true},
		{"source mismatch", "/etc/other", "/config", []string{"ro"}, true, false},
		{"destination mismatch", "/etc/service", "/other", []string{"ro"}, true, false},
		{"writable mismatch", "/etc/service", "/config", []string{"rw"}, true, false},
		{"read-only mismatch", "/etc/service", "/config", []string{"ro"}, false, false},
		{"missing source", "", "/config", []string{"ro"}, true, false},
		{"relative source", "service", "/config", []string{"ro"}, true, false},
		{"unclean source", "/etc/../etc/service", "/config", []string{"ro"}, true, false},
		{"NUL source", "/etc/service\x00", "/config", []string{"ro"}, true, false},
		{"recursive read-only", "/etc/service", "/config", []string{"rro", "ro"}, true, false},
		{"recursive writable", "/etc/service", "/config", []string{"rrw", "rw"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{
				{Destination: "/config", Kind: allowlist.MountHost, Source: "/etc/service", ReadOnly: tc.policyReadOnly},
			}}
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{
				Policy:    policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}},
			}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
				t.Fatalf("preliminary admission: %v", err)
			}
			ctr.Mounts = []*api.Mount{{Type: "bind", Source: tc.source, Destination: tc.destination, Options: tc.options}}
			err := p.StartContainer(t.Context(), pod, ctr)
			if (err == nil) != tc.allowed {
				t.Fatalf("final admission error=%v, want allowed=%v", err, tc.allowed)
			}
			_, containers, _, inventoryErr := p.inventory.DigestsForSandbox(pod.Id)
			if !tc.allowed {
				if len(containers) != 0 {
					t.Fatal("denied host mount recorded as admitted")
				}
				return
			}
			if inventoryErr != nil || len(containers) != 1 || len(containers[0].Mounts) != 1 {
				t.Fatalf("missing final evidence: containers=%+v error=%v", containers, inventoryErr)
			}
			digest, err := allowlist.HostSourceDigest("/etc/service")
			if err != nil {
				t.Fatal(err)
			}
			mount := containers[0].Mounts[0]
			if mount.Class != allowlist.MountHost || mount.Destination != "/config" || mount.HostSourceDigest != digest || mount.ReadOnly != tc.policyReadOnly {
				t.Fatalf("unexpected final host evidence: %+v", mount)
			}
			c := containers[0]
			name, _, err := al.MatchWorkload([]allowlist.RunningContainer{{Digest: c.Digest, Argv: c.Argv, Env: c.Env, Mounts: c.Mounts}})
			if err != nil || name != "w" {
				t.Fatalf("recorded host evidence did not match workload: name=%q error=%v", name, err)
			}
		})
	}
}

func TestConfinedMountAdmissionUsesFinalStartSpec(t *testing.T) {
	policy := allowlist.MountPolicy{Policy: allowlist.PolicyConfined, DenyBelow: []string{"/bin", "/etc/ld.so.preload"}, Unconfined: []string{"/run/xtables.lock"}}
	for _, tc := range []struct {
		name    string
		mount   *api.Mount
		allowed bool
	}{
		{"read-only host path", &api.Mount{Type: "bind", Source: "/etc/service", Destination: "/config", Options: []string{"rbind", "ro"}}, true},
		{"writable host path", &api.Mount{Type: "bind", Source: "/etc/service", Destination: "/config", Options: []string{"rbind", "rw"}}, false},
		{"writable host path at an unconfined destination", &api.Mount{Type: "bind", Source: "/run/xtables.lock", Destination: "/run/xtables.lock", Options: []string{"rw"}}, true},
		{"read-only host path over a denied directory", &api.Mount{Type: "bind", Source: "/etc/service", Destination: "/bin", Options: []string{"ro"}}, false},
		{"read-only host path over the loader preload list", &api.Mount{Type: "bind", Source: "/etc/service", Destination: "/etc", Options: []string{"ro"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = policy
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{
				Policy:    policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}},
			}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
				t.Fatalf("preliminary admission: %v", err)
			}
			ctr.Mounts = []*api.Mount{tc.mount}
			if err := p.StartContainer(t.Context(), pod, ctr); (err == nil) != tc.allowed {
				t.Fatalf("StartContainer(%s) error = %v, want allowed = %v", tc.mount.Destination, err, tc.allowed)
			}
		})
	}
}
