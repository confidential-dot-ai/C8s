package allowlist

import (
	"strings"
	"testing"
)

// hostDigest stands in for the source commitment the observer records for a
// host path whose mount options it fully read.
const hostDigest = "3b2e1f"

func TestObservedMountConfined(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mount ObservedMount
		want  bool
	}{
		{"platform", ObservedMount{Class: MountPlatform, Storage: MountUnknown}, true},
		{"read-only host path", ObservedMount{Class: MountHost, ReadOnly: true, HostSourceDigest: hostDigest}, true},
		{"read-only host path without a source commitment", ObservedMount{Class: MountHost, ReadOnly: true}, false},
		{"writable host path", ObservedMount{Class: MountHost, HostSourceDigest: hostDigest}, false},
		{"memory emptyDir", ObservedMount{Class: MountEmptyDir, Storage: MountMemory}, true},
		{"encrypted emptyDir", ObservedMount{Class: MountEmptyDir, Storage: MountEncrypted}, true},
		{"disk emptyDir", ObservedMount{Class: MountEmptyDir, Storage: MountUnknown}, false},
		{"read-only disk emptyDir", ObservedMount{Class: MountEmptyDir, Storage: MountUnknown, ReadOnly: true}, false},
		{"memory data", ObservedMount{Class: MountData, Storage: MountMemory}, true},
		{"encrypted data", ObservedMount{Class: MountData, Storage: MountEncrypted}, true},
		{"unprotected data", ObservedMount{Class: MountData, Storage: MountUnknown}, false},
		{"unknown class", ObservedMount{Class: "tmpfs", Storage: MountMemory}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.mount.Confined(); got != tc.want {
				t.Fatalf("%+v.Confined() = %v, want %v", tc.mount, got, tc.want)
			}
		})
	}
}

func TestConfinedMountPolicyAdmits(t *testing.T) {
	policy := MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/app", "/etc/ld.so.preload"}, Unconfined: []string{"/data"}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	platform := ObservedMount{Destination: "/etc/hosts", Class: MountPlatform}
	memory := func(destination string) ObservedMount {
		return ObservedMount{Destination: destination, Class: MountEmptyDir, Storage: MountMemory}
	}
	for _, tc := range []struct {
		name   string
		mounts []ObservedMount
		want   bool
	}{
		{"no evidence", nil, false},
		{"no mounts", []ObservedMount{}, true},
		{"platform only", []ObservedMount{platform}, true},
		{"confined volume", []ObservedMount{platform, memory("/tmp")}, true},
		{"read-only host path", []ObservedMount{{Destination: "/config", Class: MountHost, ReadOnly: true, HostSourceDigest: hostDigest}}, true},
		{"writable host path", []ObservedMount{{Destination: "/config", Class: MountHost}}, false},
		{"disk emptyDir", []ObservedMount{{Destination: "/cache", Class: MountEmptyDir, Storage: MountUnknown}}, false},
		{"unprotected data", []ObservedMount{{Destination: "/cache", Class: MountData, Storage: MountUnknown}}, false},
		{"writable host path at an unconfined destination", []ObservedMount{{Destination: "/data", Class: MountHost}}, true},
		{"unprotected data at an unconfined destination", []ObservedMount{{Destination: "/data", Class: MountData, Storage: MountUnknown}}, true},
		{"unconfined match is exact", []ObservedMount{{Destination: "/data/sub", Class: MountHost}}, false},
		{"at a denied path", []ObservedMount{memory("/app")}, false},
		{"below a denied path", []ObservedMount{memory("/app/lib")}, false},
		{"above a denied path", []ObservedMount{memory("/etc")}, false},
		{"at the root", []ObservedMount{memory("/")}, false},
		{"beside a denied path", []ObservedMount{memory("/app2"), memory("/etc/ld.so.preload.d")}, true},
		{"unclean destination below a denied path", []ObservedMount{memory("/app//lib/")}, false},
		{"relative destination", []ObservedMount{memory("app")}, false},
		{"platform class at a denied path", []ObservedMount{{Destination: "/app", Class: MountPlatform}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.admits(tc.mounts); got != tc.want {
				t.Fatalf("admits(%+v) = %v, want %v", tc.mounts, got, tc.want)
			}
		})
	}
}

func TestNormalizeConfinedMountPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  MountPolicy
		want    MountPolicy
		wantErr string
	}{
		{name: "sorted and deduplicated",
			policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/usr", "/app", "/usr"}, Unconfined: []string{"/b", "/a"}},
			want:   MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/app", "/usr"}, Unconfined: []string{"/a", "/b"}}},
		{name: "empty lists", policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{}}, want: MountPolicy{Policy: PolicyConfined}},
		{name: "relative denyBelow", policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"usr"}}, wantErr: "clean absolute"},
		{name: "unclean denyBelow", policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/usr/"}}, wantErr: "clean absolute"},
		{name: "unclean unconfined", policy: MountPolicy{Policy: PolicyConfined, Unconfined: []string{"/a/../b"}}, wantErr: "clean absolute"},
		{name: "unconfined below denyBelow", policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/usr"}, Unconfined: []string{"/usr/local"}}, wantErr: "overlaps"},
		{name: "unconfined above denyBelow", policy: MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/etc/ssl"}, Unconfined: []string{"/etc"}}, wantErr: "overlaps"},
		{name: "rules", policy: MountPolicy{Policy: PolicyConfined, Rules: emptyDirRules("/x")}, wantErr: "no rules"},
		{name: "denyBelow under any", policy: MountPolicy{Policy: PolicyAny, DenyBelow: []string{"/usr"}}, wantErr: "no denyBelow"},
		{name: "unconfined under exact", policy: MountPolicy{Policy: PolicyExact, Rules: emptyDirRules("/x"), Unconfined: []string{"/y"}}, wantErr: "no denyBelow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy
			err := normalizeMounts(&got)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("normalizeMounts(%+v) error = %v, want %q", tc.policy, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMounts(%+v): %v", tc.policy, err)
			}
			if policyKey(Container{Mounts: got}) != policyKey(Container{Mounts: tc.want}) {
				t.Fatalf("normalizeMounts(%+v) = %+v, want %+v", tc.policy, got, tc.want)
			}
		})
	}
}

// Confined admits whatever read-only host path a pod declares, so it is
// neither host-independent nor unconstrained.
func TestConfinedMountPolicyIsConstrainedButHostDependent(t *testing.T) {
	c := Container{
		Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/app"}},
		Args:    ArgvPolicy{Policy: PolicyExact, Argv: []string{"serve"}},
		Mounts:  MountPolicy{Policy: PolicyConfined, DenyBelow: []string{"/app"}},
		Env:     EnvPolicy{Policy: PolicyDeny},
	}
	if c.IsUnconstrained() {
		t.Error("IsUnconstrained() = true, want false")
	}
	if (Workload{Containers: []Container{c}}).HostIndependent() {
		t.Error("HostIndependent() = true, want false")
	}
}

// The pinned executable is checked under confined as under any: a denyBelow
// list that omits it does not let a volume replace it.
func TestConfinedPolicyChecksTheExecutable(t *testing.T) {
	index := (&Allowlist{Workloads: map[string]Workload{"c": {Containers: []Container{{
		Digest:  dig(t, dApp),
		Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/app/c8s"}},
		Args:    ArgvPolicy{Policy: PolicyAny},
		Mounts:  MountPolicy{Policy: PolicyConfined},
		Env:     EnvPolicy{Policy: PolicyAny},
	}}}}}).BuildIndex()
	over := []ObservedMount{{Destination: "/app", Class: MountData, Storage: MountMemory}}
	if index.AdmitsContainer(RunningContainer{Digest: dApp, Argv: []string{"/app/c8s"}, Mounts: over, Env: &EnvObservation{}}) {
		t.Fatal("AdmitsContainer(mount over the executable) = true, want false")
	}
}
