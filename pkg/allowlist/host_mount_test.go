package allowlist

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHostMountPolicy(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/config", Kind: MountHost, Source: "/etc/service", ReadOnly: true}}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := HostSourceDigest("/etc/service")
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := HostSourceDigest("/etc/other")
	if err != nil {
		t.Fatal(err)
	}
	good := ObservedMount{Destination: "/config", Class: MountHost, Storage: MountUnknown, HostSourceDigest: sourceDigest, ReadOnly: true}
	for _, tc := range []struct {
		name   string
		mutate func(*ObservedMount)
		want   bool
	}{
		{"pinned", func(*ObservedMount) {}, true},
		{"source", func(m *ObservedMount) { m.HostSourceDigest = otherDigest }, false},
		{"missing source", func(m *ObservedMount) { m.HostSourceDigest = "" }, false},
		{"destination", func(m *ObservedMount) { m.Destination = "/other" }, false},
		{"writable", func(m *ObservedMount) { m.ReadOnly = false }, false},
		{"class", func(m *ObservedMount) { m.Class = MountData }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := good
			tc.mutate(&m)
			if policy.admits([]ObservedMount{m}) != tc.want {
				t.Fatalf("unexpected admission for %+v", m)
			}
		})
	}
	encoded, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip ObservedMount
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !policy.admits([]ObservedMount{roundTrip}) {
		t.Fatal("serialized host evidence failed release matching")
	}
	if (mountConstraint{policy: &policy}).hostIndependent() {
		t.Fatal("pinned host content reported host-independent")
	}
	for _, source := range []string{"", "relative", "/etc/../service", "/etc/service/", "/etc/\x00service"} {
		policy.Rules[0].Source = source
		if err := normalizeMounts(&policy); err == nil {
			t.Errorf("accepted source %q", source)
		}
	}
	policy.Rules[0].Kind = MountEmptyDir
	policy.Rules[0].Source = "/etc/service"
	if err := normalizeMounts(&policy); err == nil {
		t.Fatal("accepted host fields on emptyDir")
	}
}

func TestHostSourceDigestRejectsInvalidPaths(t *testing.T) {
	for _, source := range []string{"", "relative", "/etc/../service", "/etc/service/", "/etc/\x00service"} {
		t.Run(source, func(t *testing.T) {
			if _, err := HostSourceDigest(source); err == nil {
				t.Fatalf("accepted invalid host source %q", source)
			}
		})
	}
}

func TestNodeRootFileMount(t *testing.T) {
	rule := MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountNodeRootFile, Source: "/usr/bin/nvidia-smi", ReadOnly: true}
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	digest, _ := HostSourceDigest(rule.Source)
	mount := ObservedMount{Destination: rule.Destination, Class: MountHost, HostSourceDigest: digest, ReadOnly: true, Provenance: ProvenanceNodeRoot}
	if !policy.admits([]ObservedMount{mount}) {
		t.Fatal("rejected measured-root evidence")
	}
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservedMount
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !policy.admits([]ObservedMount{decoded}) {
		t.Fatal("provenance lost during serialization")
	}
	for _, tc := range []struct {
		name   string
		change func(*ObservedMount)
	}{
		{"no evidence", func(m *ObservedMount) { m.Provenance = "" }},
		{"other provenance", func(m *ObservedMount) { m.Provenance = "dm-verity" }},
		{"writable bind", func(m *ObservedMount) { m.ReadOnly = false }},
		{"different source", func(m *ObservedMount) { m.HostSourceDigest = "other" }},
		{"not a host bind", func(m *ObservedMount) { m.Class = MountData }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := mount
			tc.change(&observed)
			if policy.admits([]ObservedMount{observed}) {
				t.Fatalf("admits(%+v) = true, want false", observed)
			}
		})
	}
	// A host rule stays path/mode-only when a node supplies evidence.
	policy.Rules[0].Kind = MountHost
	if !policy.admits([]ObservedMount{mount}) {
		t.Fatal("changed path-only host rule behavior")
	}
}

func TestNodeRootFileValidation(t *testing.T) {
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name string
		rule MountRule
		want string
	}{
		{"host verityDigest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: digest}, "verityDigest is not supported"},
		{"nodeRootFile verityDigest", MountRule{Kind: MountNodeRootFile, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: digest}, "verityDigest is not supported"},
		{"writable nodeRootFile", MountRule{Kind: MountNodeRootFile, Source: "/usr/bin/tool"}, "requires readOnly"},
		{"nodeRootFile without source", MountRule{Kind: MountNodeRootFile, ReadOnly: true}, "host source"},
		{"data verityDigest", MountRule{Kind: MountData, VerityDigest: digest}, "does not support"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.Destination = "/mnt/c8s-data/tools"
			policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{tc.rule}}
			if err := normalizeMounts(&policy); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("normalizeMounts(%+v) = %v, want error containing %q", tc.rule, err, tc.want)
			}
		})
	}
}

// An enforcer that predates a mount kind must refuse a served document that
// uses it, never fall back to a weaker rule. ParseServedJSON ignores unknown
// fields, so a node-root rule is a kind: an older parser reaches the same
// unsupported-kind refusal this future kind does.
func TestServedUnknownMountKindRefusesDocument(t *testing.T) {
	doc := `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + dApp + `","mounts":{"policy":"exact","rules":[` +
		`{"destination":"/usr/bin/tool","kind":"futureFile","source":"/usr/bin/tool","readOnly":true,"futureField":"x"}]}}]}}}`
	if al, err := ParseServedJSON([]byte(doc)); err == nil || !strings.Contains(err.Error(), `unsupported kind "futureFile"`) {
		t.Fatalf("ParseServedJSON(unknown kind) = %+v, %v, want unsupported kind error", al, err)
	}
	served := strings.Replace(doc, "futureFile", string(MountNodeRootFile), 1)
	if _, err := ParseServedJSON([]byte(served)); err != nil {
		t.Fatalf("ParseServedJSON(nodeRootFile) = %v", err)
	}
}

func TestNodeRootFileRuleIsNotPinnedForGrant(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/nvidia-smi", Kind: MountNodeRootFile, Source: "/usr/bin/nvidia-smi", ReadOnly: true}}}
	if (mountConstraint{policy: &policy}).hostIndependent() {
		t.Fatal("nodeRootFile rule reported host-independent, so a secrets grant would accept it")
	}
}

func TestAdmitsNodeRoot(t *testing.T) {
	const source = "/usr/bin/nvidia-smi"
	sourceDigest, err := HostSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := HostSourceDigest("/usr/bin/other")
	if err != nil {
		t.Fatal(err)
	}
	index := func(command ArgvPolicy, mounts MountPolicy) *Index {
		if err := normalizeMounts(&mounts); err != nil {
			t.Fatal(err)
		}
		return (&Allowlist{Workloads: map[string]Workload{"c": {Containers: []Container{{
			Digest: dig(t, dApp), Command: command, Args: ArgvPolicy{Policy: PolicyAny},
			Mounts: mounts, Env: EnvPolicy{Policy: PolicyAny},
		}}}}}).BuildIndex()
	}
	anyCommand := ArgvPolicy{Policy: PolicyAny}
	rule := MountRule{Destination: source, Kind: MountNodeRootFile, Source: source, ReadOnly: true}
	plain := rule
	plain.Kind = MountHost
	exact := MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}}
	verified := ObservedMount{Destination: source, Class: MountHost, Storage: MountUnknown, HostSourceDigest: sourceDigest, ReadOnly: true, Provenance: ProvenanceNodeRoot}
	for _, tc := range []struct {
		name   string
		index  *Index
		mutate func(*ObservedMount)
		want   bool
	}{
		{"exact nodeRootFile rule", index(anyCommand, exact), nil, true},
		{"mount policy any", index(anyCommand, MountPolicy{Policy: PolicyAny}), nil, false},
		{"host rule", index(anyCommand, MountPolicy{Policy: PolicyExact, Rules: []MountRule{plain}}), nil, false},
		{"entry refuses argv", index(ArgvPolicy{Policy: PolicyExact, Argv: []string{"/bin/app"}}, exact), nil, false},
		{"other source", index(anyCommand, exact), func(m *ObservedMount) { m.HostSourceDigest = otherDigest }, false},
		{"no observed provenance", index(anyCommand, exact), func(m *ObservedMount) { m.Provenance = "" }, false},
		{"no allowlist", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := verified
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			r := RunningContainer{Digest: dApp, Argv: []string{"/bin/other"}, Mounts: []ObservedMount{m}, Env: &EnvObservation{}}
			if got := tc.index.AdmitsNodeRoot(r, m); got != tc.want {
				t.Fatalf("AdmitsNodeRoot(%s) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}
