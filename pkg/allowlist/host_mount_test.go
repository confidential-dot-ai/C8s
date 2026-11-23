package allowlist

import (
	"encoding/json"
	"errors"
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
		{"fs-verity evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, strings.Repeat("b", 64) }},
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

func TestVerifiedFileValidation(t *testing.T) {
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		name string
		rule MountRule
		want string
	}{
		{"host verityDigest", MountRule{Kind: MountHost, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: digest}, "does not support verityDigest"},
		{"nodeRootFile verityDigest", MountRule{Kind: MountNodeRootFile, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: digest}, "does not support verityDigest"},
		{"writable nodeRootFile", MountRule{Kind: MountNodeRootFile, Source: "/usr/bin/tool"}, "requires readOnly"},
		{"nodeRootFile without source", MountRule{Kind: MountNodeRootFile, ReadOnly: true}, "host source"},
		{"data verityDigest", MountRule{Kind: MountData, VerityDigest: digest}, "does not support"},
		{"fsVerityFile without digest", MountRule{Kind: MountFSVerityFile, Source: "/usr/bin/tool", ReadOnly: true}, "64 lowercase hexadecimal"},
		{"short digest", MountRule{Kind: MountFSVerityFile, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: "abc"}, "64 lowercase hexadecimal"},
		{"uppercase digest", MountRule{Kind: MountFSVerityFile, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: strings.ToUpper(digest)}, "64 lowercase hexadecimal"},
		{"prefixed digest", MountRule{Kind: MountFSVerityFile, Source: "/usr/bin/tool", ReadOnly: true, VerityDigest: "sha256:" + digest}, "64 lowercase hexadecimal"},
		{"writable fsVerityFile", MountRule{Kind: MountFSVerityFile, Source: "/usr/bin/tool", VerityDigest: digest}, "requires readOnly"},
		{"fsVerityFile without source", MountRule{Kind: MountFSVerityFile, ReadOnly: true, VerityDigest: digest}, "host source"},
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
// fields, so node-root and fs-verity rules are kinds: an older parser reaches
// the same unsupported-kind refusal this future kind does.
func TestServedUnknownMountKindRefusesDocument(t *testing.T) {
	doc := `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + dApp + `","mounts":{"policy":"exact","rules":[` +
		`{"destination":"/usr/bin/tool","kind":"futureFile","source":"/usr/bin/tool","readOnly":true,"futureField":"x"}]}}]}}}`
	if al, err := ParseServedJSON([]byte(doc)); err == nil || !strings.Contains(err.Error(), `unsupported kind "futureFile"`) {
		t.Fatalf("ParseServedJSON(unknown kind) = %+v, %v, want unsupported kind error", al, err)
	}
	for _, kind := range []string{`"` + string(MountNodeRootFile) + `"`, `"` + string(MountFSVerityFile) + `","verityDigest":"` + strings.Repeat("b", 64) + `"`} {
		served := strings.Replace(doc, `"futureFile"`, kind, 1)
		if _, err := ParseServedJSON([]byte(served)); err != nil {
			t.Fatalf("ParseServedJSON(%s) = %v", kind, err)
		}
	}
}

func TestNodeRootFileRuleStaysHostDependent(t *testing.T) {
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/nvidia-smi", Kind: MountNodeRootFile, Source: "/usr/bin/nvidia-smi", ReadOnly: true}}}
	if (mountConstraint{policy: &policy}).hostIndependent() {
		t.Fatal("nodeRootFile rule reported host-independent; it still names a host path")
	}
}

// A secrets grant accepts a host file only when the node proves what the
// container reads and the container cannot write back (#934).
func TestMountRuleGrantPinned(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule MountRule
		want bool
	}{
		{"emptyDir", MountRule{Destination: "/models", Kind: MountEmptyDir}, true},
		{"data", MountRule{Destination: DataMountPrefix + "config", Kind: MountData}, true},
		{"nodeRootFile read-only", MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountNodeRootFile, Source: "/usr/bin/nvidia-smi", ReadOnly: true}, true},
		{"nodeRootFile writable", MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountNodeRootFile, Source: "/usr/bin/nvidia-smi"}, false},
		{"host read-only", MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountHost, Source: "/usr/bin/nvidia-smi", ReadOnly: true}, false},
		{"host writable", MountRule{Destination: "/usr/bin/nvidia-smi", Kind: MountHost, Source: "/usr/bin/nvidia-smi"}, false},
		{"fsVerityFile read-only", MountRule{Destination: "/usr/bin/tool", Kind: MountFSVerityFile, Source: "/opt/tools/tool", ReadOnly: true, VerityDigest: strings.Repeat("b", 64)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.behavior().grantPinned(); got != tc.want {
				t.Fatalf("grantPinned(%+v) = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}

// The NVIDIA CDI file set of a GPU worker, as nodeRootFile rules, passes a
// grant; an unproven host path and the writable persistenced socket do not.
func TestGPUWorkerGrantWithNodeRootCDIFiles(t *testing.T) {
	files := []string{
		"/lib/firmware/nvidia/595.71.05/gsp_ga10x.bin",
		"/usr/bin/nvidia-smi",
		"/usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05",
		"/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.71.05",
	}
	worker := func(extra ...MountRule) Workload {
		rules := []MountRule{{Destination: "/models", Kind: MountEmptyDir}}
		for _, f := range files {
			rules = append(rules, MountRule{Destination: f, Kind: MountNodeRootFile, Source: f, ReadOnly: true})
		}
		rules = append(rules, extra...)
		return Workload{Containers: []Container{{
			Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"python3"}},
			Args:    ArgvPolicy{Policy: PolicyExact, Argv: []string{"-m", "sglang.launch_server"}},
			Mounts:  MountPolicy{Policy: PolicyExact, Rules: rules},
		}}}
	}
	if err := worker().PinnedForGrant(); err != nil {
		t.Fatalf("nodeRootFile CDI files: PinnedForGrant = %v, want nil", err)
	}
	for name, extra := range map[string]MountRule{
		"unproven host path":  {Destination: "/opt/tools", Kind: MountHost, Source: "/opt/tools", ReadOnly: true},
		"persistenced socket": {Destination: "/run/nvidia-persistenced/socket", Kind: MountHost, Source: "/run/nvidia-persistenced/socket"},
	} {
		if err := worker(extra).PinnedForGrant(); !errors.Is(err, errGrantUnpinnedMounts) {
			t.Errorf("%s: PinnedForGrant = %v, want errGrantUnpinnedMounts", name, err)
		}
	}
}

// A host bind is granted only by a declaration that pins its launch and names it.
func TestGrantsHostBind(t *testing.T) {
	const source = "/usr/bin/nvidia-smi"
	sourceDigest, err := HostSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := HostSourceDigest("/usr/bin/other")
	if err != nil {
		t.Fatal(err)
	}
	env, err := ObserveEnv([]string{"PATH=/usr/bin"})
	if err != nil {
		t.Fatal(err)
	}
	declare := func(command ArgvPolicy, mounts MountPolicy, envPolicy EnvPolicy) Container {
		if err := normalizeMounts(&mounts); err != nil {
			t.Fatal(err)
		}
		return Container{
			Digest: dig(t, dApp), Command: command, Args: ArgvPolicy{Policy: PolicyDeny},
			Mounts: mounts, Env: envPolicy,
		}
	}
	index := func(declarations ...Container) *Index {
		return (&Allowlist{Workloads: map[string]Workload{"w": {Containers: declarations}}}).BuildIndex()
	}
	argv := []string{"/bin/app"}
	ownCommand := ArgvPolicy{Policy: PolicyExact, Argv: argv}
	otherCommand := ArgvPolicy{Policy: PolicyExact, Argv: []string{"/bin/other"}}
	pinnedEnv := EnvPolicy{Policy: PolicyExact, Values: map[string]string{"PATH": "/usr/bin"}}
	openEnv := EnvPolicy{Policy: PolicyAny}
	nodeRootRule := MountRule{Destination: source, Kind: MountNodeRootFile, Source: source, ReadOnly: true}
	hostRule := nodeRootRule
	hostRule.Kind = MountHost
	exact := func(rule MountRule) MountPolicy {
		return MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}}
	}
	open := MountPolicy{Policy: PolicyAny}
	hash := strings.Repeat("b", 64)
	fsVerityRule := nodeRootRule
	fsVerityRule.Kind, fsVerityRule.VerityDigest = MountFSVerityFile, hash
	measured := func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, hash }
	verified := ObservedMount{Destination: source, Class: MountHost, Storage: MountUnknown, HostSourceDigest: sourceDigest, ReadOnly: true, Provenance: ProvenanceNodeRoot}
	for _, tc := range []struct {
		name   string
		index  *Index
		mutate func(*ObservedMount)
		want   bool
	}{
		{"exact nodeRootFile rule", index(declare(ownCommand, exact(nodeRootRule), pinnedEnv)), nil, true},
		{"exact host rule", index(declare(ownCommand, exact(hostRule), pinnedEnv)), nil, true},
		{"host rule, writable bind", index(declare(ownCommand, exact(hostRule), pinnedEnv)), func(m *ObservedMount) { m.ReadOnly = false }, false},
		{"nodeRootFile rule, no provenance", index(declare(ownCommand, exact(nodeRootRule), pinnedEnv)), func(m *ObservedMount) { m.Provenance = "" }, false},
		{"host rule, other source", index(declare(ownCommand, exact(hostRule), pinnedEnv)), func(m *ObservedMount) { m.HostSourceDigest = otherDigest }, false},
		{"host rule, unlisted destination", index(declare(ownCommand, exact(hostRule), pinnedEnv)), func(m *ObservedMount) { m.Destination = "/app/verify" }, false},
		{"unconstrained environment", index(declare(ownCommand, exact(hostRule), openEnv)), nil, false},
		{"declaration refuses the argv", index(declare(otherCommand, exact(hostRule), pinnedEnv)), nil, false},
		{
			"a second declaration admits the launch, under mounts: any",
			index(declare(otherCommand, exact(hostRule), pinnedEnv), declare(ownCommand, open, pinnedEnv)),
			nil,
			false,
		},
		{"exact fsVerityFile rule", index(declare(ownCommand, exact(fsVerityRule), pinnedEnv)), measured, true},
		{"fsVerityFile rule, other digest", index(declare(ownCommand, exact(fsVerityRule), pinnedEnv)), func(m *ObservedMount) { measured(m); m.VerityDigest = strings.Repeat("a", 64) }, false},
		{"fsVerityFile rule, node-root evidence", index(declare(ownCommand, exact(fsVerityRule), pinnedEnv)), nil, false},
		{"nodeRootFile rule, fs-verity evidence", index(declare(ownCommand, exact(nodeRootRule), pinnedEnv)), measured, false},
		{"no allowlist", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := verified
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			r := RunningContainer{Digest: dApp, Argv: argv, Mounts: []ObservedMount{m}, Env: env}
			if got := tc.index.GrantsHostBind(r, m); got != tc.want {
				t.Fatalf("GrantsHostBind(%s) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}

func TestFSVerityFileMount(t *testing.T) {
	hash := strings.Repeat("b", 64)
	policy := MountPolicy{Policy: PolicyExact, Rules: []MountRule{{Destination: "/usr/bin/tool", Kind: MountFSVerityFile, Source: "/opt/tools/tool", ReadOnly: true, VerityDigest: hash}}}
	if err := normalizeMounts(&policy); err != nil {
		t.Fatal(err)
	}
	source, _ := HostSourceDigest("/opt/tools/tool")
	mount := ObservedMount{Destination: "/usr/bin/tool", Class: MountHost, HostSourceDigest: source, ReadOnly: true, Provenance: ProvenanceFSVerity, VerityDigest: hash}
	for _, tc := range []struct {
		name   string
		change func(*ObservedMount)
		want   bool
	}{
		{"pinned digest", func(*ObservedMount) {}, true},
		{"no evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = "", "" }, false},
		{"digest without provenance", func(m *ObservedMount) { m.Provenance = "" }, false},
		{"node-root evidence", func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceNodeRoot, "" }, false},
		{"other digest", func(m *ObservedMount) { m.VerityDigest = strings.Repeat("a", 64) }, false},
		{"other source", func(m *ObservedMount) { m.HostSourceDigest = "other" }, false},
		{"writable bind", func(m *ObservedMount) { m.ReadOnly = false }, false},
		{"not a host bind", func(m *ObservedMount) { m.Class = MountData }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := mount
			tc.change(&observed)
			if got := policy.admits([]ObservedMount{observed}); got != tc.want {
				t.Fatalf("admits(%+v) = %t, want %t", observed, got, tc.want)
			}
		})
	}
	encoded, err := json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ObservedMount
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != mount {
		t.Fatalf("round trip = %+v, %v, want %+v", decoded, err, mount)
	}
}

func TestIndexFSVerityMountRules(t *testing.T) {
	hash := strings.Repeat("b", 64)
	pinned := MountRule{Destination: "/usr/bin/tool", Kind: MountFSVerityFile, Source: "/opt/tools/tool", ReadOnly: true, VerityDigest: hash}
	plain := MountRule{Destination: "/usr/bin/other", Kind: MountHost, Source: "/opt/tools/other", ReadOnly: true}
	digest := mustDigest(t, "sha256:"+strings.Repeat("a", 64))
	al := &Allowlist{Workloads: map[string]Workload{"w": {Containers: []Container{{Digest: digest, Mounts: MountPolicy{Policy: PolicyExact, Rules: []MountRule{pinned, plain}}}}}}}
	idx := al.BuildIndex()
	for _, tc := range []struct {
		source, destination string
		want                bool
	}{
		{pinned.Source, pinned.Destination, true},
		{pinned.Source, plain.Destination, false},
		{plain.Source, plain.Destination, false},
	} {
		if got := idx.DeclaresFSVerityFile(tc.source, tc.destination); got != tc.want {
			t.Errorf("DeclaresFSVerityFile(%s, %s) = %t, want %t", tc.source, tc.destination, got, tc.want)
		}
	}
	if got := idx.FSVerityMountRules(digest.String()); len(got) != 1 || got[0] != pinned {
		t.Fatalf("FSVerityMountRules() = %+v, want [%+v]", got, pinned)
	}
	if got := idx.FSVerityMountRules("sha256:" + strings.Repeat("c", 64)); got != nil {
		t.Fatalf("FSVerityMountRules(other image) = %+v, want none", got)
	}
	var none *Index
	if none.DeclaresFSVerityFile(pinned.Source, pinned.Destination) || none.FSVerityMountRules(digest.String()) != nil {
		t.Fatal("nil index reported fs-verity rules")
	}
}

// A deferred digest is a matching phase of the node's create-time validation,
// never evidence: nothing serializes it and workload matching ignores it.
func TestDeferVerity(t *testing.T) {
	const source, destination = "/opt/tools/tool", "/usr/bin/tool"
	hash := strings.Repeat("b", 64)
	sourceDigest, err := HostSourceDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	unproven := ObservedMount{Destination: destination, Class: MountHost, HostSourceDigest: sourceDigest, ReadOnly: true}
	fsVerity := MountRule{Destination: destination, Kind: MountFSVerityFile, Source: source, ReadOnly: true, VerityDigest: hash}
	nodeRoot := MountRule{Destination: destination, Kind: MountNodeRootFile, Source: source, ReadOnly: true}
	allowlistFor := func(rule MountRule) *Allowlist {
		al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"w": {Containers: []Container{{
			Digest:  dig(t, dApp),
			Command: ArgvPolicy{Policy: PolicyAny},
			Args:    ArgvPolicy{Policy: PolicyAny},
			Mounts:  MountPolicy{Policy: PolicyExact, Rules: []MountRule{rule}},
		}}}}}
		if err := al.Normalize(); err != nil {
			t.Fatal(err)
		}
		return al
	}
	for _, tc := range []struct {
		name     string
		rule     MountRule
		mutate   func(*ObservedMount)
		deferred bool
		want     bool
	}{
		{"measured digest", fsVerity, func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, hash }, false, true},
		{"no evidence", fsVerity, nil, false, false},
		{"deferred, no evidence", fsVerity, nil, true, true},
		{"deferred, measured digest", fsVerity, func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, hash }, true, true},
		{"deferred, writable bind", fsVerity, func(m *ObservedMount) { m.ReadOnly = false }, true, false},
		{"deferred, other source", fsVerity, func(m *ObservedMount) { m.HostSourceDigest = "other" }, true, false},
		{"deferred, node-root evidence", fsVerity, func(m *ObservedMount) { m.Provenance = ProvenanceNodeRoot }, true, false},
		{"deferred, other measured digest", fsVerity, func(m *ObservedMount) { m.Provenance, m.VerityDigest = ProvenanceFSVerity, strings.Repeat("a", 64) }, true, false},
		{"deferred, nodeRootFile rule", nodeRoot, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := unproven
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			r := RunningContainer{Digest: dApp, Argv: []string{"/bin/app"}, Mounts: []ObservedMount{m}}
			if tc.deferred {
				r = r.DeferVerity()
			}
			if got := allowlistFor(tc.rule).BuildIndex().AdmitsContainer(r); got != tc.want {
				t.Fatalf("AdmitsContainer(%+v) = %t, want %t", m, got, tc.want)
			}
		})
	}

	al := allowlistFor(fsVerity)
	deferred := RunningContainer{Digest: dApp, Argv: []string{"/bin/app"}, Mounts: []ObservedMount{unproven}}.DeferVerity()
	if got := al.BuildIndex().Mismatch(deferred, true); len(got) != 0 {
		t.Fatalf("Mismatch(deferred) = %v, want none", got)
	}
	if name, _, err := al.MatchWorkload([]RunningContainer{deferred}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("MatchWorkload(deferred) = %q, %v, want %v", name, err, ErrNoMatch)
	}
	if diff := al.Workloads["w"].Diff([]RunningContainer{deferred}); diff.Describes() {
		t.Fatal("Diff(deferred) describes the launch, want no match")
	}
	plain, err := json.Marshal(RunningContainer{Digest: dApp, Mounts: []ObservedMount{unproven}})
	if err != nil {
		t.Fatal(err)
	}
	if encoded, err := json.Marshal(RunningContainer{Digest: dApp, Mounts: []ObservedMount{unproven}}.DeferVerity()); err != nil || string(encoded) != string(plain) {
		t.Fatalf("json.Marshal(deferred) = %s, %v, want %s", encoded, err, plain)
	}
}

// The grant answers only for a mount the launch carries.
func TestGrantsHostBindNeedsTheLaunchToCarryTheMount(t *testing.T) {
	env, err := ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"/bin/app"}
	index := (&Allowlist{Workloads: map[string]Workload{"w": {Containers: []Container{{
		Digest: dig(t, dApp), Command: ArgvPolicy{Policy: PolicyExact, Argv: argv},
		Args: ArgvPolicy{Policy: PolicyDeny}, Mounts: MountPolicy{Policy: PolicyDeny},
		Env: EnvPolicy{Policy: PolicyDeny},
	}}}}}).BuildIndex()
	r := RunningContainer{Digest: dApp, Argv: argv, Mounts: []ObservedMount{}, Env: env}
	m := ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: MountHost, ReadOnly: true}
	if index.GrantsHostBind(r, m) {
		t.Fatal("GrantsHostBind(a mount the launch does not carry) = true, want false")
	}
}
