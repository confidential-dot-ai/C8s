package allowlist

import (
	"slices"
	"strings"
	"testing"
)

func TestIndex_AnyArgvEntryAdmitsAnyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsDigest(digestA) {
		t.Fatal("digest not admitted")
	}
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/anything", "--dynamic"}}) {
		t.Fatal("an any/any entry must admit the digest regardless of argv")
	}
}

// A multi-token command is matched as an exact prefix; args:any leaves the rest
// free. This is the case an entrypoint like "/docker-entrypoint.sh nginx" needs.
func TestIndex_MultiTokenCommandPrefix(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/docker-entrypoint.sh","nginx"]},
		 "args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}}) {
		t.Fatal("argv starting with the command prefix should be admitted")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/docker-entrypoint.sh"}}) {
		t.Fatal("argv shorter than the command prefix must be rejected")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/bin/sh", "nginx", "-g"}}) {
		t.Fatal("a different prefix must be rejected")
	}
}

func TestIndex_FullExact(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"exact","argv":["--serve","--port=8080"]}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/app", "--serve", "--port=8080"}}) {
		t.Fatal("exact command+args should match the concatenation")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/bin/sh", "--serve", "--port=8080"}}) {
		t.Fatal("a swapped command must be rejected")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/app", "--serve"}}) {
		t.Fatal("truncated args must be rejected")
	}
}

func TestIndex_ArgsDenyMeansNoArgs(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/app"}}) {
		t.Fatal("args:deny should admit the command with no extra args")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/app", "--exfil"}}) {
		t.Fatal("args:deny must reject any extra args")
	}
}

func TestIndex_CommandDenyMeansEmptyArgv(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"deny"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: nil}) {
		t.Fatal("command:deny should admit an empty argv")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"/bin/sh"}}) {
		t.Fatal("command:deny must reject any argv")
	}
}

// A shared digest may run under several command/args policies; admission is the
// union across entries.
func TestIndex_SharedDigestUnion(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"a":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","sleep"]},"args":{"policy":"exact","argv":["1"]}}]},
		"b":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["busybox","echo"]},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"busybox", "sleep", "1"}}) {
		t.Fatal("first entry's argv should be admitted")
	}
	if !idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"busybox", "echo", "hi"}}) {
		t.Fatal("second entry's argv should be admitted")
	}
	if idx.AdmitsContainer(RunningContainer{Digest: digestA, Mounts: []ObservedMount{}, Argv: []string{"busybox", "cat", "/etc/shadow"}}) {
		t.Fatal("an argv no entry permits must be rejected")
	}
}

func TestIndex_UnknownDigestDenied(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`).BuildIndex()
	if idx.AdmitsDigest(digestB) || idx.AdmitsContainer(RunningContainer{Digest: digestB, Mounts: []ObservedMount{}, Argv: nil}) {
		t.Fatal("unknown digest must be denied")
	}
}

func TestIndex_NilAdmitsNothing(t *testing.T) {
	var idx *Index
	if idx.AdmitsDigest(digestA) || idx.AdmitsContainer(RunningContainer{Digest: digestA}) || idx.Size() != 0 {
		t.Fatal("a nil *Index must admit nothing and report size 0")
	}
}

func TestIndex_MismatchNamesTheClosestEntrysFields(t *testing.T) {
	idx := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"far":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/bin/other"]},"args":{"policy":"deny"},"env":{"policy":"deny"}}]},
		"near":{"containers":[{"digest":"`+digestA+`","command":{"policy":"exact","argv":["/bin/app"]},"args":{"policy":"deny"},"env":{"policy":"deny"}}]}}}`).BuildIndex()
	env, err := ObserveEnv([]string{"MODE=x"})
	if err != nil {
		t.Fatal(err)
	}
	r := RunningContainer{Digest: digestA, Argv: []string{"/bin/app"}, Mounts: []ObservedMount{}, Env: env}
	if got := idx.Mismatch(r, true); len(got) != 1 || got[0] != "env" {
		t.Errorf("final mismatch = %v, want [env]", got)
	}
	if got := idx.Mismatch(r, false); len(got) != 0 {
		t.Errorf("preliminary mismatch = %v, want none: it checks command and args alone", got)
	}
	r.Argv = []string{"/bin/app", "--debug"}
	if got := idx.Mismatch(r, true); len(got) != 2 || got[0] != "args" || got[1] != "env" {
		t.Errorf("mismatch = %v, want [args env]", got)
	}
}

func TestIndexNodeRootBinds(t *testing.T) {
	observe := func(source string) ObservedMount {
		digest, err := HostSourceDigest(source)
		if err != nil {
			t.Fatal(err)
		}
		return ObservedMount{Source: source, Destination: source, Class: MountHost, HostSourceDigest: digest, ReadOnly: true}
	}
	rule := func(kind MountClass, source string) MountRule {
		return MountRule{Destination: source, Kind: kind, Source: source, ReadOnly: true}
	}
	entry := func(rules ...MountRule) Container {
		return Container{Digest: dig(t, digestA), Mounts: MountPolicy{Policy: PolicyExact, Rules: rules}}
	}
	// One entry names /usr/bin/tool by nodeRootFile and /etc/host by host; a
	// second entry for the same digest names /usr/bin/other by nodeRootFile.
	index := (&Allowlist{Workloads: map[string]Workload{
		"mixed":  {Containers: []Container{entry(rule(MountNodeRootFile, "/usr/bin/tool"), rule(MountHost, "/etc/host"))}},
		"second": {Containers: []Container{entry(rule(MountNodeRootFile, "/usr/bin/other"))}},
	}}).BuildIndex()
	tool, other, host, unnamed := observe("/usr/bin/tool"), observe("/usr/bin/other"), observe("/etc/host"), observe("/usr/bin/unnamed")
	undigested := ObservedMount{Destination: "/usr/bin/tool", Class: MountHost, ReadOnly: true}
	all := []ObservedMount{tool, host, undigested, other, unnamed}
	for _, tc := range []struct {
		name   string
		digest string
		mounts []ObservedMount
		want   []ObservedMount
	}{
		{"unparseable digest", "not-a-digest", all, nil},
		{"digest without its algorithm", strings.TrimPrefix(digestA, "sha256:"), all, nil},
		{"short digest", digestA[:len(digestA)-2], all, nil},
		{"digest with no entry", digestB, all, nil},
		{"only nodeRootFile sources across entries", digestA, all, []ObservedMount{tool, other}},
		{"uppercase digest names the same entries", digestA[:7] + strings.ToUpper(digestA[7:]), all, []ObservedMount{tool, other}},
		{"host rule source alone", digestA, []ObservedMount{host}, nil},
		{"mount without a source digest", digestA, []ObservedMount{undigested}, nil},
		{"no mounts", digestA, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := index.NodeRootBinds(tc.digest, tc.mounts)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("NodeRootBinds(%q) = %+v, want %+v", tc.digest, got, tc.want)
			}
		})
	}
	var nilIndex *Index
	if got := nilIndex.NodeRootBinds(digestA, all); got != nil {
		t.Fatalf("nil Index NodeRootBinds = %+v, want nil", got)
	}
}
