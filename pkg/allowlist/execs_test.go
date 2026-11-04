package allowlist

import (
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var probeExecs = [][]string{{"kubectl", "get", "--raw=/livez"}, {"kubectl", "get", "--raw=/readyz"}}

// execsEntry is one declaration of digestA running argv with pinned mounts.
func execsEntry(t *testing.T, execs [][]string, argv []string) Container {
	t.Helper()
	digest, err := types.ParseDigest(digestA)
	if err != nil {
		t.Fatal(err)
	}
	return Container{
		Digest:  digest,
		Execs:   execs,
		Command: ArgvPolicy{Policy: PolicyExact, Argv: argv},
		Args:    ArgvPolicy{Policy: PolicyDeny},
		Mounts:  MountPolicy{Policy: PolicyDeny},
	}
}

func execsIndex(t *testing.T, workloads map[string]Workload) *Index {
	t.Helper()
	a := &Allowlist{Schema: Schema, Workloads: workloads}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	return a.BuildIndex()
}

// Execs ride on the whole verified launch, and only a declaration that pins
// the command, args and mounts grants them.
func TestExecsOfBindsAPinnedLaunch(t *testing.T) {
	argv := []string{"kube-apiserver"}
	launch := RunningContainer{Digest: digestA, Argv: argv, Mounts: []ObservedMount{}}

	index := execsIndex(t, map[string]Workload{"entry": {Containers: []Container{execsEntry(t, probeExecs, argv)}}})
	if got := index.ExecsOf(launch); !slices.EqualFunc(got, probeExecs, slices.Equal[[]string]) {
		t.Fatalf("ExecsOf = %q, want %q", got, probeExecs)
	}
	launch.Argv = []string{"kube-apiserver", "--extra"}
	if got := index.ExecsOf(launch); got != nil {
		t.Fatalf("a launch the declaration does not admit was granted %q", got)
	}

	launch.Argv = argv
	loose := execsEntry(t, probeExecs, argv)
	loose.Mounts = MountPolicy{Policy: PolicyAny}
	if got := execsIndex(t, map[string]Workload{"entry": {Containers: []Container{loose}}}).ExecsOf(launch); got != nil {
		t.Fatalf("a declaration with unpinned mounts granted %q", got)
	}
}

// Two declarations admitting one launch with different execs grant none.
func TestExecsOfRefusesDisagreeingDeclarations(t *testing.T) {
	argv := []string{"kube-apiserver"}
	index := execsIndex(t, map[string]Workload{
		"a": {Containers: []Container{execsEntry(t, probeExecs, argv)}},
		"b": {Containers: []Container{execsEntry(t, probeExecs[:1], argv)}},
	})
	if got := index.ExecsOf(RunningContainer{Digest: digestA, Argv: argv, Mounts: []ObservedMount{}}); got != nil {
		t.Fatalf("disagreeing declarations granted %q", got)
	}
}

// A command without an executable is refused at load.
func TestExecsNeedAnExecutable(t *testing.T) {
	a := &Allowlist{Schema: Schema, Workloads: map[string]Workload{"entry": {Containers: []Container{
		execsEntry(t, [][]string{{}}, []string{"kube-apiserver"}),
	}}}}
	if err := a.Normalize(); err == nil || !strings.Contains(err.Error(), "execs[0]") {
		t.Fatalf("Normalize = %v, want an execs refusal", err)
	}
}

// Execs never travel on the wire: an authored document naming them is
// refused, and a served one grants none.
func TestExecsAreGrantedByBootConfigAlone(t *testing.T) {
	wire := `{"schema":"` + Schema + `","workloads":{"entry":{"containers":[` +
		`{"digest":"` + digestA + `","execs":[["sh"]],"command":{"policy":"exact","argv":["sh"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"any"}}` +
		`]}}}`
	if _, err := ParseJSON([]byte(wire)); err == nil || !strings.Contains(err.Error(), "execs") {
		t.Fatalf("an authored document naming execs was accepted: %v", err)
	}
	served, err := ParseServedJSON([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got := served.BuildIndex().ExecsOf(RunningContainer{Digest: digestA, Argv: []string{"sh"}, Mounts: []ObservedMount{}}); got != nil {
		t.Fatalf("a served document granted %q", got)
	}
}
