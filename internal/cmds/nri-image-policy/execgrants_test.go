package nriimagepolicy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const grantContainerID = "4a2dbd89094511041afa94178b0fdcc06e40ab3b44c014a89d84ce9c13367c27"

var grantedExecs = [][]string{{"kubectl", "get", "--raw=/livez"}}

// execsPlugin is a plugin whose base grants grantedExecs to pushDigestB
// running argv, recording into a private temporary directory.
func execsPlugin(t *testing.T, argv []string) *plugin {
	t.Helper()
	base := roleBase(t, pushDigestB, "", argv)
	entry := base.Workloads["role-entry"]
	entry.Containers[0].Execs = grantedExecs
	entry.Containers[0].Args = allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}
	entry.Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyDeny}
	if !grantsExecs(base) {
		t.Fatal("the base grants no execs")
	}
	p := newTestPlugin(&config{Allowlist: allowlistConfig{Base: base}})
	p.execGrants = &execGrants{dir: filepath.Join(privateDir(t), "grants")}
	return p
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A container holds a grant exactly while the measured base grants its whole
// launch execs: a launch the declaration does not admit gets none, and
// removing the container drops it.
func TestExecGrantFollowsTheMeasuredBase(t *testing.T) {
	argv := []string{"kube-apiserver"}
	p := execsPlugin(t, argv)
	ctr := &api.Container{Id: grantContainerID, PodSandboxId: "pod", Args: argv}
	// A host-network pod, like RKE2's static pods: outside the mesh gates.
	pod := makePod("default", "pod")

	p.recordDigest(pod, ctr, pushDigestB, []allowlist.ObservedMount{})
	if got, err := ReadExecGrant(p.execGrants.dir, ctr.Id); err != nil || !slices.EqualFunc(got, grantedExecs, slices.Equal[[]string]) {
		t.Fatalf("ReadExecGrant after a granted launch = %q, %v; want %q", got, err, grantedExecs)
	}

	impostor := &api.Container{Id: ctr.Id, PodSandboxId: "pod", Args: []string{"sh"}}
	p.recordDigest(pod, impostor, pushDigestB, []allowlist.ObservedMount{})
	if got, err := ReadExecGrant(p.execGrants.dir, ctr.Id); err == nil {
		t.Fatalf("a launch the declaration does not admit kept the grant %q", got)
	}

	p.recordDigest(pod, ctr, pushDigestB, []allowlist.ObservedMount{})
	if err := p.RemoveContainer(context.Background(), nil, ctr); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExecGrant(p.execGrants.dir, ctr.Id); err == nil {
		t.Fatal("a removed container kept its grant")
	}
}

// A pod the mesh gates cover holds no grant, whatever the base declares: no
// new process starts in a member.
func TestNoExecGrantInAMeshGatedPod(t *testing.T) {
	argv := []string{"kube-apiserver"}
	p := execsPlugin(t, argv)
	ctr := &api.Container{Id: grantContainerID, PodSandboxId: "pod", Args: argv}
	p.recordDigest(meshPod("default", "pod", "/proc/4242/ns/net"), ctr, pushDigestB, []allowlist.ObservedMount{})
	if got, err := ReadExecGrant(p.execGrants.dir, ctr.Id); err == nil {
		t.Fatalf("a mesh-gated pod was granted %q", got)
	}
}

// A base granting no execs keeps no records.
func TestNoExecGrantsWithoutExecs(t *testing.T) {
	if grantsExecs(roleBase(t, pushDigestB, "", []string{"kube-apiserver"})) {
		t.Fatal("a base without execs keeps grant records")
	}
}

// The record directory and file are the reader's alone, and a record grants
// at least one command or it is none.
func TestReadExecGrantRefusesForeignRecords(t *testing.T) {
	const valid = `{"execs":[["kubectl"]]}`
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		id    string
	}{
		{name: "path-like id", id: "../" + grantContainerID},
		{name: "no record"},
		{name: "no command", setup: func(t *testing.T, dir string) { writeGrant(t, dir, `{"execs":[]}`, 0o600) }},
		{name: "empty command", setup: func(t *testing.T, dir string) { writeGrant(t, dir, `{"execs":[[]]}`, 0o600) }},
		{name: "writable record", setup: func(t *testing.T, dir string) { writeGrant(t, dir, valid, 0o666) }},
		{name: "symlinked record", setup: func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "grant")
			if err := os.WriteFile(target, []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, grantContainerID)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "writable directory", setup: func(t *testing.T, dir string) {
			writeGrant(t, dir, valid, 0o600)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			id := tc.id
			if id == "" {
				id = grantContainerID
			}
			if got, err := ReadExecGrant(dir, id); err == nil {
				t.Fatalf("ReadExecGrant = %q, want a refusal", got)
			}
		})
	}
}

// writeGrant puts a record for grantContainerID in dir with the given mode.
func writeGrant(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, grantContainerID)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
