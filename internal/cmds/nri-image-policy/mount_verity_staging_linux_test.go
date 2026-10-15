//go:build linux

package nriimagepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

var testVerityDigest = strings.Repeat("ab", 32)

type verityFixture struct {
	p   *plugin
	pod *api.PodSandbox
	ctr *api.Container
}

// newVerityFixture builds a ready plugin whose workload entry pins the
// container's host file by fs-verity digest. withPathOnly adds a second entry
// for the same image that admits that file without provenance.
func newVerityFixture(t *testing.T, mode string, withPathOnly bool, pin func(string, bool, []string) (string, string, error)) verityFixture {
	t.Helper()
	originalPin, originalUnpin := pinFSVerity, unpinFSVerity
	pinFSVerity = pin
	unpinFSVerity = func(path string) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return os.Remove(filepath.Dir(path))
	}
	t.Cleanup(func() { pinFSVerity, unpinFSVerity = originalPin, originalUnpin })

	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte("operator bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	pinned := allowlist.MountRule{Destination: "/srv/tool", Kind: allowlist.MountHost, Source: file, ReadOnly: true, Provenance: allowlist.ProvenanceFSVerity, VerityDigest: testVerityDigest}
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{pinned}}
	if withPathOnly {
		pathOnly := pinned
		pathOnly.Provenance, pathOnly.VerityDigest = "", ""
		entry := al.Workloads["w"].Containers[0]
		entry.Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{pathOnly}}
		al.Workloads["path-only"] = allowlist.Workload{Containers: []allowlist.Container{entry}}
	}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: mode}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.SetReady()
	pod := makePod("default", "pod")
	pod.Uid = "pod-uid"
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
	ctr.Args = []string{"/bin/app"}
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: file, Destination: "/srv/tool", Options: []string{"bind", "ro"}}}
	t.Cleanup(func() { releaseVerifiedMounts(ctr.Id) })
	return verityFixture{p: p, pod: pod, ctr: ctr}
}

func (f verityFixture) validate(t *testing.T, adjust *api.ContainerAdjustment) error {
	t.Helper()
	return f.p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: f.pod, Container: f.ctr, Adjust: adjust})
}

func registeredMounts(containerID string) []string {
	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	var paths []string
	for path, entry := range verifiedMountRegistry.mounts {
		if entry.containerID == containerID {
			paths = append(paths, path)
		}
	}
	return paths
}

// fakeStaging returns a staging path that the fixture's unpin removes.
func fakeStaging(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "file-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inode")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func registerStaging(t *testing.T, containerID string) string {
	t.Helper()
	path := fakeStaging(t)
	verifiedMountRegistry.Lock()
	verifiedMountRegistry.mounts[path] = verifiedMount{containerID: containerID}
	verifiedMountRegistry.Unlock()
	t.Cleanup(func() { releaseVerifiedMounts(containerID) })
	return path
}

func TestUnstagedVerityMountIsDeniedAtValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"digest not pinned", errVerityNotPinned},
		{"capacity reached", errVerityCapacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) { return "", "", tc.err })
			other := registerStaging(t, "other-container")
			adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
			if err != nil || adjust != nil {
				t.Fatalf("CreateContainer = %v, %v, want no adjustment and no error", adjust, err)
			}
			if got := registeredMounts(f.ctr.Id); len(got) != 0 {
				t.Fatalf("registered %v for an unstaged mount", got)
			}
			if got := registeredMounts("other-container"); len(got) != 1 || got[0] != other {
				t.Fatalf("other container's pins = %v, want [%s]", got, other)
			}
			if err := f.validate(t, adjust); err == nil {
				t.Fatal("ValidateContainerAdjustment admitted an fs-verity rule without staged evidence")
			}
		})
	}
}

func TestUnstagedVerityMountMatchesEntryWithoutProvenance(t *testing.T) {
	f := newVerityFixture(t, ModeFailClosed, true, func(string, bool, []string) (string, string, error) { return "", "", errVerityNotPinned })
	adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if err := f.validate(t, adjust); err != nil {
		t.Fatalf("ValidateContainerAdjustment denied a mount the path-only entry admits: %v", err)
	}
	mounts := adjustedMounts(&api.ValidateContainerAdjustmentRequest{Pod: f.pod, Container: f.ctr, Adjust: adjust}, f.ctr)
	if len(mounts) != 1 || mounts[0].Provenance != "" || mounts[0].VerityDigest != "" {
		t.Fatalf("observed %+v, want no provenance for an unstaged mount", mounts)
	}
}

func TestStagingFailureAfterDigestMatch(t *testing.T) {
	failure := errors.New("bind mount failed")
	for _, tc := range []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"enforce", ModeFailClosed, true},
		{"audit", ModeAudit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerityFixture(t, tc.mode, false, func(string, bool, []string) (string, string, error) { return "", "", failure })
			// A pin staged for another of the container's mounts must be released.
			staged := registerStaging(t, f.ctr.Id)
			_, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("CreateContainer error = %v, want error %t", err, tc.wantErr)
			}
			if got := registeredMounts(f.ctr.Id); len(got) != 0 {
				t.Fatalf("pins left after a staging failure: %v", got)
			}
			if _, err := os.Stat(staged); !os.IsNotExist(err) {
				t.Fatalf("staged file %s not released: %v", staged, err)
			}
		})
	}
}

func TestStartContainerDenyReleasesPins(t *testing.T) {
	f := newVerityFixture(t, ModeFailClosed, false, pinFSVerityFile)
	f.ctr.Args = []string{"/bin/other"}
	staged := registerStaging(t, f.ctr.Id)
	if err := f.p.StartContainer(t.Context(), f.pod, f.ctr); err == nil {
		t.Fatal("StartContainer admitted an argv no entry allows")
	}
	if got := registeredMounts(f.ctr.Id); len(got) != 0 {
		t.Fatalf("pins left after a denied start: %v", got)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged file %s not released: %v", staged, err)
	}
}
