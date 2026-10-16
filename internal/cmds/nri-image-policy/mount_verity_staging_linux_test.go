//go:build linux

package nriimagepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
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
	t.Cleanup(func() { releaseVerifiedMounts(discardLogger(), ctr.Id) })
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
	t.Cleanup(func() { releaseVerifiedMounts(discardLogger(), containerID) })
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
	mounts := adjustedMounts(&api.ValidateContainerAdjustmentRequest{Pod: f.pod, Container: f.ctr, Adjust: adjust}, f.ctr, "")
	if len(mounts) != 1 || mounts[0].Provenance != "" || mounts[0].VerityDigest != "" {
		t.Fatalf("observed %+v, want no provenance for an unstaged mount", mounts)
	}
}

func TestStagingFailureLeavesFinalMatchingToDecide(t *testing.T) {
	failure := errors.New("bind mount failed")
	for _, tc := range []struct {
		name     string
		pathOnly bool
		admitted bool
	}{
		{"no other entry", false, false},
		{"path-only entry", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newVerityFixture(t, ModeFailClosed, tc.pathOnly, func(string, bool, []string) (string, string, error) { return "", "", failure })
			adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
			if err != nil || adjust != nil {
				t.Fatalf("CreateContainer = %v, %v, want no adjustment and no error", adjust, err)
			}
			if got := registeredMounts(f.ctr.Id); len(got) != 0 {
				t.Fatalf("pins left after a staging failure: %v", got)
			}
			if err := f.validate(t, adjust); (err == nil) != tc.admitted {
				t.Fatalf("ValidateContainerAdjustment = %v, want admitted %t", err, tc.admitted)
			}
		})
	}
}

func TestNonBindMountIsNeverStaged(t *testing.T) {
	pinned := 0
	f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) {
		pinned++
		return fakeStaging(t), testVerityDigest, nil
	})
	file := f.ctr.Mounts[0].Source
	for _, mount := range []*api.Mount{
		{Type: "overlay", Source: file, Destination: "/srv/tool", Options: []string{"bind", "ro", "lowerdir=/untrusted"}},
		{Type: "bind", Source: file, Destination: "/srv/tool", Options: []string{"bind", "ro", "lowerdir=/untrusted"}},
	} {
		f.ctr.Mounts = []*api.Mount{mount}
		if adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr); err != nil || adjust != nil {
			t.Fatalf("CreateContainer(%s %v) = %v, %v, want no staging", mount.Type, mount.Options, adjust, err)
		}
	}
	if pinned != 0 {
		t.Fatalf("pinned %d non-bind mounts", pinned)
	}
	staged := registerStaging(t, f.ctr.Id)
	ctx := MountContext{PodUID: f.pod.Uid, SandboxID: f.pod.Id, Container: f.ctr}
	if _, ok := verifiedHostMount(ctx, &api.Mount{Type: "overlay", Source: staged, Destination: "/srv/tool", Options: []string{"ro"}}); ok {
		t.Fatal("verifiedHostMount granted provenance to an overlay")
	}
}

func TestStagingDoesNotHoldRegistryLock(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) {
		close(entered)
		<-release
		return "", "", errVerityNotPinned
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.p.CreateContainer(t.Context(), f.pod, f.ctr) //nolint:errcheck // Only the lock matters here.
	}()
	<-entered
	locked := verifiedMountRegistry.TryLock()
	if locked {
		verifiedMountRegistry.Unlock()
	}
	close(release)
	<-done
	if !locked {
		t.Fatal("registry lock held across pinFSVerity")
	}
}

func TestReleaseRetriesFailedUnmount(t *testing.T) {
	newVerityFixture(t, ModeFailClosed, false, pinFSVerityFile)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	stuck := registerStaging(t, "stuck")
	unpinFSVerity = func(string) error { return fmt.Errorf("%w: device busy", errStillMounted) }
	releaseVerifiedMounts(logger, "stuck")
	if got := registeredMounts("stuck"); len(got) != 1 || got[0] != stuck {
		t.Fatalf("pins after failed unmount = %v, want [%s]", got, stuck)
	}
	if !strings.Contains(logs.String(), stuck) {
		t.Fatalf("failed unmount not logged with its path: %s", logs.String())
	}
	var unpinned []string
	unpinFSVerity = func(path string) error {
		unpinned = append(unpinned, path)
		return errors.New("remove staging directory: busy")
	}
	releaseVerifiedMounts(logger, "another-container")
	if got := registeredMounts("stuck"); len(got) != 0 || len(unpinned) != 1 || unpinned[0] != stuck {
		t.Fatalf("stale pin not retried and dropped after unmount: registered %v, unpinned %v", got, unpinned)
	}
}

func TestSweepRemovesStaleStaging(t *testing.T) {
	newVerityFixture(t, ModeFailClosed, false, pinFSVerityFile)
	originalRoot := verifiedMountRoot
	verifiedMountRoot = t.TempDir()
	t.Cleanup(func() { verifiedMountRoot = originalRoot })
	stale := filepath.Join(verifiedMountRoot, "file-stale")
	empty := filepath.Join(verifiedMountRoot, "file-empty")
	for _, dir := range []string{stale, empty} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stale, "inode"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	sweepVerifiedMounts(discardLogger())
	entries, err := os.ReadDir(verifiedMountRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging left after sweep: %v %v", entries, err)
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
