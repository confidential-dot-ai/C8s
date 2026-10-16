//go:build linux

package nriimagepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/audit"
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

func TestBindStagingRollback(t *testing.T) {
	file, err := os.Open(filepath.Join(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	for _, tc := range []struct {
		name        string
		failingCall int
		unmountErr  error
		wantPath    bool
	}{
		{"bind fails without privilege", 1, unix.EPERM, false},
		{"remount fails and detaches", 2, nil, false},
		{"propagation fails and detaches", 3, nil, false},
		{"remount fails and stays attached", 2, unix.EBUSY, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalRoot, originalMount, originalUnmount := verifiedMountRoot, mountSyscall, unmountSyscall
			t.Cleanup(func() { verifiedMountRoot, mountSyscall, unmountSyscall = originalRoot, originalMount, originalUnmount })
			verifiedMountRoot = t.TempDir()
			calls := 0
			mountSyscall = func(string, string, string, uintptr, string) error {
				calls++
				if calls == tc.failingCall {
					return unix.EPERM
				}
				return nil
			}
			unmountSyscall = func(string, int) error { return tc.unmountErr }
			path, err := bindStaging(file)
			if err == nil {
				t.Fatal("bindStaging succeeded despite a failing mount")
			}
			entries, _ := os.ReadDir(verifiedMountRoot)
			if tc.wantPath {
				if path == "" || len(entries) != 1 {
					t.Fatalf("bindStaging = %q with %d staging entries, want the attached path reported", path, len(entries))
				}
				return
			}
			if path != "" || len(entries) != 0 {
				t.Fatalf("bindStaging = %q, left %d staging entries, want none", path, len(entries))
			}
		})
	}
}

func TestUndetachedStagingIsTrackedAsStale(t *testing.T) {
	var leaked string
	f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) {
		leaked = fakeStaging(t)
		return leaked, "", unix.EPERM
	})
	adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
	if err != nil || adjust != nil {
		t.Fatalf("CreateContainer = %v, %v, want no adjustment and no error", adjust, err)
	}
	verifiedMountRegistry.Lock()
	entry, ok := verifiedMountRegistry.mounts[leaked]
	verifiedMountRegistry.Unlock()
	if !ok || !entry.stale {
		t.Fatalf("undetached staging %s not registered as stale: %+v", leaked, entry)
	}
	releaseVerifiedMounts(discardLogger(), "another-container")
	if got := registeredMounts(f.ctr.Id); len(got) != 0 {
		t.Fatalf("stale staging not reclaimed: %v", got)
	}
}

func TestNodeRootFileKeepsBothProofs(t *testing.T) {
	original := nodeRootEvidence
	nodeRootEvidence = func(string) (string, bool) { return testVerityDigest, true }
	t.Cleanup(func() { nodeRootEvidence = original })
	pinned := 0
	f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) {
		pinned++
		return fakeStaging(t), testVerityDigest, nil
	})
	// Only a node-root entry admits /bin/app; the fs-verity entry admits another argv.
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	verity := al.Workloads["w"].Containers[0]
	verity.Command.Argv = []string{"/bin/other"}
	verity.Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/srv/tool", Kind: allowlist.MountHost, Source: f.ctr.Mounts[0].Source, ReadOnly: true, Provenance: allowlist.ProvenanceFSVerity, VerityDigest: testVerityDigest}}}
	al.Workloads["verity"] = allowlist.Workload{Containers: []allowlist.Container{verity}}
	nodeRoot := al.Workloads["w"].Containers[0]
	nodeRoot.Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/srv/tool", Kind: allowlist.MountHost, Source: f.ctr.Mounts[0].Source, ReadOnly: true, Provenance: allowlist.ProvenanceNodeRoot}}}
	al.Workloads["w"] = allowlist.Workload{Containers: []allowlist.Container{nodeRoot}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	f.p.policy.apply(al, 2)
	adjust, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if pinned != 0 {
		t.Fatalf("staged a node-root file %d times", pinned)
	}
	if err := f.validate(t, adjust); err != nil {
		t.Fatalf("fs-verity alternative invalidated the node-root entry: %v", err)
	}
	f.ctr.Args = []string{"/bin/other"}
	if err := f.validate(t, adjust); err != nil {
		t.Fatalf("fs-verity rule rejected a node-root file with that digest: %v", err)
	}
}

func TestStagingTimeoutReleasesLatePins(t *testing.T) {
	originalBudget := verityStagingBudget
	verityStagingBudget = 10 * time.Millisecond
	t.Cleanup(func() { verityStagingBudget = originalBudget })
	release := make(chan struct{})
	staged := fakeStaging(t)
	f := newVerityFixture(t, ModeFailClosed, false, func(string, bool, []string) (string, string, error) {
		<-release
		return staged, testVerityDigest, nil
	})
	unpinned := make(chan string, 1)
	unpinFSVerity = func(path string) error {
		unpinned <- path
		return nil
	}
	done := make(chan *api.ContainerAdjustment, 1)
	go func() {
		adjust, _, _ := f.p.CreateContainer(t.Context(), f.pod, f.ctr)
		done <- adjust
	}()
	select {
	case adjust := <-done:
		if adjust != nil {
			t.Fatalf("CreateContainer = %v, want no adjustment after a timeout", adjust)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("CreateContainer blocked on a hung staging call")
	}
	close(release)
	select {
	case path := <-unpinned:
		if path != staged {
			t.Fatalf("released %s, want late staging %s", path, staged)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late staging never released")
	}
	if got := registeredMounts(f.ctr.Id); len(got) != 0 {
		t.Fatalf("late staging still registered: %v", got)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestFullRegistryRetriesStalePins(t *testing.T) {
	var capacity bool
	f := newVerityFixture(t, ModeFailClosed, false, func(_ string, c bool, _ []string) (string, string, error) {
		capacity = c
		return "", "", errVerityNotPinned
	})
	unpinFSVerity = func(string) error { return nil }
	verifiedMountRegistry.Lock()
	for i := range maxVerifiedMounts {
		verifiedMountRegistry.mounts[fmt.Sprintf("/stale/%d", i)] = verifiedMount{containerID: "gone", stale: true}
	}
	verifiedMountRegistry.Unlock()
	t.Cleanup(func() { releaseVerifiedMounts(discardLogger(), "gone") })
	if _, _, err := f.p.CreateContainer(t.Context(), f.pod, f.ctr); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if !capacity {
		t.Fatal("staging reported no capacity while stale pins were reclaimable")
	}
}

func TestCreateContainerResolvesDigestOnlyForVerityRules(t *testing.T) {
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeAudit}}, al)
	p.SetReady()
	resolved := 0
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		resolved++
		return pushDigestB, nil
	}}
	pod := makePod("default", "pod")
	pod.Uid = "pod-uid"
	ctr := makeCtrWithImageArgs(pod.Id, "app", "registry/repo:tag", []string{"/bin/app"})
	if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	baseline := resolved
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: "/var/lib/kubelet/pods/pod-uid/volumes/token", Destination: "/var/run/secrets/token", Options: []string{"rbind", "ro"}}}
	if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if resolved != baseline {
		t.Fatalf("CreateContainer resolved the digest %d extra times without an fs-verity rule", resolved-baseline)
	}
}

func TestNewPluginLeavesStagingAlone(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	originalRoot := verifiedMountRoot
	verifiedMountRoot = t.TempDir()
	t.Cleanup(func() { verifiedMountRoot = originalRoot })
	staged := filepath.Join(verifiedMountRoot, "file-live")
	if err := os.Mkdir(staged, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, &fakeContainerd{}, newPolicyStore(nil), audit.NewLogger(), discardLogger()); err != nil {
		t.Fatal(err)
	}
	if !fileExists(staged) {
		t.Fatal("newPlugin removed staging; only Run may sweep it")
	}
}
