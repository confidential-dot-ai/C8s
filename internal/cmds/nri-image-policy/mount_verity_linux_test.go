//go:build linux

package nriimagepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestEnforcesFSVerity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fsType uint32
		want   bool
	}{
		{"ext4", unix.EXT4_SUPER_MAGIC, true},
		{"f2fs", unix.F2FS_SUPER_MAGIC, true},
		{"btrfs", unix.BTRFS_SUPER_MAGIC, true},
		{"fuse", unix.FUSE_SUPER_MAGIC, false},
		{"overlayfs", unix.OVERLAYFS_SUPER_MAGIC, false},
		{"tmpfs", unix.TMPFS_MAGIC, false},
		{"nfs", unix.NFS_SUPER_MAGIC, false},
		{"erofs", unix.EROFS_SUPER_MAGIC_V1, false},
	} {
		if got := enforcesFSVerity(tc.fsType); got != tc.want {
			t.Errorf("enforcesFSVerity(%s) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestOpenVerityFileRefusesUnsafeSources(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "binary")
	if err := os.WriteFile(source, []byte("operator bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, source+"-alias"); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	notify, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(notify)
	if _, err := unix.InotifyAddWatch(notify, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source + "-alias", fifo, dir, "relative", "/proc/self/status"} {
		if file, _, err := openVerityFile(path); err == nil {
			file.Close()
			t.Errorf("openVerityFile(%s) succeeded, want refusal", path)
		}
	}
	if n, _ := unix.Read(notify, make([]byte, 4096)); n > 0 {
		t.Fatal("opened the FIFO while checking its type")
	}
	shm := filepath.Join("/dev/shm", filepath.Base(dir))
	if err := os.WriteFile(shm, []byte("tmpfs bytes"), 0600); err != nil {
		t.Skipf("no tmpfs at /dev/shm: %v", err)
	}
	defer os.Remove(shm)
	if _, _, err := openVerityFile(shm); !errors.Is(err, errVerityFilesystem) {
		t.Fatalf("openVerityFile(tmpfs) = %v, want %v", err, errVerityFilesystem)
	}
	if path, digest, err := pinFSVerityFile(shm, []string{testVerityDigest}); err == nil || path != "" || digest != "" {
		t.Fatalf("pinFSVerityFile(tmpfs) = %q, %q, %v, want refusal", path, digest, err)
	}
}

func TestOrdinaryFileHasNoVerityDigest(t *testing.T) {
	source := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(source, []byte("operator bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if fsVerityDigest(file) != "" {
		t.Fatal("ordinary file reported fs-verity")
	}
	if path, digest, err := pinFSVerityFile(source, []string{testVerityDigest}); err == nil || path != "" || digest != "" {
		t.Fatalf("pinFSVerityFile(mutable file) = %q, %q, %v, want refusal", path, digest, err)
	}
	if pinnedFSVerityFile(source, "") {
		t.Fatal("pinnedFSVerityFile accepted a writable file without fs-verity")
	}
}

// Run explicitly on a disposable verity-enabled ext4 filesystem in a private
// mount namespace. The ordinary suite exercises the fail-closed paths above.
func TestFSVerityPinnedInodeIntegration(t *testing.T) {
	root := os.Getenv("C8S_TEST_FS_VERITY_DIR")
	if root == "" {
		t.Skip("requires private mount namespace and verity-enabled ext4")
	}
	originalRoot := verifiedMountRoot
	verifiedMountRoot = filepath.Join(root, "staging")
	defer func() { verifiedMountRoot = originalRoot }()
	source := filepath.Join(root, "binary")
	if err := os.WriteFile(source, []byte("approved executable"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	// struct fsverity_enable_arg from the Linux UAPI; no signature is needed
	// because the authenticated workload policy pins FS_IOC_MEASURE_VERITY.
	enable := struct {
		Version, Algorithm, BlockSize, SaltSize uint32
		SaltPtr                                 uint64
		SigSize, Reserved                       uint32
		SigPtr                                  uint64
		Reserved2                               [11]uint64
	}{Version: 1, Algorithm: 1, BlockSize: 4096}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.FS_IOC_ENABLE_VERITY, uintptr(unsafe.Pointer(&enable)))
	digest := fsVerityDigest(file)
	file.Close()
	if errno != 0 {
		t.Fatalf("enable fs-verity: %v", errno)
	}
	// The production sandbox and namespaces: the launch must pass StartContainer.
	pod := sandboxedPod()
	ctr := sandboxedContainer()
	ctr.PodSandboxId = pod.Id
	ctr.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestB}
	ctr.Args = []string{"/bin/app"}
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: source, Destination: "/usr/bin/tool", Options: []string{"rbind", "rprivate", "ro"}}}
	rule := allowlist.MountRule{Destination: "/usr/bin/tool", Kind: allowlist.MountHost, Source: source, ReadOnly: true, Provenance: allowlist.ProvenanceFSVerity, VerityDigest: digest}
	if adjust := stageVerityMounts(t.Context(), discardLogger(), pod, ctr, nil, nil); adjust != nil {
		t.Fatal("staged fs-verity without a policy pin")
	}
	wrong := rule
	wrong.VerityDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if adjust := stageVerityMounts(t.Context(), discardLogger(), pod, ctr, nil, []allowlist.MountRule{wrong}); adjust != nil {
		t.Fatalf("stageVerityMounts(unpinned digest) = %v, want no staging", adjust)
	}
	overlay := &api.Mount{Type: "overlay", Source: source, Destination: "/usr/bin/tool", Options: []string{"ro", "lowerdir=" + root}}
	if adjust := stageVerityMounts(t.Context(), discardLogger(), pod, &api.Container{Id: ctr.Id, PodSandboxId: pod.Id, Mounts: []*api.Mount{overlay}}, nil, []allowlist.MountRule{rule}); adjust != nil {
		t.Fatalf("stageVerityMounts(overlay) = %v, want no staging", adjust)
	}
	// Create-time staging returns the immutable inode's node-owned mount path.
	adjust := stageVerityMounts(t.Context(), discardLogger(), pod, ctr, nil, []allowlist.MountRule{rule})
	defer releaseVerifiedMounts(discardLogger(), ctr.Id)
	if adjust == nil || len(adjust.Mounts) != 1 {
		t.Fatal("missing inode pin")
	}
	snapshot := adjust.Mounts[0].Source
	if err := os.Rename(source, source+"-approved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("smuggled executable"), 0600); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(snapshot)
	if err != nil || string(content) != "approved executable" {
		t.Fatalf("source substitution reached snapshot: %q %v", content, err)
	}
	if err := os.WriteFile(snapshot, []byte("smuggled executable"), 0600); err == nil {
		t.Fatal("snapshot writable")
	}
	mounts := adjustedMounts(&api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: adjust}, ctr, "")
	if len(mounts) != 1 || mounts[0].Provenance != allowlist.ProvenanceFSVerity || mounts[0].VerityDigest != digest {
		t.Fatalf("lost kernel evidence: %+v, want digest %s", mounts, digest)
	}
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{rule}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.inventory = newAdmissionInventory(t.TempDir())
	p.SetReady()
	staged := proto.Clone(adjust.Mounts[0]).(*api.Mount)
	ctr.Mounts = adjust.Mounts
	req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err != nil {
		t.Fatalf("verified inode rejected: %v", err)
	}
	if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
		t.Fatalf("StartContainer rejected the verified inode: %v", err)
	}
	_, containers, ok, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil || !ok || len(containers) != 1 {
		t.Fatalf("inventory = %v, %t, %v, want one container", containers, ok, err)
	}
	running := allowlist.RunningContainer{Digest: containers[0].Digest, Argv: containers[0].Argv, Env: containers[0].Env, Mounts: containers[0].Mounts}
	if name, _, err := al.MatchWorkload([]allowlist.RunningContainer{running}); err != nil || name != "w" {
		t.Fatalf("MatchWorkload(recorded launch) = %q, %v, want w", name, err)
	}
	// Provenance checks run while the pin is registered: the rejected
	// validation below releases it.
	last := len(ctr.Mounts) - 1
	if got := newMountObserver(nil, "").Observe(pod, ctr); got[last].Provenance != allowlist.ProvenanceFSVerity {
		t.Fatal("staged bind lost provenance")
	}
	overlay = proto.Clone(staged).(*api.Mount)
	overlay.Type, overlay.Options = "overlay", []string{"ro", "lowerdir=" + root}
	ctr.Mounts[last] = overlay
	if got := newMountObserver(nil, "").Observe(pod, ctr); got[last].Provenance != "" {
		t.Fatal("overlay naming the snapshot kept provenance")
	}
	ctr.Mounts[last] = staged
	another := proto.Clone(ctr).(*api.Container)
	another.Id = "another-container"
	if got := newMountObserver(nil, "").Observe(pod, another); got[last].Provenance != "" {
		t.Fatal("another container borrowed provenance")
	}
	substituted := proto.Clone(staged).(*api.Mount)
	substituted.Source = source
	ctr.Mounts[last] = substituted
	if err := p.ValidateContainerAdjustment(t.Context(), req); err == nil {
		t.Fatal("substituted unverified source admitted")
	}
}
