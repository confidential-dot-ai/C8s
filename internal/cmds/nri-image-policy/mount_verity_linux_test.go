//go:build linux

package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestFSVerityRequiresKernelEvidence(t *testing.T) {
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
	if path, digest, err := pinFSVerityFile(source, true, nil); err != nil || path != "" || digest != "" {
		t.Fatalf("pinned mutable file: %s %s %v", path, digest, err)
	}
	if err := os.Symlink(source, source+"-alias"); err != nil {
		t.Fatal(err)
	}
	if file, err := openVeritySource(source + "-alias"); err == nil {
		file.Close()
		t.Fatal("followed source symlink")
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
	// struct fsverity_enable_arg from the Linux UAPI; no signature is necessary
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
	pod := makePod("default", "pod")
	pod.Uid = "pod-uid"
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
	ctr.Args = []string{"/bin/app"}
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: source, Destination: "/usr/bin/tool", Options: []string{"bind", "ro"}}}
	// Create-time staging returns the immutable inode's node-owned mount path.
	rule := allowlist.MountRule{Destination: "/usr/bin/tool", Kind: allowlist.MountHost, Source: source, ReadOnly: true, Provenance: allowlist.ProvenanceFSVerity, VerityDigest: digest}
	if adjust, err := stageVerityMounts(pod, ctr, nil, nil); err != nil || adjust != nil {
		t.Fatal("staged fs-verity without a policy pin")
	}
	wrong := rule
	wrong.VerityDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := stageVerityMounts(pod, ctr, nil, []allowlist.MountRule{wrong}); err == nil {
		t.Fatal("staged an unapproved kernel digest")
	}
	adjust, err := stageVerityMounts(pod, ctr, nil, []allowlist.MountRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	defer releaseVerifiedMounts(ctr.Id)
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
	bytes, err := os.ReadFile(snapshot)
	if err != nil || string(bytes) != "approved executable" {
		t.Fatalf("source substitution reached snapshot: %q %v", bytes, err)
	}
	if err := os.WriteFile(snapshot, []byte("smuggled executable"), 0600); err == nil {
		t.Fatal("snapshot writable")
	}
	mounts := adjustedMounts(&api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: adjust}, ctr)
	if len(mounts) != 1 || mounts[0].Provenance != allowlist.ProvenanceFSVerity || mounts[0].VerityDigest == "" {
		t.Fatalf("lost kernel evidence: %+v", mounts)
	}
	if mounts[0].VerityDigest != digest {
		t.Fatal("digest changed during staging")
	}
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{rule}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.SetReady()
	ctr.Mounts = adjust.Mounts
	req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err != nil {
		t.Fatalf("verified inode rejected: %v", err)
	}
	ctr.Mounts[0].Source = source
	if err := p.ValidateContainerAdjustment(t.Context(), req); err == nil {
		t.Fatal("substituted unverified source admitted")
	}
	ctr.Mounts[0].Source = snapshot
	ctr.Id = "another-container"
	if got := newMountObserver(nil).Observe(pod, ctr); got[0].Provenance != "" {
		t.Fatal("another container borrowed provenance")
	}

}
