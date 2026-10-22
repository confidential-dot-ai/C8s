package volumed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// fakeOps records every privileged call and can be told to fail one step.
type fakeOps struct {
	mu     sync.Mutex
	calls  []string
	failOn string

	cryptOpen, verityOpen, mounted map[string]bool

	// cryptRO records the read-only flag each crypt mapping was opened with,
	// and mounts the (fsType, readOnly) of each Mount call.
	cryptRO map[string]bool
	mounts  []mountCall

	// blank and hasExt4 are what the device probes report; formatted
	// records the rootOwner each MakeExt4 was given.
	blank, hasExt4 bool
	formatted      []string

	// honorCtx makes every op fail once its context is done.
	honorCtx bool
	// afterCryptOpen fires once the first privileged step has landed.
	afterCryptOpen func()
}

// mountCall records what one Mount was asked to do.
type mountCall struct {
	source, fsType string
	readOnly       bool
}

func newOps() *fakeOps {
	return &fakeOps{
		cryptOpen:  map[string]bool{},
		verityOpen: map[string]bool{},
		mounted:    map[string]bool{},
		cryptRO:    map[string]bool{},
	}
}

// ctxErr mirrors the real ops, which shell out to cryptsetup/veritysetup and
// so cannot do anything once their context is done. Without this the fake
// would unwind happily on a cancelled context and hide a leak.
func (f *fakeOps) ctxErr(ctx context.Context) error {
	if f.honorCtx {
		return ctx.Err()
	}
	return nil
}

func (f *fakeOps) record(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
	if f.failOn == op {
		return errors.New(op + " failed")
	}
	return nil
}

func (f *fakeOps) CryptOpen(ctx context.Context, _, mapper string, key []byte, readOnly bool) error {
	if len(key) != volume.KeyBytes {
		return errors.New("wrong key length")
	}
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("CryptOpen"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cryptOpen[mapper] = true
	f.cryptRO[mapper] = readOnly
	if f.afterCryptOpen != nil {
		f.afterCryptOpen()
	}
	return nil
}

func (f *fakeOps) CryptClose(ctx context.Context, mapper string) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("CryptClose"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.cryptOpen, mapper)
	return nil
}

func (f *fakeOps) VerityOpen(ctx context.Context, _, mapper string, _ volume.Verity) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("VerityOpen"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verityOpen[mapper] = true
	return nil
}

func (f *fakeOps) VerityClose(ctx context.Context, mapper string) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("VerityClose"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.verityOpen, mapper)
	return nil
}

// ListMappings answers from what is open, the way /dev/mapper does: a mapping
// is listed until something closes it.
func (f *fakeOps) ListMappings(ctx context.Context) ([]string, error) {
	if err := f.ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := f.record("ListMappings"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for name := range f.cryptOpen {
		out = append(out, name)
	}
	for name := range f.verityOpen {
		out = append(out, name)
	}
	// /dev/mapper carries every consumer's targets, not only ours.
	out = append(out, "control", "rootvg-swap")
	sort.Strings(out)
	return out, nil
}

func (f *fakeOps) MountRO(ctx context.Context, source string, target *os.File, fsType string) error {
	return f.mount(ctx, "MountRO", source, target, fsType, true)
}

func (f *fakeOps) MountRW(ctx context.Context, source string, target *os.File, fsType string) error {
	return f.mount(ctx, "MountRW", source, target, fsType, false)
}

func (f *fakeOps) mount(ctx context.Context, op, source string, target *os.File, fsType string, readOnly bool) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record(op); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// The kernel resolves /proc/self/fd/N to the directory it names, so the
	// mount lands at the real path — which is what teardown unmounts.
	f.mounted[target.Name()] = true
	f.mounts = append(f.mounts, mountCall{source: source, fsType: fsType, readOnly: readOnly})
	return nil
}

func (f *fakeOps) Unmount(ctx context.Context, target string) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("Unmount"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.mounted, target)
	return nil
}

func (f *fakeOps) Blank(ctx context.Context, _ string) (bool, error) {
	if err := f.ctxErr(ctx); err != nil {
		return false, err
	}
	if err := f.record("Blank"); err != nil {
		return false, err
	}
	return f.blank, nil
}

func (f *fakeOps) HasExt4(ctx context.Context, _ string) (bool, error) {
	if err := f.ctxErr(ctx); err != nil {
		return false, err
	}
	if err := f.record("HasExt4"); err != nil {
		return false, err
	}
	return f.hasExt4, nil
}

func (f *fakeOps) MakeExt4(ctx context.Context, _, rootOwner string) error {
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("MakeExt4"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.formatted = append(f.formatted, rootOwner)
	return nil
}

// leaked reports device-mapper targets or mounts left behind. A leaked crypt
// target holds the key in kernel memory with nothing owning it.
func (f *fakeOps) leaked() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cryptOpen), len(f.verityOpen), len(f.mounted)
}

func (f *fakeOps) sequence() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func testOpener(t *testing.T, ops DeviceOps) *Opener {
	t.Helper()
	root, base := kubeletTree(t)
	if err := os.Mkdir(filepath.Join(base, KubeVolumeName("weights")), 0o755); err != nil {
		t.Fatalf("mkdir volume dir: %v", err)
	}
	return &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	blob, err := volume.NewBlob(volumeKey(), volume.Verity{
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 4,
		HashOffset: 4 * volume.VerityBlockSize,
	})
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	return Request{Pod: testPod(testPodUID), Name: "weights", Device: "/dev/disk/by-id/virtio-c8s-vol-weights", Blob: blob}
}

// testPod is a pod as the kernel would report it: the UID naming its kubelet
// directory, and the systemd-driver slice that disappears when it goes.
func testPod(uid string) PodCgroup {
	return PodCgroup{
		UID:  uid,
		Path: "/kubepods.slice/kubepods-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice",
	}
}

func volumeKey() []byte {
	k := make([]byte, volume.KeyBytes)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestOpenRunsTheStepsInOrder(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("sequence = %q", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", o.Len())
	}
	m := ops.mounts[0]
	if m.fsType != fsTypeErofs || !m.readOnly {
		t.Errorf("mount = %+v, want read-only erofs", m)
	}
	if !strings.HasSuffix(m.source, "c8s-verity-"+testPodUID+"-weights") {
		t.Errorf("mount source = %q, want the verity device", m.source)
	}
	if !ops.cryptRO["c8s-crypt-"+testPodUID+"-weights"] {
		t.Error("immutable volume's crypt mapping was not opened read-only")
	}
}

// Every step that completed must be undone when a later one fails, or the
// device-mapper targets are left holding the key with no owner.
func TestOpenUnwindsEveryCompletedStepOnFailure(t *testing.T) {
	for _, tc := range []struct{ failOn, wantSeq string }{
		{"CryptOpen", "CryptOpen"},
		{"VerityOpen", "CryptOpen,VerityOpen,CryptClose"},
		{"MountRO", "CryptOpen,VerityOpen,MountRO,VerityClose,CryptClose"},
	} {
		ops := newOps()
		ops.failOn = tc.failOn
		o := testOpener(t, ops)

		if err := o.Open(t.Context(), testRequest(t)); err == nil {
			t.Fatalf("%s: open succeeded despite failure", tc.failOn)
		}
		if got := ops.sequence(); got != tc.wantSeq {
			t.Errorf("%s: sequence = %q, want %q", tc.failOn, got, tc.wantSeq)
		}
		if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
			t.Errorf("%s: leaked crypt=%d verity=%d mounts=%d", tc.failOn, c, v, m)
		}
		if o.Len() != 0 {
			t.Errorf("%s: a failed open was recorded as a mount", tc.failOn)
		}
	}
}

// kubelet restarts a native sidecar for the pod's life, so it re-sends its
// request; an identical one must not open a second mapping.
func TestOpenIsIdempotentForAnIdenticalRequest(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)

	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("repeat open: %v", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("repeat re-ran privileged steps: %q", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", o.Len())
	}
}

// Without this the volume NAME is the credential — and a name is a label in a
// host-written annotation, so any pod reaching the socket would be handed the
// plaintext once one entitled pod had opened it.
func TestOpenRefusesAWrongKeyForAnOpenVolume(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}

	other := testRequest(t)
	wrong := make([]byte, volume.KeyBytes)
	blob, err := volume.NewBlob(wrong, *other.Blob.Verity)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	other.Blob = blob

	if err := o.Open(t.Context(), other); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v, want ErrNotAuthorized", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("a refused caller reached the privileged steps: %q", got)
	}
}

func testMutableRequest(t *testing.T) Request {
	t.Helper()
	blob, err := volume.NewMutableBlob(volumeKey())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	return Request{Pod: testPod(testPodUID), Name: "weights", Device: "/dev/disk/by-id/virtio-c8s-vol-weights", Blob: blob}
}

// A mutable volume mounts the crypt device itself, writable ext4 — there is no
// verity layer to open.
func TestOpenMutableMountsTheCryptDeviceWritable(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testMutableRequest(t)); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := ops.sequence(); got != "CryptOpen,MountRW" {
		t.Fatalf("sequence = %q, want no verity step", got)
	}
	m := ops.mounts[0]
	if m.fsType != fsTypeExt4 || m.readOnly {
		t.Errorf("mount = %+v, want writable ext4", m)
	}
	if !strings.HasSuffix(m.source, "c8s-crypt-"+testPodUID+"-weights") {
		t.Errorf("mount source = %q, want the crypt device", m.source)
	}
	if ops.cryptRO["c8s-crypt-"+testPodUID+"-weights"] {
		t.Error("mutable volume's crypt mapping was opened read-only")
	}
}

// Close on a mutable mount must not touch a verity layer that never existed.
func TestCloseMutableSkipsVerity(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testMutableRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}
	o.Close(t.Context(), req.Pod.UID, req.Name)
	if got := ops.sequence(); !strings.HasSuffix(got, "Unmount,CryptClose") {
		t.Fatalf("teardown order = %q", got)
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

// The mode is part of the commitment: the same key presented in the other mode
// is a different volume, not a repeat request.
func TestOpenRefusesAModeFlipOnAnOpenVolume(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := o.Open(t.Context(), testMutableRequest(t)); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("immutable then mutable: got %v, want ErrNotAuthorized", err)
	}

	ops2 := newOps()
	o2 := testOpener(t, ops2)
	if err := o2.Open(t.Context(), testMutableRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := o2.Open(t.Context(), testRequest(t)); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("mutable then immutable: got %v, want ErrNotAuthorized", err)
	}
}

// conflictTree builds the kubelet volume dirs for two pods, each able to hold
// weights, and the first able to hold datasets too.
func conflictTree(t *testing.T) (root, otherUID string) {
	t.Helper()
	root, base := kubeletTree(t)
	for _, n := range []string{"weights", "datasets"} {
		if err := os.Mkdir(filepath.Join(base, KubeVolumeName(n)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", n, err)
		}
	}
	otherUID = "99999999-8888-7777-6666-555555555555"
	otherBase := filepath.Join(root, "pods", otherUID, emptyDirSubdir)
	if err := os.MkdirAll(filepath.Join(otherBase, KubeVolumeName("weights")), 0o755); err != nil {
		t.Fatalf("mkdir other pod: %v", err)
	}
	return root, otherUID
}

// Two writable mounts of one device corrupt the filesystem, and a writable
// mount under read-only readers corrupts what they read: if either side is
// mutable, one device backs one mount. This is the double-mount a rolling
// update of a single-device workload would otherwise hit.
func TestMutableOpenIsExclusivePerDevice(t *testing.T) {
	root, otherUID := conflictTree(t)
	ops := newOps()
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	if err := o.Open(t.Context(), testMutableRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}

	// Same pod, different name, same device.
	samePod := testMutableRequest(t)
	samePod.Name = "datasets"
	if err := o.Open(t.Context(), samePod); !errors.Is(err, ErrVolumeInUse) {
		t.Errorf("second mutable open, same pod: got %v, want ErrVolumeInUse", err)
	}

	// Another pod, same device.
	otherPod := testMutableRequest(t)
	otherPod.Pod = testPod(otherUID)
	if err := o.Open(t.Context(), otherPod); !errors.Is(err, ErrVolumeInUse) {
		t.Errorf("second mutable open, other pod: got %v, want ErrVolumeInUse", err)
	}

	// A read-only open of the same device is refused too.
	ro := testRequest(t)
	ro.Pod = testPod(otherUID)
	if err := o.Open(t.Context(), ro); !errors.Is(err, ErrVolumeInUse) {
		t.Errorf("immutable open over a mutable one: got %v, want ErrVolumeInUse", err)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want only the first", o.Len())
	}
}

// The mirror image: a device held mutable refuses every later open, whichever
// mode the later one asks for.
func TestImmutableOpenRefusesAMutableHolderOfTheSameDevice(t *testing.T) {
	root, otherUID := conflictTree(t)
	ops := newOps()
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	mutable := testMutableRequest(t)
	mutable.Pod = testPod(otherUID)
	if err := o.Open(t.Context(), mutable); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("got %v, want ErrVolumeInUse", err)
	}
}

// Read-only mounts of one device share it as they always have.
func TestImmutableOpensShareADevice(t *testing.T) {
	root, otherUID := conflictTree(t)
	ops := newOps()
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	other := testRequest(t)
	other.Pod = testPod(otherUID)
	if err := o.Open(t.Context(), other); err != nil {
		t.Fatalf("second immutable open: %v", err)
	}
	if o.Len() != 2 {
		t.Fatalf("opener holds %d mounts, want 2", o.Len())
	}
}

// Exclusivity is per device, not per daemon: two mutable volumes on distinct
// devices open side by side.
func TestMutableOpensOnDistinctDevicesCoexist(t *testing.T) {
	root, _ := conflictTree(t)
	ops := newOps()
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	if err := o.Open(t.Context(), testMutableRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}
	second := testMutableRequest(t)
	second.Name = "datasets"
	second.Device = "/dev/disk/by-id/virtio-c8s-vol-datasets"
	if err := o.Open(t.Context(), second); err != nil {
		t.Fatalf("second open: %v", err)
	}
	if o.Len() != 2 {
		t.Fatalf("opener holds %d mounts, want 2", o.Len())
	}
}

// The root hash is half the commitment: same key, different integrity anchor is
// a different volume.
func TestOpenRefusesADifferentRootHashForAnOpenVolume(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("first open: %v", err)
	}

	other := testRequest(t)
	v := *other.Blob.Verity
	v.RootHash = strings.Repeat("cd", 32)
	blob, err := volume.NewBlob(volumeKey(), v)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	other.Blob = blob

	if err := o.Open(t.Context(), other); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v, want ErrNotAuthorized", err)
	}
}

func TestOpenCapsLiveMounts(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	o.MaxMounts = 1
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}

	// A different pod, so it is not the idempotent path.
	other := testRequest(t)
	other.Pod = testPod("99999999-8888-7777-6666-555555555555")
	if err := o.Open(t.Context(), other); !errors.Is(err, ErrTooManyMounts) {
		t.Fatalf("got %v, want ErrTooManyMounts", err)
	}
}

func TestCloseTearsDownInReverse(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}

	o.Close(t.Context(), req.Pod.UID, req.Name)
	if got := ops.sequence(); !strings.HasSuffix(got, "Unmount,VerityClose,CryptClose") {
		t.Fatalf("teardown order = %q", got)
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
	if o.Len() != 0 {
		t.Fatal("mount still recorded after close")
	}
}

// Teardown races kubelet removing the pod directory, so closing something
// already gone is not an error.
func TestCloseIsIdempotent(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}
	o.Close(t.Context(), req.Pod.UID, req.Name)
	before := ops.sequence()
	o.Close(t.Context(), req.Pod.UID, req.Name)
	if ops.sequence() != before {
		t.Fatal("closing an absent volume issued more privileged calls")
	}
}

// A failed unmount must not stop the device-mapper targets being removed: they
// are what holds the key.
func TestTeardownContinuesPastAFailedUnmount(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}
	ops.failOn = "Unmount"

	o.Close(t.Context(), req.Pod.UID, req.Name)
	if c, v, _ := ops.leaked(); c != 0 || v != 0 {
		t.Fatalf("a failed unmount left crypt=%d verity=%d behind", c, v)
	}
}

func TestClosePodTearsDownEveryVolumeItHolds(t *testing.T) {
	ops := newOps()
	root, base := kubeletTree(t)
	for _, n := range []string{"weights", "datasets"} {
		if err := os.Mkdir(filepath.Join(base, KubeVolumeName(n)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", n, err)
		}
	}
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	for _, n := range []string{"weights", "datasets"} {
		req := testRequest(t)
		req.Name = n
		if err := o.Open(t.Context(), req); err != nil {
			t.Fatalf("open %s: %v", n, err)
		}
	}
	if o.Len() != 2 {
		t.Fatalf("opener holds %d mounts, want 2", o.Len())
	}

	o.ClosePod(t.Context(), testPodUID)
	if o.Len() != 0 {
		t.Fatalf("opener holds %d mounts after pod teardown", o.Len())
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

func TestOpenRejectsMalformedRequests(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)

	bad := testRequest(t)
	bad.Name = "Weights"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a name that is not a label")
	}

	bad = testRequest(t)
	bad.Blob.Verity.RootHash = "short"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a blob that fails validation")
	}

	bad = testRequest(t)
	bad.Blob.Key = "not base64"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a blob with an unusable key")
	}

	if ops.sequence() != "" {
		t.Errorf("a malformed request reached the privileged steps: %q", ops.sequence())
	}
}

// Two pods opening the same volume get their own mappings, so one pod's
// teardown cannot remove the other's.
func TestMapperNamesAreScopedPerPod(t *testing.T) {
	a := mapperName("crypt", testPodUID, "weights")
	b := mapperName("crypt", "99999999-8888-7777-6666-555555555555", "weights")
	if a == b {
		t.Fatal("two pods share a mapper name")
	}
	if !strings.HasPrefix(a, "c8s-crypt-") {
		t.Fatalf("mapper name = %q", a)
	}
}

func TestCommitmentCoversKeyModeAndRootHash(t *testing.T) {
	key := volumeKey()
	withHash := func(h string) volume.Blob {
		b, err := volume.NewBlob(key, volume.Verity{
			RootHash: h, Salt: "cd", DataBlocks: 4, HashOffset: 4 * volume.VerityBlockSize,
		})
		if err != nil {
			t.Fatalf("blob: %v", err)
		}
		return b
	}
	base := commitmentFor(key, withHash(strings.Repeat("aa", 32)))
	if commitmentFor(key, withHash(strings.Repeat("bb", 32))) == base {
		t.Error("commitment ignores the root hash")
	}
	other := make([]byte, volume.KeyBytes)
	if commitmentFor(other, withHash(strings.Repeat("aa", 32))) == base {
		t.Error("commitment ignores the key")
	}
	mutable, err := volume.NewMutableBlob(key)
	if err != nil {
		t.Fatalf("mutable blob: %v", err)
	}
	if commitmentFor(key, mutable) == base {
		t.Error("commitment ignores the mode")
	}
}

func TestZeroClearsTheBuffer(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d", i, v)
		}
	}
}

// A fetcher whose request deadline expires mid-open cancels the context the
// open is running on. Unwinding on that context cannot remove what the open
// already created — cryptsetup needs a live one — so the mapper name leaks and
// every retry fails with "Device <name> already exists", which is terminal:
// the fetcher retries for its whole budget and the pod never gets its volume.
func TestOpenUnwindsAfterTheCallerContextIsCancelled(t *testing.T) {
	ops := newOps()
	ops.honorCtx = true
	ops.failOn = "VerityOpen"
	o := testOpener(t, ops)

	ctx, cancel := context.WithCancel(t.Context())
	// Cancel the moment the first privileged step lands, the way a deadline
	// expiring mid-open does.
	ops.afterCryptOpen = cancel

	if err := o.Open(ctx, testRequest(t)); err == nil {
		t.Fatal("open succeeded despite a cancelled context")
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Errorf("leaked crypt=%d verity=%d mounts=%d after a cancelled open", c, v, m)
	}
}

// A volume stack outlives the volumed that opened it: the mappings are kernel
// state, and nothing else on a node reaps them. Until they go they hold the
// backing disk open, so the next install cannot reopen the volume.
func TestSweepStaleClosesMappingsLeftByAnEarlierVolumed(t *testing.T) {
	ops := newOps()
	ops.cryptOpen["c8s-crypt-podA-weights"] = true
	ops.verityOpen["c8s-verity-podA-weights"] = true

	o := testOpener(t, ops)
	closed, stuck := o.SweepStale(context.Background())
	if closed != 2 {
		t.Errorf("closed %d mappings, want the crypt and verity pair", closed)
	}
	if len(stuck) != 0 {
		t.Errorf("reported %v as still in use", stuck)
	}
	if len(ops.cryptOpen) != 0 || len(ops.verityOpen) != 0 {
		t.Errorf("mappings survived the sweep: crypt=%v verity=%v", ops.cryptOpen, ops.verityOpen)
	}
	// verity is stacked on crypt and holds it open, so closing crypt first
	// would fail against a real device-mapper.
	var verityAt, cryptAt = -1, -1
	for i, c := range ops.calls {
		switch c {
		case "VerityClose":
			verityAt = i
		case "CryptClose":
			cryptAt = i
		}
	}
	if verityAt < 0 || cryptAt < 0 || verityAt > cryptAt {
		t.Errorf("verity must close before the crypt device under it; calls: %v", ops.calls)
	}
}

// The sweep runs before this process has any state, so the kernel is what
// decides: a mapping something still has mounted refuses to close, and a
// workload's volume is not pulled out from under it.
func TestSweepStaleLeavesAMappingStillInUse(t *testing.T) {
	ops := newOps()
	ops.cryptOpen["c8s-crypt-podA-weights"] = true
	ops.verityOpen["c8s-verity-podA-weights"] = true
	ops.failOn = "VerityClose"

	o := testOpener(t, ops)
	closed, stuck := o.SweepStale(context.Background())
	if closed != 1 {
		t.Errorf("closed %d, want only the crypt mapping", closed)
	}
	if len(stuck) != 1 || stuck[0] != "c8s-verity-podA-weights" {
		t.Errorf("stuck = %v, want the verity mapping that refused", stuck)
	}
	if !ops.verityOpen["c8s-verity-podA-weights"] {
		t.Error("a mapping that refused to close was reported as gone")
	}
}

// Sweeping by name prefix keeps it to volumes this platform opened; the node's
// other device-mapper targets are not ours to close.
func TestSweepStaleTouchesOnlyC8sMappings(t *testing.T) {
	ops := newOps()
	ops.cryptOpen["luks-tenant-disk"] = true
	ops.verityOpen["c8s-verity-podA-weights"] = true

	o := testOpener(t, ops)
	closed, _ := o.SweepStale(context.Background())
	if closed != 1 {
		t.Errorf("closed %d, want only the c8s mapping", closed)
	}
	if !ops.cryptOpen["luks-tenant-disk"] {
		t.Error("closed a device-mapper target this platform did not open")
	}
}

// A caller cancelled before its mapping lands has already posted its close, so
// the mapping must not land — it would outlive the pod with only the reaper
// behind it.
func TestOpenDoesNotLandForACancelledCaller(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	ctx, cancel := context.WithCancel(context.Background())
	ops.afterCryptOpen = cancel

	if err := o.Open(ctx, testRequest(t)); err == nil {
		t.Fatal("a cancelled open landed")
	}
	if o.Len() != 0 {
		t.Fatalf("opener holds %d mounts, want 0", o.Len())
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("cancelled open leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

// A mapping that refuses to close keeps its record, so the device stays marked
// in use and the next close retries the teardown.
func TestCloseKeepsTheRecordOfAStuckMapping(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(context.Background(), testRequest(t)); err != nil {
		t.Fatalf("open: %v", err)
	}

	ops.failOn = "CryptClose"
	if n := o.ClosePod(context.Background(), testPodUID); n != 0 {
		t.Fatalf("a stuck close reported %d closed, want 0", n)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want the stuck 1", o.Len())
	}

	ops.failOn = ""
	if n := o.ClosePod(context.Background(), testPodUID); n != 1 {
		t.Fatalf("retry closed %d, want 1", n)
	}
	if o.Len() != 0 {
		t.Fatalf("opener holds %d mounts, want 0", o.Len())
	}
}
