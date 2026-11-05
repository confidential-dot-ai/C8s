package volumed

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

func argsAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, flag string) bool {
	return slices.Contains(args, flag)
}

// Without --hash plain, cryptsetup runs a passphrase hash over the key file in
// plain mode, and the default algorithm is a compile-time choice — so the key
// the image was written with and the key it is opened with would differ, and
// the volume would decrypt to noise with nothing to say why.
func TestCryptOpenUsesTheKeyBytesDirectly(t *testing.T) {
	args := cryptOpenArgs("/dev/vdb", "c8s-crypt-x", true)
	if got := argsAfter(args, "--hash"); got != "plain" {
		t.Fatalf("--hash = %q, want plain", got)
	}
	if got := argsAfter(args, "--keyfile-size"); got != "64" {
		t.Fatalf("--keyfile-size = %q, want 64", got)
	}
}

// The tweak is the sector index; at a larger sector size dm-crypt's numbering
// depends on iv_large_sectors, so this must match what wrote the image.
func TestCryptOpenMatchesTheWriterCipherAndSectorSize(t *testing.T) {
	args := cryptOpenArgs("/dev/vdb", "c8s-crypt-x", true)
	if got := argsAfter(args, "--cipher"); got != "aes-xts-plain64" {
		t.Errorf("--cipher = %q", got)
	}
	if got := argsAfter(args, "--sector-size"); got != "512" {
		t.Errorf("--sector-size = %q, want 512", got)
	}
	if got := argsAfter(args, "--key-size"); got != "512" {
		t.Errorf("--key-size = %q, want 512 bits for a 64-byte key", got)
	}
	if got := argsAfter(args, "--type"); got != "plain" {
		t.Errorf("--type = %q, want plain: a LUKS header is host-writable metadata", got)
	}
}

func TestCryptOpenIsReadOnlyAndTakesTheKeyByFD(t *testing.T) {
	args := cryptOpenArgs("/dev/vdb", "c8s-crypt-x", true)
	if !hasFlag(args, "--readonly") {
		t.Error("mapping is not opened read-only")
	}
	if !hasFlag(args, "--shared") {
		t.Error("immutable mappings cannot reopen a device held by another reader")
	}
	if got := argsAfter(args, "--key-file"); got != "/proc/self/fd/3" {
		t.Errorf("--key-file = %q, want the inherited fd", got)
	}
	// The key must never be an argument: /proc/<pid>/cmdline is readable
	// node-wide.
	for _, a := range args {
		if len(a) == volume.KeyBytes || strings.Contains(a, "=") && len(a) > 80 {
			t.Errorf("argv carries something key-shaped: %q", a)
		}
	}
	if args[len(args)-2] != "/dev/vdb" || args[len(args)-1] != "c8s-crypt-x" {
		t.Errorf("device and mapper are not the trailing positionals: %v", args[len(args)-2:])
	}
}

// A mutable volume's mapping is the writable one by design: no --readonly,
// and no read-only assertion to fail it afterwards.
func TestCryptOpenMutableOmitsReadOnly(t *testing.T) {
	args := cryptOpenArgs("/dev/vdb", "c8s-crypt-x", false)
	if hasFlag(args, "--readonly") {
		t.Error("a writable mapping carries --readonly")
	}
	if hasFlag(args, "--shared") {
		t.Error("a writable mapping permits shared device access")
	}
	if args[len(args)-3] != "--batch-mode" || args[len(args)-2] != "/dev/vdb" || args[len(args)-1] != "c8s-crypt-x" {
		t.Errorf("batch-mode, device and mapper are not the trailing arguments: %v", args[len(args)-3:])
	}

	r := &fakeRunner{}
	err := SystemOps{Run: r.run}.CryptOpen(context.Background(), "/dev/vdb", "c8s-crypt-absent", make([]byte, volume.KeyBytes), false)
	if err != nil {
		t.Fatalf("a writable open ran the read-only assertion: %v", err)
	}
}

func TestMountFlags(t *testing.T) {
	if mountROFlags&unix.MS_RDONLY == 0 {
		t.Error("read-only mount without MS_RDONLY")
	}
	if mountRWFlags&unix.MS_RDONLY != 0 {
		t.Error("writable mount carries MS_RDONLY")
	}
	for _, flag := range []uintptr{unix.MS_NOSUID, unix.MS_NODEV, unix.MS_NOEXEC} {
		if mountRWFlags&flag == 0 || mountROFlags&flag == 0 {
			t.Errorf("hardening flag %d missing (rw=%d ro=%d)", flag, mountRWFlags, mountROFlags)
		}
	}
}

// Reading geometry from an on-disk superblock would reintroduce exactly the
// host-controlled metadata parse that omitting a LUKS header removed.
func TestVerityOpenPassesGeometryAndNoSuperblock(t *testing.T) {
	v := volume.Verity{
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 26214400,
		HashOffset: 26214400 * volume.VerityBlockSize,
	}
	args := verityOpenArgs("/dev/mapper/c8s-crypt-x", "c8s-verity-x", v)

	if !hasFlag(args, "--no-superblock") {
		t.Fatal("verity would read a superblock off the device")
	}
	// veritysetup's open action has no confirmation prompt and does not define
	// --batch-mode (a cryptsetup-only global); passing it makes veritysetup
	// exit with a usage error, failing every volume open. See cryptOpenArgs,
	// where --batch-mode is valid.
	if hasFlag(args, "--batch-mode") {
		t.Fatal("veritysetup open rejects --batch-mode; it must not be passed")
	}
	for flag, want := range map[string]string{
		"--hash":            "sha256",
		"--format":          "1",
		"--data-block-size": "4096",
		"--hash-block-size": "4096",
		"--data-blocks":     "26214400",
		"--hash-offset":     "107374182400",
		"--salt":            v.Salt,
	} {
		if got := argsAfter(args, flag); got != want {
			t.Errorf("%s = %q, want %q", flag, got, want)
		}
	}
}

// The tree was appended to the filesystem before encryption, so it lives at
// HashOffset inside the same device.
func TestVerityOpenUsesOneDeviceForDataAndHash(t *testing.T) {
	v := volume.Verity{
		RootHash: strings.Repeat("ab", 32), Salt: "cd",
		DataBlocks: 4, HashOffset: 4 * volume.VerityBlockSize,
	}
	const dev = "/dev/mapper/c8s-crypt-x"
	args := verityOpenArgs(dev, "c8s-verity-x", v)

	// veritysetup open <data_device> <name> <hash_device> <root_hash>
	if args[0] != "open" || args[1] != dev || args[2] != "c8s-verity-x" || args[3] != dev || args[4] != v.RootHash {
		t.Fatalf("positional arguments are wrong: %v", args[:5])
	}
}

// The key goes in an anonymous file: not argv, not a temp file on a
// filesystem, and not stdin, which cryptsetup would treat as a passphrase.
func TestKeyMemfdHoldsTheKeyAndNothingElse(t *testing.T) {
	key := make([]byte, volume.KeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	f, err := keyMemfd(key)
	if err != nil {
		t.Fatalf("memfd: %v", err)
	}
	defer f.Close()

	// A child opens it afresh; read the same way to confirm the contents.
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != volume.KeyBytes {
		t.Fatalf("memfd holds %d bytes, want %d", len(got), volume.KeyBytes)
	}
	for i := range got {
		if got[i] != key[i] {
			t.Fatalf("byte %d differs", i)
		}
	}

	// It is anonymous: nothing on a filesystem to leak or forget to remove.
	if _, err := os.Stat(f.Name()); err == nil {
		t.Errorf("key file %q exists on a filesystem", f.Name())
	}
}

func TestKeyMemfdRejectsAWrongLengthKey(t *testing.T) {
	if _, err := keyMemfd(make([]byte, 32)); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

// A mapping that is not there cannot be confirmed read-only, so the open
// failure is reported rather than treated as a pass.
func TestAssertReadOnlyReportsAnAbsentDevice(t *testing.T) {
	if err := assertReadOnly(t.TempDir(), "c8s-crypt-absent"); err == nil {
		t.Fatal("accepted a mapping that does not exist")
	}
}

// Something that opens but is not a block device has no read-only flag to read.
func TestAssertReadOnlyRejectsANonBlockDevice(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "c8s-crypt-x"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := assertReadOnly(dir, "c8s-crypt-x"); err == nil {
		t.Fatal("accepted something that is not a block device")
	}
}

var _ DeviceOps = SystemOps{}

// Teardown races kubelet removing the pod directory, so arriving after it is
// the normal case; anything else is a real failure.
func TestUnmountedToleratesAnAlreadyGoneTarget(t *testing.T) {
	for _, err := range []error{nil, unix.EINVAL, unix.ENOENT} {
		if !unmounted(err) {
			t.Errorf("%v treated as a failure", err)
		}
	}
	for _, err := range []error{unix.EPERM, unix.EBUSY, errors.New("boom")} {
		if unmounted(err) {
			t.Errorf("%v treated as success", err)
		}
	}
}

// A missing tool is reported, never swallowed: silently continuing would leave
// the caller believing a mapping exists.
func TestRunReportsAMissingTool(t *testing.T) {
	if err := (SystemOps{}).run(context.Background(), "c8s-no-such-tool-exists", nil); err == nil {
		t.Fatal("a missing tool reported success")
	}
}

func testVerity() volume.Verity {
	return volume.Verity{
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 4,
		HashOffset: 4 * volume.VerityBlockSize,
	}
}

// fakeRunner records what the ops asked for and answers as told.
type fakeRunner struct {
	calls  []string
	extra  [][]*os.File
	failOn string
}

func (f *fakeRunner) run(_ context.Context, name string, extra []*os.File, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.extra = append(f.extra, extra)
	if f.failOn != "" && strings.Contains(name+" "+strings.Join(args, " "), f.failOn) {
		return []byte("tool said no"), errors.New("exit status 1")
	}
	return nil, nil
}

func TestOpsDelegateToTheRunner(t *testing.T) {
	r := &fakeRunner{}
	ops := SystemOps{Run: r.run}
	ctx := context.Background()

	if err := ops.CryptClose(ctx, "c8s-crypt-x"); err != nil {
		t.Fatalf("crypt close: %v", err)
	}
	if err := ops.VerityClose(ctx, "c8s-verity-x"); err != nil {
		t.Fatalf("verity close: %v", err)
	}
	if err := ops.VerityOpen(ctx, "/dev/mapper/c8s-crypt-x", "c8s-verity-x", testVerity()); err != nil {
		t.Fatalf("verity open: %v", err)
	}

	want := []string{"cryptsetup close c8s-crypt-x", "veritysetup close c8s-verity-x"}
	for i, w := range want {
		if r.calls[i] != w {
			t.Errorf("call %d = %q, want %q", i, r.calls[i], w)
		}
	}
	if !strings.Contains(r.calls[2], "--no-superblock") {
		t.Errorf("verity open lost --no-superblock: %q", r.calls[2])
	}
}

// The key reaches cryptsetup on fd 3 and never through argv, where
// /proc/<pid>/cmdline would expose it node-wide.
func TestCryptOpenPassesTheKeyOutOfBand(t *testing.T) {
	r := &fakeRunner{}
	key := make([]byte, volume.KeyBytes)
	// assertReadOnly fails here: there is no real mapping to inspect. The open
	// itself is what this covers.
	_ = SystemOps{Run: r.run}.CryptOpen(context.Background(), "/dev/vdb", "c8s-crypt-x", key, true)

	if len(r.calls) == 0 {
		t.Fatal("cryptsetup was never invoked")
	}
	if strings.Contains(r.calls[0], string(key)) {
		t.Error("the key appeared in argv")
	}
	if len(r.extra[0]) != 1 {
		t.Fatalf("cryptsetup got %d extra files, want the key on fd 3", len(r.extra[0]))
	}
}

// A mapping that cannot be confirmed read-only is torn down rather than left
// for the caller to mount.
func TestCryptOpenClosesAMappingItCannotVerify(t *testing.T) {
	r := &fakeRunner{}
	err := SystemOps{Run: r.run}.CryptOpen(context.Background(), "/dev/vdb", "c8s-crypt-absent", make([]byte, volume.KeyBytes), true)
	if err == nil {
		t.Fatal("an unverifiable mapping was accepted")
	}
	if len(r.calls) != 2 || !strings.HasPrefix(r.calls[1], "cryptsetup close") {
		t.Fatalf("calls = %v, want the open followed by a close", r.calls)
	}
}

func TestCryptOpenReportsAFailedTool(t *testing.T) {
	r := &fakeRunner{failOn: "open"}
	err := SystemOps{Run: r.run}.CryptOpen(context.Background(), "/dev/vdb", "c8s-crypt-x", make([]byte, volume.KeyBytes), true)
	if err == nil || !strings.Contains(err.Error(), "tool said no") {
		t.Fatalf("got %v, want the tool's output", err)
	}
}

func TestExecRunnerDisablesUdevSync(t *testing.T) {
	out, err := execRunner(context.Background(), "printenv", nil, "DM_DISABLE_UDEV")
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("DM_DISABLE_UDEV = %q, err = %v", out, err)
	}
}

func TestExecRunnerWiresOutputAndFailure(t *testing.T) {
	out, err := execRunner(context.Background(), "sh", nil, "-c", "echo hello")
	if err != nil || strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if _, err := execRunner(context.Background(), "sh", nil, "-c", "exit 3"); err == nil {
		t.Fatal("a failing tool reported success")
	}
}

// The child opens the memfd afresh, but the handle must not be left mid-file.
func TestKeyMemfdRewindsItsHandle(t *testing.T) {
	f, err := keyMemfd(make([]byte, volume.KeyBytes))
	if err != nil {
		t.Fatalf("memfd: %v", err)
	}
	defer f.Close()
	if at, err := f.Seek(0, io.SeekCurrent); err != nil || at != 0 {
		t.Fatalf("key handle is at %d (err %v), want rewound", at, err)
	}
}

// The mapper name becomes a path opened as root. Callers validate the volume
// name it is built from, but the shape is enforced here too.
func TestAssertReadOnlyRefusesAnythingButABareName(t *testing.T) {
	for _, mapper := range []string{"", "../../etc/shadow", "nested/name", `back\\slash`, "a..b/../c"} {
		if err := assertReadOnly(t.TempDir(), mapper); err == nil || !strings.Contains(err.Error(), "bare name") {
			t.Errorf("assertReadOnly(%q) = %v, want a rejection", mapper, err)
		}
	}
}
