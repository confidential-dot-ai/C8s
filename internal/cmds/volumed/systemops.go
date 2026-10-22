package volumed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// The only two filesystems a volume can hold: erofs under dm-verity for an
// immutable volume, writable ext4 for a mutable one. The opener picks from the
// validated blob's mode — a filesystem type read from the request would be a
// host-chosen argument to mount(2).
const (
	fsTypeErofs = "erofs"
	fsTypeExt4  = "ext4"
)

// keyFD is where the key file lands in the child. exec.Cmd.ExtraFiles starts at
// 3, and cryptsetup opens it by path.
const keyFD = 3

// Runner executes one device tool, with extra files handed to the child from fd
// 3 up. It exists so the orchestration and its failure paths are testable
// without cryptsetup and device-mapper.
type Runner func(ctx context.Context, name string, extra []*os.File, args ...string) ([]byte, error)

// SystemOps is the real DeviceOps: cryptsetup, veritysetup, and mount(2).
type SystemOps struct {
	// Run executes the device tools; nil uses execRunner.
	Run Runner
}

// CryptOpen creates the plain dm-crypt mapping.
//
// Plain, not LUKS: there is no header on the device, so every parameter comes
// from the key blob and none from bytes the host can rewrite.
//
// An immutable volume's mapping must be read-only at the device layer, not
// only at the mount: a writable mapping lets anything on the node write
// plaintext through it, producing ciphertext under the real key on
// host-visible storage. A mutable volume's is the writable one by design.
func (s SystemOps) CryptOpen(ctx context.Context, device, mapper string, key []byte, readOnly bool) error {
	keyFile, err := keyMemfd(key)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := s.run(ctx, "cryptsetup", []*os.File{keyFile}, cryptOpenArgs(device, mapper, readOnly)...); err != nil {
		return err
	}
	if !readOnly {
		return nil
	}
	if err := assertReadOnly(mapperDir, mapper); err != nil {
		_ = s.CryptClose(ctx, mapper)
		return err
	}
	return nil
}

func (s SystemOps) CryptClose(ctx context.Context, mapper string) error {
	return s.run(ctx, "cryptsetup", nil, "close", mapper)
}

// VerityOpen creates the dm-verity mapping over the crypt device.
//
// Data and hash device are the same device: the tree was appended to the
// filesystem before encryption, so it sits at HashOffset within the plaintext.
func (s SystemOps) VerityOpen(ctx context.Context, dataDev, mapper string, v volume.Verity) error {
	return s.run(ctx, "veritysetup", nil, verityOpenArgs(dataDev, mapper, v)...)
}

func (s SystemOps) VerityClose(ctx context.Context, mapper string) error {
	return s.run(ctx, "veritysetup", nil, "close", mapper)
}

// The hardening every volume mount gets, with and without the read-only flag
// an immutable volume adds.
const (
	mountROFlags uintptr = unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	mountRWFlags uintptr = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
)

// MountRO mounts the opened device read-only at the target handle; MountRW
// mounts it writable.
//
// The syscall is made directly rather than through mount(8): the target is an
// open handle, and passing /proc/self/fd to a subprocess would reopen it by
// path in a process that does not hold it.
func (SystemOps) MountRO(_ context.Context, source string, target *os.File, fsType string) error {
	return doMount(source, target, fsType, mountROFlags)
}

func (SystemOps) MountRW(_ context.Context, source string, target *os.File, fsType string) error {
	return doMount(source, target, fsType, mountRWFlags)
}

func doMount(source string, target *os.File, fsType string, flags uintptr) error {
	if err := unix.Mount(source, ProcPath(target), fsType, flags, ""); err != nil {
		return fmt.Errorf("mount %s at %s: %w", source, target.Name(), err)
	}
	return nil
}

// Unmount detaches the mount. MNT_DETACH so a mount still busy is removed from
// the tree rather than left for kubelet to trip over while tearing the pod down.
// ListMappings names what device-mapper has published, which is the only
// record of a volume stack that outlives the process that opened it.
func (SystemOps) ListMappings(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(mapperDir)
	if err != nil {
		return nil, fmt.Errorf("volumed: read %s: %w", mapperDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func (SystemOps) Unmount(_ context.Context, target string) error {
	if err := unix.Unmount(target, unix.MNT_DETACH); !unmounted(err) {
		return fmt.Errorf("unmount %s: %w", target, err)
	}
	return nil
}

// unmounted reports whether the target is gone, treating "was never mounted"
// and "no longer there" as success. Teardown races kubelet removing the pod
// directory, so arriving second is the normal case, not a failure.
func unmounted(err error) bool {
	return err == nil || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT)
}

// blankProbeBytes is how much of a device Blank reads. mkfs writes its
// superblock and group descriptors inside it, so any formatted volume has
// non-zero ciphertext here.
const blankProbeBytes = 1 << 20

// Blank reads the host-visible ciphertext, never the plaintext: a zeroed
// disk decrypts to noise, so blankness is only visible below dm-crypt.
func (SystemOps) Blank(_ context.Context, device string) (bool, error) {
	f, err := os.Open(device)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, blankProbeBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, fmt.Errorf("read %s: %w", device, err)
	}
	return !slices.ContainsFunc(buf[:n], func(b byte) bool { return b != 0 }), nil
}

func (s SystemOps) MakeExt4(ctx context.Context, device, rootOwner string) error {
	return s.run(ctx, "mkfs.ext4", nil, mkfsArgs(device, rootOwner)...)
}

// mkfsArgs builds a non-interactive mkfs with no reserved blocks: the volume
// has one consumer, and blocks held back for root are blocks it cannot use.
func mkfsArgs(device, rootOwner string) []string {
	ext := "nodiscard"
	if rootOwner != "" {
		ext += ",root_owner=" + rootOwner
	}
	return []string{"-q", "-F", "-m", "0", "-E", ext, device}
}

// cryptOpenArgs builds the plain-mode open.
//
// Every parameter is explicit, and two of them are load-bearing:
//
//   - --hash plain uses the key file's bytes as the key. Without it cryptsetup
//     runs a passphrase hash over them in plain mode, and the default algorithm
//     is a compile-time choice — so the key the device was written with and the
//     key it is opened with would differ silently.
//   - --sector-size 512 matches what wrote the image. For aes-xts-plain64 the
//     tweak is the sector index, and at a larger sector size the numbering
//     depends on iv_large_sectors.
func cryptOpenArgs(device, mapper string, readOnly bool) []string {
	args := []string{
		"open",
		"--type", "plain",
		"--hash", "plain",
		"--key-file", fmt.Sprintf("/proc/self/fd/%d", keyFD),
		"--keyfile-size", strconv.Itoa(volume.KeyBytes),
		"--cipher", "aes-xts-plain64",
		"--key-size", strconv.Itoa(volume.KeyBytes * 8),
		"--sector-size", strconv.Itoa(volume.SectorSize),
	}
	if readOnly {
		args = append(args, "--readonly")
	}
	return append(args, "--batch-mode", device, mapper)
}

// verityOpenArgs builds the verity open with no superblock.
//
// --no-superblock is why the geometry is passed: the alternative is reading it
// from a superblock on the device, which the host writes. Everything here comes
// from the attested blob instead.
func verityOpenArgs(dataDev, mapper string, v volume.Verity) []string {
	return []string{
		"open", dataDev, mapper, dataDev, v.RootHash,
		"--no-superblock",
		"--format", "1",
		"--hash", "sha256",
		"--data-block-size", strconv.FormatUint(volume.VerityBlockSize, 10),
		"--hash-block-size", strconv.FormatUint(volume.VerityBlockSize, 10),
		"--data-blocks", strconv.FormatUint(v.DataBlocks, 10),
		"--hash-offset", strconv.FormatUint(v.HashOffset, 10),
		"--salt", v.Salt,
	}
}

// keyMemfd puts the key in an anonymous file for the child to open.
//
// Not argv (/proc/<pid>/cmdline is readable node-wide), and not a temp file
// (which would put the key on a filesystem). Not stdin either: cryptsetup
// treats a key read from stdin as a passphrase to hash.
func keyMemfd(key []byte) (*os.File, error) {
	if len(key) != volume.KeyBytes {
		return nil, fmt.Errorf("volumed: key is %d bytes, want %d", len(key), volume.KeyBytes)
	}
	fd, err := unix.MemfdCreate("c8s-volume-key", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("volumed: memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "c8s-volume-key")
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, fmt.Errorf("volumed: write key: %w", err)
	}
	// The child opens the memfd afresh through /proc/self/fd, which starts at
	// offset zero, but rewind so the handle is not left mid-file.
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("volumed: rewind key: %w", err)
	}
	return f, nil
}

// assertReadOnly refuses a mapping the kernel reports as writable, rather than
// trusting that --readonly was honoured.
//
// The name is built from an already-validated volume name and pod UID, but this
// is where it becomes a path opened as root, so the bare-name shape is enforced
// here rather than assumed of the caller.
func assertReadOnly(dir, mapper string) error {
	if mapper == "" || strings.ContainsAny(mapper, `/\`) || strings.Contains(mapper, "..") {
		return fmt.Errorf("volumed: mapper name %q is not a bare name", mapper)
	}
	device := filepath.Join(dir, mapper)
	f, err := os.OpenFile(device, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("volumed: open %s: %w", device, err)
	}
	defer f.Close()
	ro, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKROGET)
	if err != nil {
		return fmt.Errorf("volumed: read %s read-only flag: %w", device, err)
	}
	if ro != 1 {
		return fmt.Errorf("volumed: %s opened writable", device)
	}
	return nil
}

func (s SystemOps) run(ctx context.Context, name string, extra []*os.File, args ...string) error {
	run := s.Run
	if run == nil {
		run = execRunner
	}
	if out, err := run(ctx, name, extra, args...); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func execRunner(ctx context.Context, name string, extra []*os.File, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.ExtraFiles = extra
	// No udev services dm events in the guest; without this the dm handshake blocks forever (see scratch-setup.sh).
	cmd.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
	return cmd.CombinedOutput()
}
