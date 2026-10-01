package volume

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// saltBytes is the dm-verity salt length. Fixed, and generated per build: the
// salt is not secret, but a per-image one keeps two volumes built from the same
// directory from sharing a hash tree.
const saltBytes = 32

// ImageBlockSize is the unit every built image is a whole number of: ext4's
// block size for a mutable volume, dm-verity's for an immutable one. Same
// value, two reasons — attach checks copies against it.
const ImageBlockSize = 4096

// minMutableBytes floors a mutable volume: below it ext4's own metadata leaves
// no room to write anything.
const minMutableBytes = 16 << 20

// Runner executes one build tool. It exists so the orchestration is testable
// without erofs-utils and cryptsetup on the machine running the tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner runs a tool for real, with SOURCE_DATE_EPOCH pinned so mkfs.erofs
// does not stamp the current time into the image.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=0", "TZ=UTC", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// BuildConfig describes one image build.
type BuildConfig struct {
	// Source is the directory whose contents become the volume.
	Source string
	// Out is where the encrypted image is written. It must not already exist.
	Out string
	// Key is the XTS key; GenerateKey supplies it.
	Key []byte
	// WorkDir holds the intermediate plaintext image and hash tree. Empty uses
	// a temp dir. Both intermediates are removed on the way out, whatever
	// happens — they are the plaintext this whole design exists to protect.
	WorkDir string
	// Run executes the build tools; nil uses execRunner.
	Run Runner
}

// Build packages Source into an erofs image, formats a dm-verity tree over it,
// concatenates the two, and encrypts the result to Out.
//
// The tree goes inside the encryption rather than outside it. A hash tree is a
// fingerprint of the plaintext, so leaving it in the clear would hand the host
// a way to identify the contents; and the root hash then commits to the data
// itself rather than to one encryption of it.
func Build(ctx context.Context, cfg BuildConfig) (Verity, error) {
	if err := checkSource(cfg.Source); err != nil {
		return Verity{}, err
	}
	if len(cfg.Key) != KeyBytes {
		return Verity{}, fmt.Errorf("volume: key is %d bytes, want %d", len(cfg.Key), KeyBytes)
	}
	b := &immutableImage{source: cfg.Source}
	if err := buildImage(ctx, cfg, b); err != nil {
		return Verity{}, err
	}
	return b.verity, nil
}

type immutableImage struct {
	source     string
	data, tree imagePart
	verity     Verity
}

func (b *immutableImage) prepare(work string) []imagePart {
	b.data = imagePart{filepath.Join(work, "data.erofs"), "erofs image"}
	b.tree = imagePart{filepath.Join(work, "hash.tree"), "hash tree"}
	return []imagePart{b.data, b.tree}
}

func (b *immutableImage) build(ctx context.Context, run Runner) error {
	dataPath, treePath := b.data.path, b.tree.path
	if _, err := run(ctx, "mkfs.erofs", erofsArgs(dataPath, b.source)...); err != nil {
		return err
	}
	dataSize, err := fileSize(dataPath)
	if err != nil {
		return err
	}
	if dataSize == 0 || dataSize%VerityBlockSize != 0 {
		return fmt.Errorf("volume: erofs image is %d bytes, not a multiple of %d", dataSize, VerityBlockSize)
	}

	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("volume: generate verity salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)

	stdout, err := run(ctx, "veritysetup", verityArgs(dataPath, treePath, saltHex)...)
	if err != nil {
		return err
	}
	rootHash, err := parseRootHash(stdout)
	if err != nil {
		return err
	}

	b.verity = Verity{
		RootHash:   rootHash,
		Salt:       saltHex,
		DataBlocks: dataSize / VerityBlockSize,
		HashOffset: dataSize,
	}
	return nil
}

// MutableBuildConfig describes one writable image build.
type MutableBuildConfig struct {
	// Source, when set, is the directory preloaded into the filesystem.
	Source string
	// Out is where the encrypted image is written. It must not already exist.
	Out string
	// Key is the XTS key; GenerateKey supplies it.
	Key []byte
	// Size is the filesystem size in bytes. Zero infers it from Source, which
	// is then required.
	Size uint64
	// WorkDir holds the intermediate plaintext image, as in BuildConfig.
	WorkDir string
	// Run executes the build tools; nil uses execRunner.
	Run Runner
}

// BuildMutable builds a writable ext4 image of Size bytes — preloaded from
// Source when one is given — and encrypts it to Out, returning the size
// actually built so an inferred Size is reported back to the operator.
//
// Every sector is encrypted, free space included: a sector left unwritten
// would read back as the XTS decryption of zeros rather than the plaintext
// zeros the filesystem expects, so the image must hold real ciphertext end to
// end.
func BuildMutable(ctx context.Context, cfg MutableBuildConfig) (uint64, error) {
	if len(cfg.Key) != KeyBytes {
		return 0, fmt.Errorf("volume: key is %d bytes, want %d", len(cfg.Key), KeyBytes)
	}
	size := cfg.Size
	var inodes uint64
	var rootOwner string
	if cfg.Source != "" {
		if err := checkSource(cfg.Source); err != nil {
			return 0, err
		}
		owner, err := sourceRootOwner(cfg.Source)
		if err != nil {
			return 0, err
		}
		rootOwner = owner
		dataBytes, entries, err := treeSize(cfg.Source)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			size = inferSize(dataBytes, entries)
		}
		inodes = inferInodes(size, entries)
	}
	if size == 0 {
		return 0, fmt.Errorf("volume: a mutable volume without --source needs --size")
	}
	size = alignUp(size, ImageBlockSize)
	if size < minMutableBytes {
		return 0, fmt.Errorf("volume: mutable volume size %d is below the %d MiB minimum",
			size, minMutableBytes>>20)
	}

	b := &mutableImage{source: cfg.Source, rootOwner: rootOwner, size: size, inodes: inodes}
	if err := buildImage(ctx, BuildConfig{Out: cfg.Out, Key: cfg.Key, WorkDir: cfg.WorkDir, Run: cfg.Run}, b); err != nil {
		return 0, err
	}
	return size, nil
}

type mutableImage struct {
	source string
	// rootOwner is the source directory's "uid:gid", for the image root.
	rootOwner    string
	data         imagePart
	size, inodes uint64
}

func (b *mutableImage) prepare(work string) []imagePart {
	b.data = imagePart{filepath.Join(work, "data.ext4"), "intermediate image"}
	return []imagePart{b.data}
}

func (b *mutableImage) build(ctx context.Context, run Runner) error {
	dataPath := b.data.path
	data, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("volume: create intermediate image: %w", err)
	}
	if err := data.Truncate(int64(b.size)); err != nil {
		data.Close()
		return fmt.Errorf("volume: size intermediate image: %w", err)
	}
	if err := data.Close(); err != nil {
		return fmt.Errorf("volume: close intermediate image: %w", err)
	}

	_, err = run(ctx, "mkfs.ext4", ext4Args(dataPath, b.source, b.rootOwner, b.inodes)...)
	return err
}

// ext4Args builds a 4K-block ext4 with no root-reserved blocks, preloading
// source when given. Reserved blocks exist to keep a host's root user able to
// write; a volume whose whole content is tenant data gets nothing from them.
// -e remount-ro matches the platform rootfs: a filesystem error degrades the
// mount to read-only rather than letting corruption spread — on a volume with
// no integrity layer, the most likely cause is a host flipping bits.
// Ownership and modes of the source's entries are preserved, as on the
// immutable path. -d does not apply them to the root directory itself, which
// mkfs.ext4 creates as 0:0 — so root_owner copies the source root's owner, or
// a non-root consumer could not create files at the mount root. The root
// mode stays mkfs's 0755, which lets that owner write; root_perms would copy
// the mode too, but e2fsprogs before 1.47.1 rejects it.
func ext4Args(dest, source, rootOwner string, inodes uint64) []string {
	args := []string{"-q", "-F", "-b", fmt.Sprint(ImageBlockSize), "-m", "0", "-e", "remount-ro"}
	if inodes > 0 {
		args = append(args, "-N", fmt.Sprint(inodes))
	}
	if rootOwner != "" {
		args = append(args, "-E", "root_owner="+rootOwner)
	}
	if source != "" {
		args = append(args, "-d", source)
	}
	return append(args, dest)
}

// inferSize estimates what a source tree needs: its bytes plus a block per
// entry, grown by half so the volume is not born full, floored and rounded to
// whole mebibytes.
func inferSize(dataBytes, entries uint64) uint64 {
	need := (dataBytes + entries*ImageBlockSize) * 3 / 2
	return alignUp(max(need, minMutableBytes), 4<<20)
}

// inferInodes raises the inode count when the source tree's entries outnumber
// what the default ratio gives the image, so a tree of small files does not
// run mkfs out of inodes while blocks remain. Zero keeps the default.
func inferInodes(size, entries uint64) uint64 {
	const defaultInodeRatio = 16384
	if inodes := entries * 2; inodes > size/defaultInodeRatio {
		return inodes
	}
	return 0
}

// treeSize totals a source tree's bytes and entries, the inputs to inferSize.
func treeSize(source string) (dataBytes, entries uint64, err error) {
	err = filepath.Walk(source, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		entries++
		if info.Mode().IsRegular() {
			dataBytes += uint64(info.Size())
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("volume: measure --source: %w", err)
	}
	return dataBytes, entries, nil
}

func alignUp(n, unit uint64) uint64 {
	return (n + unit - 1) / unit * unit
}

// erofsArgs pins the inputs that would otherwise vary per build, so the same
// source directory yields the same image and therefore the same root hash.
//
// Ownership and mode are deliberately not normalized: they are preserved into
// the image and therefore covered by the root hash. Forcing them to root would
// make a 0600 source file unreadable to a non-root workload.
//
// Reproducibility across erofs-utils versions is NOT established — pin the tool
// version alongside this if you depend on it.
func erofsArgs(dest, source string) []string {
	return []string{
		"-U", "00000000-0000-0000-0000-000000000000",
		"-T", "0",
		dest, source,
	}
}

// verityArgs formats the tree with every parameter explicit and no superblock.
//
// --no-superblock is load-bearing: the opener passes it too and takes the
// geometry from the key blob instead. A superblock would be host-writable
// metadata read at open time, which is the thing omitting a LUKS header removed.
func verityArgs(data, tree, saltHex string) []string {
	return []string{
		"format", data, tree,
		"--no-superblock",
		"--hash", "sha256",
		"--format", "1",
		"--data-block-size", fmt.Sprint(VerityBlockSize),
		"--hash-block-size", fmt.Sprint(VerityBlockSize),
		"--salt", saltHex,
	}
}

var rootHashRE = regexp.MustCompile(`(?im)^Root hash:\s*([0-9a-fA-F]+)\s*$`)

func parseRootHash(veritysetupOutput []byte) (string, error) {
	m := rootHashRE.FindSubmatch(veritysetupOutput)
	if m == nil {
		return "", fmt.Errorf("volume: veritysetup printed no root hash: %s", strings.TrimSpace(string(veritysetupOutput)))
	}
	root := strings.ToLower(string(m[1]))
	if len(root) != verityHashBytes*2 {
		return "", fmt.Errorf("volume: veritysetup root hash is %d hex chars, want %d", len(root), verityHashBytes*2)
	}
	return root, nil
}

// imagePart order is the plaintext stream order, including the verity tree.
type imagePart struct {
	path, description string
}

type imageBuilder interface {
	prepare(work string) []imagePart
	build(context.Context, Runner) error
}

func buildImage(ctx context.Context, cfg BuildConfig, builder imageBuilder) error {
	run := cfg.Run
	if run == nil {
		run = execRunner
	}
	out, err := os.OpenFile(cfg.Out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("volume: create %s: %w", cfg.Out, err)
	}
	defer out.Close()
	work, cleanup, err := workDir(cfg.WorkDir)
	if err != nil {
		return err
	}
	defer cleanup()
	files := builder.prepare(work)
	for _, part := range files {
		defer os.Remove(part.path)
	}
	if err := builder.build(ctx, run); err != nil {
		return err
	}
	readers := make([]io.Reader, 0, len(files))
	for _, part := range files {
		f, err := os.Open(part.path)
		if err != nil {
			return fmt.Errorf("volume: open %s: %w", part.description, err)
		}
		defer f.Close()
		readers = append(readers, f)
	}
	return Encrypt(out, io.MultiReader(readers...), cfg.Key)
}

func checkSource(source string) error {
	if source == "" {
		return fmt.Errorf("volume: --source is required")
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("volume: --source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("volume: --source %s is not a directory", source)
	}
	return nil
}

// sourceRootOwner returns the "uid:gid" that owns the source directory.
func sourceRootOwner(source string) (string, error) {
	info, err := os.Stat(source)
	if err != nil {
		return "", fmt.Errorf("volume: --source: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("volume: --source %s: cannot read its owner", source)
	}
	return fmt.Sprintf("%d:%d", st.Uid, st.Gid), nil
}

func fileSize(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("volume: stat %s: %w", path, err)
	}
	return uint64(info.Size()), nil
}

func workDir(configured string) (string, func(), error) {
	if configured != "" {
		if err := os.MkdirAll(configured, 0o700); err != nil {
			return "", nil, fmt.Errorf("volume: --work-dir: %w", err)
		}
		return configured, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "c8s-volume-")
	if err != nil {
		return "", nil, fmt.Errorf("volume: create work dir: %w", err)
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}
