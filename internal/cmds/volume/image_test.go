package volume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeTools stands in for mkfs.erofs and veritysetup so the orchestration is
// exercised without either installed. It writes the sizes it is told to and
// records the argv it was called with.
type fakeTools struct {
	dataBytes int
	treeBytes int
	rootHash  string
	calls     [][]string
	failOn    string
}

func (f *fakeTools) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn == name {
		return nil, errors.New("tool failed")
	}
	switch name {
	case "mkfs.erofs":
		// argv is [...flags, dest, source]
		dest := args[len(args)-2]
		if err := os.WriteFile(dest, bytes.Repeat([]byte{0xA5}, f.dataBytes), 0o600); err != nil {
			return nil, err
		}
		return nil, nil
	case "veritysetup":
		tree := args[2]
		if err := os.WriteFile(tree, bytes.Repeat([]byte{0x5A}, f.treeBytes), 0o600); err != nil {
			return nil, err
		}
		return []byte("VERITY header information\nRoot hash:      " + f.rootHash + "\n"), nil
	case "mkfs.ext4":
		// argv is [...flags, dest]; the caller already sized dest. The fake
		// leaves it zeroed, which is valid plaintext to encrypt.
		return nil, nil
	}
	return nil, errors.New("unexpected tool " + name)
}

func newFake() *fakeTools {
	return &fakeTools{
		dataBytes: 4 * VerityBlockSize,
		treeBytes: VerityBlockSize,
		rootHash:  strings.Repeat("ab", 32),
	}
}

func buildInto(t *testing.T, f *fakeTools) (Verity, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	out := filepath.Join(dir, "vol.img")
	key := testKey()

	v, err := Build(t.Context(), BuildConfig{Source: src, Out: out, Key: key, Run: f.run})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return v, out, key
}

func TestBuildProducesDecryptableConcatenation(t *testing.T) {
	f := newFake()
	v, out, key := buildInto(t, f)

	ct, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	if len(ct) != f.dataBytes+f.treeBytes {
		t.Fatalf("image is %d bytes, want %d", len(ct), f.dataBytes+f.treeBytes)
	}

	var plain bytes.Buffer
	if err := Decrypt(&plain, bytes.NewReader(ct), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	want := append(bytes.Repeat([]byte{0xA5}, f.dataBytes), bytes.Repeat([]byte{0x5A}, f.treeBytes)...)
	if !bytes.Equal(plain.Bytes(), want) {
		t.Fatal("decrypted image is not the erofs data followed by the hash tree")
	}

	// The geometry has to describe the layout that was actually written, or the
	// opener hashes the wrong bytes.
	if v.HashOffset != uint64(f.dataBytes) {
		t.Errorf("hash_offset = %d, want %d", v.HashOffset, f.dataBytes)
	}
	if v.DataBlocks != uint64(f.dataBytes)/VerityBlockSize {
		t.Errorf("data_blocks = %d, want %d", v.DataBlocks, f.dataBytes/VerityBlockSize)
	}
	if _, err := NewBlob(key, v); err != nil {
		t.Errorf("build produced geometry a blob rejects: %v", err)
	}
}

// The tree must be encrypted as a continuation of the data, not as its own
// stream: sector indices are the XTS tweaks, and they run continuously across
// the join when the device is read.
func TestBuildEncryptsTreeAsContinuationOfData(t *testing.T) {
	f := newFake()
	_, out, key := buildInto(t, f)
	ct, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}

	var whole bytes.Buffer
	plain := append(bytes.Repeat([]byte{0xA5}, f.dataBytes), bytes.Repeat([]byte{0x5A}, f.treeBytes)...)
	if err := Encrypt(&whole, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(ct, whole.Bytes()) {
		t.Fatal("image differs from encrypting data||tree as one stream")
	}
}

func TestBuildPassesNoSuperblockAndExplicitGeometry(t *testing.T) {
	f := newFake()
	buildInto(t, f)

	var verity []string
	for _, c := range f.calls {
		if c[0] == "veritysetup" {
			verity = c
		}
	}
	if verity == nil {
		t.Fatal("veritysetup was never invoked")
	}
	joined := strings.Join(verity, " ")
	for _, want := range []string{"--no-superblock", "--hash sha256", "--data-block-size 4096", "--salt "} {
		if !strings.Contains(joined, want) {
			t.Errorf("veritysetup argv missing %q: %s", want, joined)
		}
	}
}

// Replacing an existing image would destroy a volume whose key is already in
// the store, so the output is created O_EXCL.
func TestBuildRefusesToOverwriteExistingImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	out := filepath.Join(dir, "vol.img")
	if err := os.WriteFile(out, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed out: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{Source: src, Out: out, Key: testKey(), Run: newFake().run}); err == nil {
		t.Fatal("build overwrote an existing image")
	}
}

func TestBuildRejectsUnalignedErofsImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()
	f.dataBytes = VerityBlockSize + 7
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), Run: f.run,
	}); err == nil {
		t.Fatal("accepted an erofs image that is not block-aligned")
	}
}

func TestBuildRejectsMissingSource(t *testing.T) {
	dir := t.TempDir()
	if _, err := Build(t.Context(), BuildConfig{
		Source: filepath.Join(dir, "nope"), Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a source directory that does not exist")
	}
}

func TestParseRootHash(t *testing.T) {
	good := hex.EncodeToString(mustSum("x"))
	got, err := parseRootHash([]byte("Root hash:\t" + strings.ToUpper(good) + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != good {
		t.Fatalf("root hash = %q, want lowercase %q", got, good)
	}
	for name, out := range map[string]string{
		"absent":    "VERITY header information\n",
		"truncated": "Root hash: abcd\n",
	} {
		if _, err := parseRootHash([]byte(out)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustSum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestBuildRejectsFileAsSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "weights.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: newFake().run,
	})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("got %v, want a not-a-directory error", err)
	}
}

func TestBuildRejectsWrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: make([]byte, 32), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

// A work directory that cannot be created is reported before the build starts,
// rather than surfacing as a confusing failure from mkfs.erofs.
func TestBuildRejectsUnusableWorkDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(),
		WorkDir: filepath.Join(blocker, "under-a-file"), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a work dir that cannot be created")
	}
}

func TestBuildFailsWhenErofsFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()
	f.failOn = "mkfs.erofs"
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: f.run,
	}); err == nil {
		t.Fatal("build succeeded despite mkfs.erofs failing")
	}
}

func mkfsExt4Call(t *testing.T, f *fakeTools) string {
	t.Helper()
	for _, c := range f.calls {
		if c[0] == "mkfs.ext4" {
			return strings.Join(c, " ")
		}
	}
	t.Fatal("mkfs.ext4 was never invoked")
	return ""
}

func TestBuildMutableProducesSizedDecryptableImage(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "vol.img")
	key := testKey()
	f := newFake()
	const size = 20 << 20

	got, err := BuildMutable(t.Context(), MutableBuildConfig{Out: out, Key: key, Size: size, Run: f.run})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got != size {
		t.Fatalf("size = %d, want %d", got, size)
	}
	ct, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	if len(ct) != size {
		t.Fatalf("image is %d bytes, want %d", len(ct), size)
	}

	// Every sector is real ciphertext, free space included: the whole image
	// must decrypt, to the zeroed plaintext the fake left behind.
	var plain bytes.Buffer
	if err := Decrypt(&plain, bytes.NewReader(ct), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain.Bytes(), make([]byte, size)) {
		t.Fatal("decrypted image is not the zeroed filesystem the build wrote")
	}

	argv := mkfsExt4Call(t, f)
	for _, want := range []string{"-b 4096", "-m 0", "-e remount-ro"} {
		if !strings.Contains(argv, want) {
			t.Errorf("mkfs.ext4 argv missing %q: %s", want, argv)
		}
	}
	if strings.Contains(argv, " -d ") {
		t.Errorf("mkfs.ext4 preloads without a source: %s", argv)
	}
	if strings.Contains(argv, "root_owner") {
		t.Errorf("mkfs.ext4 sets a root owner without a source: %s", argv)
	}
}

// A source with no size is sized from the tree, grown and rounded, and the
// size actually built is handed back so the operator sees it.
func TestBuildMutableInfersSizeFromSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	const payload = 3 << 20
	if err := os.WriteFile(filepath.Join(src, "weights.bin"), make([]byte, payload), 0o600); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	f := newFake()

	got, err := BuildMutable(t.Context(), MutableBuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), Run: f.run,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The walk counts the directory itself as an entry.
	if want := inferSize(payload, 2); got != want {
		t.Fatalf("size = %d, want the inferred %d", got, want)
	}
	if argv := mkfsExt4Call(t, f); !strings.Contains(argv, " -d "+src) {
		t.Errorf("mkfs.ext4 argv does not preload the source: %s", argv)
	}
}

// An explicit size is used as given (rounded up to a whole block), with the
// source preloaded.
func TestBuildMutableHonorsAnExplicitSize(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()

	got, err := BuildMutable(t.Context(), MutableBuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), Size: 100<<20 + 1, Run: f.run,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if want := uint64(100<<20 + ImageBlockSize); got != want {
		t.Fatalf("size = %d, want %d (rounded to a whole block)", got, want)
	}
}

// mkfs.ext4 -d does not apply the source directory's own owner to the image
// root, so the build passes it as root_owner: a consumer that owns the seed
// can then create files at the mount root.
func TestBuildMutableGivesTheRootTheSourceOwner(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()

	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), Size: 100 << 20, Run: f.run,
	}); err != nil {
		t.Fatalf("build: %v", err)
	}
	want := fmt.Sprintf("-E root_owner=%d:%d -d %s", os.Getuid(), os.Getgid(), src)
	if argv := mkfsExt4Call(t, f); !strings.Contains(argv, want) {
		t.Errorf("mkfs.ext4 argv = %s, want it to contain %q", argv, want)
	}
}

var debugfsOwnerRE = regexp.MustCompile(`User:\s+(\d+)\s+Group:\s+(\d+)`)

// The same arguments with the real mkfs.ext4: the image root is owned by the
// source directory's owner, and its entries keep their own owner.
func TestExt4ArgsRootOwnerWithRealMkfs(t *testing.T) {
	for _, tool := range []string{"mkfs.ext4", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	info, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat src: %v", err)
	}
	owner := ownerOf(info)
	img := filepath.Join(dir, "data.ext4")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := os.Truncate(img, minMutableBytes); err != nil {
		t.Fatalf("size image: %v", err)
	}
	if out, err := exec.Command("mkfs.ext4", ext4Args(img, src, owner, 0)...).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	stat := func(path string) string {
		cmd := exec.Command("debugfs", "-R", "stat "+path, img)
		cmd.Env = append(os.Environ(), "DEBUGFS_PAGER=__none__")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("debugfs stat %s: %v", path, err)
		}
		m := debugfsOwnerRE.FindStringSubmatch(string(out))
		if m == nil {
			t.Fatalf("debugfs stat %s printed no owner: %s", path, out)
		}
		return m[1] + ":" + m[2]
	}
	if got := stat("/"); got != owner {
		t.Errorf("image root owner = %s, want the source owner %s", got, owner)
	}
	if got := stat("/sub"); got != owner {
		t.Errorf("image /sub owner = %s, want the source owner %s", got, owner)
	}
}

func TestBuildMutableRejectsBadInvocations(t *testing.T) {
	dir := t.TempDir()
	f := newFake()

	// No source and no size: there is nothing to size from.
	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Out: filepath.Join(dir, "a.img"), Key: testKey(), Run: f.run,
	}); err == nil || !strings.Contains(err.Error(), "--size") {
		t.Errorf("got %v, want a --size error", err)
	}

	// Below the floor ext4's own metadata leaves nothing to write into.
	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Out: filepath.Join(dir, "b.img"), Key: testKey(), Size: 4 << 20, Run: f.run,
	}); err == nil {
		t.Error("accepted a size below the minimum")
	}

	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Out: filepath.Join(dir, "c.img"), Key: make([]byte, 32), Size: 20 << 20, Run: f.run,
	}); err == nil {
		t.Error("accepted a 32-byte key")
	}

	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Source: filepath.Join(dir, "nope"), Out: filepath.Join(dir, "d.img"), Key: testKey(), Run: f.run,
	}); err == nil {
		t.Error("accepted a source directory that does not exist")
	}
}

func TestBuildMutableRefusesToOverwriteExistingImage(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "vol.img")
	if err := os.WriteFile(out, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed out: %v", err)
	}
	if _, err := BuildMutable(t.Context(), MutableBuildConfig{
		Out: out, Key: testKey(), Size: 20 << 20, Run: newFake().run,
	}); err == nil {
		t.Fatal("build overwrote an existing image")
	}
}

func TestInferSize(t *testing.T) {
	// A tiny tree gets the floor, grown nowhere.
	if got := inferSize(100, 3); got != minMutableBytes {
		t.Errorf("inferSize(100, 3) = %d, want the %d-byte floor", got, minMutableBytes)
	}
	// Otherwise: bytes plus a block per entry, grown by half, rounded to
	// whole mebibytes.
	got := inferSize(32<<20, 1)
	want := alignUp((32<<20+ImageBlockSize)*3/2, 4<<20)
	if got != want {
		t.Errorf("inferSize(32MiB, 1) = %d, want %d", got, want)
	}
}

func TestInferInodes(t *testing.T) {
	// Few entries on a large image: the default ratio suffices.
	if got := inferInodes(1<<30, 10); got != 0 {
		t.Errorf("inferInodes(1GiB, 10) = %d, want the default", got)
	}
	// A tree of small files outnumbers it.
	if got := inferInodes(1<<30, 100000); got != 200000 {
		t.Errorf("inferInodes(1GiB, 100000) = %d, want 200000", got)
	}
}

func TestBuildCleansPlaintextAndPreservesWorkDir(t *testing.T) {
	for _, mutable := range []bool{false, true} {
		for _, outcome := range []string{"success", "format failure", "missing image", "unaligned image"} {
			t.Run(fmt.Sprintf("mutable=%t/%s", mutable, outcome), func(t *testing.T) {
				work := t.TempDir()
				marker := filepath.Join(work, "unrelated")
				if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				tools := newFake()
				failed := errors.New("formatter failed after writing plaintext")
				run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
					out, err := tools.run(ctx, name, args...)
					if err != nil || name == "mkfs.erofs" {
						return out, err
					}
					lastImage := args[len(args)-1]
					if name == "veritysetup" {
						lastImage = args[2]
					}
					switch outcome {
					case "format failure":
						return nil, failed
					case "missing image":
						return out, os.Remove(lastImage)
					case "unaligned image":
						return out, os.Truncate(lastImage, 1)
					}
					return out, nil
				}
				out := filepath.Join(t.TempDir(), "vol.img")
				var err error
				if mutable {
					_, err = BuildMutable(t.Context(), MutableBuildConfig{
						Out: out, Key: testKey(), Size: minMutableBytes, WorkDir: work, Run: run,
					})
				} else {
					_, err = Build(t.Context(), BuildConfig{
						Source: t.TempDir(), Out: out, Key: testKey(), WorkDir: work, Run: run,
					})
				}
				if (err != nil) != (outcome != "success") {
					t.Fatalf("build error = %v", err)
				}
				if outcome == "format failure" && !errors.Is(err, failed) {
					t.Fatalf("lost formatter error: %v", err)
				}
				entries, err := os.ReadDir(work)
				if err != nil || len(entries) != 1 || entries[0].Name() != "unrelated" {
					t.Fatalf("workdir after build = %v, error = %v", entries, err)
				}
				data, err := os.ReadFile(marker)
				if err != nil || string(data) != "keep" {
					t.Fatalf("unrelated file = %q, error = %v", data, err)
				}
			})
		}
	}
}
