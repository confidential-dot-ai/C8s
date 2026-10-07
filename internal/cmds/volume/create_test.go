package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runCreateDryRun drives the command through cobra so flag validation and the
// build run exactly as they do for an operator, minus the CDS call.
func runCreateDryRun(t *testing.T, dir string, extra ...string) (string, error) {
	t.Helper()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	o := &options{}
	cmd := newCreateCmd(o)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	args := append([]string{
		"--name=weights",
		"--source=" + src,
		"--out=" + filepath.Join(dir, "vol.img"),
		"--path=/tenant-a/volumes/weights",
		"--escrow-out=" + filepath.Join(dir, "escrow.json"),
		"--dry-run",
	}, extra...)
	cmd.SetArgs(args)

	// Build shells out to mkfs.erofs and veritysetup; neither is needed to
	// exercise validation, so a build failure is reported as-is.
	err := cmd.Execute()
	return out.String(), err
}

func TestCreateRejectsOverlongName(t *testing.T) {
	dir := t.TempDir()
	_, err := runCreateDryRun(t, dir, "--name=thirteenchars")
	if err == nil || !strings.Contains(err.Error(), "device serial holds") {
		t.Fatalf("got %v, want a name-length error naming the serial bound", err)
	}
}

func TestCreateRejectsMalformedName(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Weights", "-weights", "weights-", "we/ights"} {
		if _, err := runCreateDryRun(t, dir, "--name="+name); err == nil {
			t.Errorf("name %q: accepted", name)
		}
	}
}

func TestCreateRequiresEscrowOut(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	o := &options{}
	cmd := newCreateCmd(o)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--name=weights", "--source=" + src,
		"--out=" + filepath.Join(dir, "vol.img"),
		"--path=/tenant-a/volumes/weights", "--dry-run",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "escrow-out") {
		t.Fatalf("got %v, want an --escrow-out error", err)
	}
}

func TestCreateRejectsNonCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"tenant-a/volumes/weights", "/tenant-a/../weights", "/tenant-a/volumes/"} {
		if _, err := runCreateDryRun(t, dir, "--path="+p); err == nil {
			t.Errorf("path %q: accepted", p)
		}
	}
}

// Validation must reject before anything is generated or written: a rejected
// invocation should leave no image and no escrow file behind.
func TestCreateValidationLeavesNoArtifacts(t *testing.T) {
	dir := t.TempDir()
	if _, err := runCreateDryRun(t, dir, "--name=thirteenchars"); err == nil {
		t.Fatal("expected rejection")
	}
	for _, f := range []string{"vol.img", "escrow.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s exists after a rejected invocation", f)
		}
	}
}

func TestWriteEscrowRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "escrow.json")
	if err := os.WriteFile(dest, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(dest, blob); err == nil {
		t.Fatal("overwrote an existing escrow file")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "existing" {
		t.Fatal("existing escrow file was modified")
	}
}

func TestWriteEscrowIsOwnerOnlyAndReloadable(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "escrow.json")
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(dest, blob); err != nil {
		t.Fatalf("write escrow: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("escrow mode is %o, want 600", perm)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The escrow file is the recovery path, so it has to decode as a blob.
	if _, err := DecodeBlob(raw); err != nil {
		t.Fatalf("escrow file does not decode as a key blob: %v", err)
	}
}

func TestPrintResultNamesSerialAnnotationGrantAndMountPolicy(t *testing.T) {
	var out bytes.Buffer
	printResult(&out, createConfig{
		name: "weights", out: "/tmp/vol.img", escrowOut: "/tmp/escrow.json", node: "node-1",
	}, "/tenant-a/volumes/weights", 0, Verity{DataBlocks: 4})
	got := out.String()
	for _, want := range []string{
		"c8s-vol-weights",
		`confidential.ai/c8s-volumes: "weights=/tenant-a/volumes/weights"`,
		"kubernetes.io/hostname: node-1",
		`"read": ["/tenant-a/volumes/weights"]`,
		`"mounts": {"policy": "any"}`,
		"mounts this volume into every container",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// A subtree grant would hand over every volume beneath the base.
	if strings.Contains(got, "/**") {
		t.Errorf("output offers a subtree grant:\n%s", got)
	}
	// The credential volume reaches the injected containers alone, so an entry
	// admitting it would describe a mount its containers never hold.
	if strings.Contains(got, "cert volume") {
		t.Errorf("output asks the entry to admit the credential volume:\n%s", got)
	}
}

func TestNewCmdRegistersCreate(t *testing.T) {
	cmd := newCmd(nil)
	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	if !containsStr(names, "create") {
		t.Fatalf("subcommands = %v, want create", names)
	}
}

func containsStr(hay []string, needle string) bool {
	return slices.Contains(hay, needle)
}

func TestWriteEscrowReportsAnUnwritableDestination(t *testing.T) {
	blob, err := NewBlob(testKey(), validVerity())
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	if err := writeEscrow(filepath.Join(t.TempDir(), "missing-dir", "escrow.json"), blob); err == nil {
		t.Fatal("accepted a path whose directory does not exist")
	}
}

// runCreateArgs drives the command through cobra with exactly the given flags,
// for validation tests that need source-less invocations. A rejected
// invocation must fail before any build runs, so no tool fakes are needed.
func runCreateArgs(dir string, extra ...string) error {
	o := &options{}
	cmd := newCreateCmd(o)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{
		"--name=weights",
		"--out=" + filepath.Join(dir, "vol.img"),
		"--path=/tenant-a/volumes/weights",
		"--escrow-out=" + filepath.Join(dir, "escrow.json"),
		"--dry-run",
	}, extra...))
	return cmd.Execute()
}

func TestCreateImmutableRequiresSource(t *testing.T) {
	dir := t.TempDir()
	err := runCreateArgs(dir)
	if err == nil || !strings.Contains(err.Error(), "--source is required") {
		t.Fatalf("got %v, want a --source error", err)
	}
}

// An immutable image sizes itself to what it packs; a size would say nothing.
func TestCreateRejectsSizeWithoutMutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	err := runCreateArgs(dir, "--source="+src, "--size=50Gi")
	if err == nil || !strings.Contains(err.Error(), "--size is only valid with --mutable") {
		t.Fatalf("got %v, want a --size/--mutable error", err)
	}
}

// A mutable volume with no source has nothing to be sized from.
func TestCreateMutableWithoutSourceOrSizeIsRejected(t *testing.T) {
	dir := t.TempDir()
	err := runCreateArgs(dir, "--mutable")
	if err == nil || !strings.Contains(err.Error(), "--size is required") {
		t.Fatalf("got %v, want a --size error", err)
	}
}

func TestCreateRejectsBadSize(t *testing.T) {
	dir := t.TempDir()
	for _, size := range []string{"bogus", "-5", "0"} {
		if err := runCreateArgs(dir, "--mutable", "--size="+size); err == nil {
			t.Errorf("size %q: accepted", size)
		}
	}
}

func TestParseSize(t *testing.T) {
	for input, want := range map[string]uint64{
		"50Gi":        50 << 30,
		"512Mi":       512 << 20,
		"10G":         10_000_000_000,
		"10737418240": 10 << 30,
	} {
		got, err := parseSize(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
		} else if got != want {
			t.Errorf("%q = %d, want %d", input, got, want)
		}
	}
	for _, input := range []string{"", "bogus", "-5", "0", "1.5.2"} {
		if _, err := parseSize(input); err == nil {
			t.Errorf("%q: accepted", input)
		}
	}
}
