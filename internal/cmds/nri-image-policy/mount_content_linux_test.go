//go:build linux

package nriimagepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestHostContentRequiresImmutableRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nvidia-smi")
	if err := os.WriteFile(path, []byte("reviewed executable bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{path, "/dev/null", "/proc/self/cmdline", "relative", "/usr/../usr/bin/nvidia-smi"} {
		if _, got := nodeRootFile(source); got {
			t.Fatalf("reported node-root authority for %s: %v", source, got)
		}
	}
}

func verityTableFixture(options string) []byte {
	data := make([]byte, 8192)
	header := (*unix.DmIoctl)(unsafe.Pointer(&data[0]))
	header.Data_size = uint32(len(data))
	header.Data_start = unix.SizeofDmIoctl
	header.Target_count = 1
	header.Dev = 123
	header.Flags = unix.DM_READONLY_FLAG | unix.DM_ACTIVE_PRESENT_FLAG
	target := (*unix.DmTargetSpec)(unsafe.Pointer(&data[unix.SizeofDmIoctl]))
	target.Length = 1024
	copy(target.Target_type[:], "verity")
	parameters := "1 8:1 8:2 4096 4096 128 1 sha256 " + strings.Repeat("b", 64) + " -" + options
	copy(data[unix.SizeofDmIoctl+unix.SizeofDmTargetSpec:], parameters)
	return data
}

func TestVerityTableProof(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		allowed       bool
	}{
		{"strict default", "", true},
		{"restart on corruption", " 1 restart_on_corruption", true},
		{"zero blocks read as zero", " 1 ignore_zero_blocks", true},
		{"ignore corruption", " 1 ignore_corruption", false},
		{"verify only first read", " 1 check_at_most_once", false},
		{"unknown option", " 1 future_option", false},
		{"bad option count", " 2 restart_on_corruption", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeVerityTable(verityTableFixture(tc.options), 123); got != tc.allowed {
				t.Fatalf("safe = %v, want %v", got, tc.allowed)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"writable device", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Flags &^= unix.DM_READONLY_FLAG }},
		{"inactive table", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Flags &^= unix.DM_ACTIVE_PRESENT_FLAG }},
		{"truncated buffer", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Flags |= unix.DM_BUFFER_FULL_FLAG }},
		{"multiple targets", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Target_count = 2 }},
		{"foreign device", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Dev = 124 }},
		{"oversized reply", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Data_size = 9000 }},
		{"invalid offset", func(data []byte) { (*unix.DmIoctl)(unsafe.Pointer(&data[0])).Data_start = 9999 }},
		{"unprotected prefix", func(data []byte) { (*unix.DmTargetSpec)(unsafe.Pointer(&data[unix.SizeofDmIoctl])).Sector_start = 1 }},
		{"linear mapping", func(data []byte) {
			target := (*unix.DmTargetSpec)(unsafe.Pointer(&data[unix.SizeofDmIoctl]))
			target.Target_type = [16]byte{}
			copy(target.Target_type[:], "linear")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := verityTableFixture("")
			tc.change(data)
			if safeVerityTable(data, 123) {
				t.Fatal("accepted incomplete verity proof")
			}
		})
	}
	if safeVerityTable(nil, 123) {
		t.Fatal("accepted missing table")
	}
}

func TestRootFileCannotTraverseSymlinksOrMounts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "binary"), []byte("approved bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("binary", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	file, err := openRootFile(fd, "/binary")
	if err != nil {
		t.Fatalf("canonical file: %v", err)
	}
	file.Close()
	for _, source := range []string{"/alias", "/escape/passwd", "/../binary", "binary"} {
		file, err := openRootFile(fd, source)
		if err == nil {
			file.Close()
			t.Fatalf("accepted unsafe source %s", source)
		}
	}
	actualRoot, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(actualRoot)
	// /proc is a separate filesystem on the supported Linux nodes.
	file, err = openRootFile(actualRoot, "/proc/version")
	if err == nil {
		file.Close()
		t.Fatal("crossed a mount boundary")
	}
}

func TestBootRootHash(t *testing.T) {
	hash := strings.Repeat("b", 64)
	for _, tc := range []struct{ cmdline, expected string }{
		{"quiet roothash=" + hash + " ro", hash},
		{"quiet", ""}, {"roothash=abc", ""},
		{"roothash=" + hash + " roothash=" + hash, ""},
		{"roothash=" + strings.ToUpper(hash), ""},
	} {
		if got := bootRootHash(tc.cmdline); got != tc.expected {
			t.Fatalf("bootRootHash(%q)=%q", tc.cmdline, got)
		}
	}
	if verityTableRootHash(verityTableFixture(""), 123) != hash {
		t.Fatal("lost active root hash")
	}
}

func TestDMVerityMountedRootIntegration(t *testing.T) {
	root, expected := os.Getenv("C8S_TEST_DM_VERITY_ROOT"), os.Getenv("C8S_TEST_DM_VERITY_HASH")
	if root == "" {
		t.Skip("requires private mount namespace and disposable dm-verity device")
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Flags&unix.ST_RDONLY == 0 {
		t.Fatal("test root is not read-only")
	}
	if got, err := deviceVerityRootHash(uint64(st.Dev)); err != nil || got != expected {
		t.Fatalf("kernel root hash=%q, %v, expected %q", got, err, expected)
	}
	file, err := openRootFile(fd, "/binary")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffer := make([]byte, 32)
	count, err := file.Read(buffer)
	if err != nil || string(buffer[:count]) != "approved executable" {
		t.Fatalf("verity file=%q, %v", buffer[:count], err)
	}
	if rootDeviceVerityMismatch(uint64(st.Dev)) == "" {
		t.Fatal("operator-created verity device matched host measured boot root")
	}
}
