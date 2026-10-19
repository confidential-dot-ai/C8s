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
		if got := nodeRootFile(source); got {
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

func safeVerityTable(data []byte, device uint64) bool { return verityTableRootHash(data, device) != "" }

func TestVerityTableProof(t *testing.T) {
	for _, tc := range []struct {
		name, options string
		allowed       bool
	}{
		{"strict default", "", true},
		{"restart on corruption", " 1 restart_on_corruption", true},
		{"panic on corruption", " 1 panic_on_corruption", true},
		{"restart on error", " 1 restart_on_error", true},
		{"panic on error", " 1 panic_on_error", true},
		{"zero blocks read as zero", " 1 ignore_zero_blocks", true},
		{"verify in tasklet", " 1 try_verify_in_tasklet", true},
		{"invalid error_as_corruption", " 1 error_as_corruption", false},
		{"invalid use_tasklet", " 1 use_tasklet", false},
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
	if _, err := statRootFile(fd, "/binary"); err != nil {
		t.Fatalf("canonical file: %v", err)
	}
	for _, source := range []string{"/alias", "/escape/passwd", "/../binary", "binary"} {
		if _, err := statRootFile(fd, source); err == nil {
			t.Fatalf("accepted unsafe source %s", source)
		}
	}
	actualRoot, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(actualRoot)
	// /proc is a separate filesystem on the supported Linux nodes.
	if _, err := statRootFile(actualRoot, "/proc/version"); err == nil {
		t.Fatal("crossed a mount boundary")
	}
}

func TestRootFileNeverOpensSpecialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "binary"), []byte("approved bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(root, &st); err != nil {
		t.Fatal(err)
	}
	cache := &rootCache{probe: func() rootProbe { return rootProbe{device: uint64(st.Dev)} }}
	if !cache.file(root, "/binary") {
		t.Fatal("file(/binary) = false, want true on the measured root")
	}
	notify, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(notify)
	if _, err := unix.InotifyAddWatch(notify, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	if cache.file(root, "/fifo") {
		t.Fatal("file(/fifo) = true, want false")
	}
	if n, _ := unix.Read(notify, make([]byte, 4096)); n > 0 {
		t.Fatal("opened the FIFO while checking its type")
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
	content, err := os.ReadFile(filepath.Join(root, "binary"))
	if err != nil || string(content) != "approved executable" {
		t.Fatalf("verity file=%q, %v", content, err)
	}
	if reason, _ := rootDeviceVerityMismatch(uint64(st.Dev), "ro roothash="+expected); reason != "" {
		t.Fatalf("matching roothash rejected: %s", reason)
	}
	other := strings.Repeat("0", 64)
	if reason, _ := rootDeviceVerityMismatch(uint64(st.Dev), "ro roothash="+other); reason == "" {
		t.Fatal("verity device matched a different boot roothash")
	}
	for _, tc := range []struct {
		cmdline string
		want    bool
	}{
		{"ro roothash=" + expected, true},
		{"ro roothash=" + other, false},
		{"ro", false},
	} {
		cache := &rootCache{probe: func() rootProbe { return probeMeasuredRoot(root, tc.cmdline) }}
		if got := cache.file(root, "/binary"); got != tc.want {
			t.Fatalf("file(/binary) with cmdline %q = %v, want %v", tc.cmdline, got, tc.want)
		}
	}
}

func TestMeasuredRootRetriesTransientFailures(t *testing.T) {
	probes := []rootProbe{
		{reason: "open /dev/mapper/control: too many open files", transient: true},
		{device: 7},
	}
	calls := 0
	cache := &rootCache{probe: func() rootProbe {
		calls++
		return probes[calls-1]
	}}
	if _, reason := cache.device(); reason == "" {
		t.Fatal("device() = measured root, want the transient failure")
	}
	for range 2 {
		if device, reason := cache.device(); device != 7 || reason != "" {
			t.Fatalf("device() = %d, %q, want 7 after a transient failure", device, reason)
		}
	}
	if calls != 2 {
		t.Fatalf("probed %d times, want 2", calls)
	}
}
