//go:build linux

package nriimagepolicy

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// nodeRootFile proves the source is reached through the measured read-only
// root, without traversing symlinks or any intervening mount. Bind mounts of
// arbitrary verity devices and writable overlays are not node-image evidence.
// It also returns the file's fs-verity digest, or "" when fs-verity is off, so
// a node-root file satisfies an fs-verity rule without staging.
func nodeRootFile(source string) (string, bool) {
	if !cleanAbsolute(source) {
		return "", false
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false
	}
	defer unix.Close(root) //nolint:errcheck // No writes to flush.
	var st unix.Stat_t
	device, ok := measuredRootDevice()
	if !ok || unix.Fstat(root, &st) != nil || uint64(st.Dev) != device {
		return "", false
	}
	file, err := openRootFile(root, source)
	if err != nil {
		return "", false
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return fsVerityDigest(file), true
}

// measuredRootDevice is the root filesystem's device when it is the measured
// dm-verity root. Both facts are fixed for the boot, so they are read once and
// a node that cannot supply node-root evidence says why, once.
var measuredRootDevice = sync.OnceValues(func() (uint64, bool) {
	var fs unix.Statfs_t
	var st unix.Stat_t
	reason := ""
	switch {
	case unix.Statfs("/", &fs) != nil || fs.Flags&unix.ST_RDONLY == 0:
		reason = "root filesystem is not read-only"
	case unix.Stat("/", &st) != nil:
		reason = "cannot stat root filesystem"
	default:
		reason = rootDeviceVerityMismatch(uint64(st.Dev))
	}
	if reason != "" {
		slog.Warn("node-root provenance unavailable", "reason", reason)
		return 0, false
	}
	return uint64(st.Dev), true
})

func openRootFile(root int, source string) (*os.File, error) {
	if !cleanAbsolute(source) {
		return nil, fmt.Errorf("source is not a clean absolute path")
	}
	fd, err := unix.Openat2(root, strings.TrimPrefix(source, "/"), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), source), nil
}

// rootDeviceVerityMismatch explains why device is not the measured root, or
// returns "" when it is. The active root device must match roothash in the
// measured boot command line, which the approved node-image launch measurement
// authenticates.
func rootDeviceVerityMismatch(device uint64) string {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "cannot read /proc/cmdline"
	}
	expected := bootRootHash(string(cmdline))
	if expected == "" {
		return "no single roothash= on the boot command line"
	}
	actual, err := deviceVerityRootHash(device)
	if err != nil {
		return err.Error()
	}
	if actual != expected {
		return "root device is not a strict dm-verity target with the boot roothash"
	}
	return ""
}

func deviceVerityRootHash(device uint64) (string, error) {
	fd, err := unix.Open("/dev/mapper/control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open /dev/mapper/control: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck // Read-only table query.
	data := make([]byte, 8192)
	header := (*unix.DmIoctl)(unsafe.Pointer(&data[0]))
	header.Version = [3]uint32{4, 0, 0}
	header.Data_size = uint32(len(data))
	header.Data_start = unix.SizeofDmIoctl
	header.Dev = device
	header.Flags = unix.DM_STATUS_TABLE_FLAG
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.DM_TABLE_STATUS, uintptr(unsafe.Pointer(&data[0])))
	if errno != 0 {
		return "", fmt.Errorf("query device-mapper table: %w", errno)
	}
	return verityTableRootHash(data, device), nil
}

func safeVerityTable(data []byte, device uint64) bool { return verityTableRootHash(data, device) != "" }

func verityTableRootHash(data []byte, device uint64) string {
	if len(data) < unix.SizeofDmIoctl {
		return ""
	}
	header := (*unix.DmIoctl)(unsafe.Pointer(&data[0]))
	start, size := uint64(header.Data_start), uint64(header.Data_size)
	if header.Dev != device || header.Target_count != 1 || header.Flags&unix.DM_READONLY_FLAG == 0 || header.Flags&unix.DM_ACTIVE_PRESENT_FLAG == 0 || header.Flags&unix.DM_BUFFER_FULL_FLAG != 0 || start < unix.SizeofDmIoctl || size > uint64(len(data)) || start+unix.SizeofDmTargetSpec >= size || start%8 != 0 {
		return ""
	}
	target := (*unix.DmTargetSpec)(unsafe.Pointer(&data[start]))
	if target.Sector_start != 0 || target.Length == 0 || unix.ByteSliceToString(target.Target_type[:]) != "verity" {
		return ""
	}
	parameters := data[start+unix.SizeofDmTargetSpec : size]
	end := strings.IndexByte(string(parameters), 0)
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(parameters[:end]))
	if len(fields) < 10 || fields[7] != "sha256" || !canonicalVerityDigest(fields[8]) {
		return ""
	}
	if len(fields) == 10 {
		return fields[8]
	}
	count, err := strconv.Atoi(fields[10])
	if err != nil || count != len(fields)-11 {
		return ""
	}
	// Unknown options fail closed. In particular, ignore_corruption and
	// check_at_most_once cannot guarantee that later reads retain verified bytes.
	for _, option := range fields[11:] {
		switch option {
		case "restart_on_corruption", "panic_on_corruption", "error_as_corruption", "ignore_zero_blocks", "try_verify_in_tasklet", "use_tasklet":
		default:
			return ""
		}
	}
	return fields[8]
}

func bootRootHash(cmdline string) string {
	var root string
	for _, field := range strings.Fields(cmdline) {
		if value, ok := strings.CutPrefix(field, "roothash="); ok {
			if root != "" || !canonicalVerityDigest(value) {
				return ""
			}
			root = value
		}
	}
	return root
}
