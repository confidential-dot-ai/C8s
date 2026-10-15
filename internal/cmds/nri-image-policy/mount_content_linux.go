//go:build linux

package nriimagepolicy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// nodeRootFile proves the source is reached through the measured read-only
// root, without traversing symlinks or any intervening mount. Bind mounts of
// arbitrary verity devices and writable overlays are not node-image evidence.
func nodeRootFile(source string) bool {
	if !cleanAbsolute(source) {
		return false
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(root) //nolint:errcheck // No writes to flush.
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(root, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 || unix.Fstat(root, &st) != nil || !rootDeviceVerity(uint64(st.Dev)) {
		return false
	}
	file, err := openRootFile(root, source)
	if err != nil {
		return false
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	info, err := file.Stat()
	return err == nil && info.Mode().IsRegular()
}

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

// The active root device must match roothash in the measured boot command line.
// The approved node-image launch measurement authenticates that command line.
func rootDeviceVerity(device uint64) bool {
	cmdline, err := os.ReadFile("/proc/cmdline")
	expected := bootRootHash(string(cmdline))
	return err == nil && expected != "" && deviceVerityRootHash(device) == expected
}

func deviceVerityRootHash(device uint64) string {
	fd, err := unix.Open("/dev/mapper/control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
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
		return ""
	}
	return verityTableRootHash(data, device)
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
