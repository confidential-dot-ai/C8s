//go:build linux

package nriimagepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Bound work on host-controlled mount requests. Directories, devices and files
// larger than this are not eligible for content-pinned host rules.
const maxHostContentBytes = 256 << 20

// hostFileContentDigest observes bytes only after proving their source cannot
// change between validation and the runtime's bind. Openat2 refuses symlinks
// and intervening mounts, including a bind of a root file through writable
// directories. A read-only bind alone would not stop its owner changing bytes.
func hostFileContentDigest(source string) string {
	if !cleanAbsolute(source) {
		return ""
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(root) //nolint:errcheck // No writes to flush.
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(root, &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 || unix.Fstat(root, &st) != nil || !rootDeviceVerity(uint64(st.Dev)) {
		return ""
	}
	file, err := openRootFile(root, source)
	if err != nil {
		return ""
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	return regularFileSHA256(file)
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

func regularFileSHA256(file *os.File) string {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxHostContentBytes {
		return ""
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxHostContentBytes+1))
	if err != nil || count != info.Size() || count > maxHostContentBytes {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Inspect the active kernel table, not a device's name, UUID or a file saying
// it is measured. Only a single read-only verity target is accepted. The node's
// measured boot authenticates this root; the content pin independently selects
// the exact file bytes the operator authorizes.
func rootDeviceVerity(device uint64) bool {
	fd, err := unix.Open("/dev/mapper/control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
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
	return errno == 0 && safeVerityTable(data, device)
}

func safeVerityTable(data []byte, device uint64) bool {
	if len(data) < unix.SizeofDmIoctl {
		return false
	}
	header := (*unix.DmIoctl)(unsafe.Pointer(&data[0]))
	start, size := uint64(header.Data_start), uint64(header.Data_size)
	if header.Dev != device || header.Target_count != 1 || header.Flags&unix.DM_READONLY_FLAG == 0 || header.Flags&unix.DM_ACTIVE_PRESENT_FLAG == 0 || header.Flags&unix.DM_BUFFER_FULL_FLAG != 0 || start < unix.SizeofDmIoctl || size > uint64(len(data)) || start+unix.SizeofDmTargetSpec >= size || start%8 != 0 {
		return false
	}
	target := (*unix.DmTargetSpec)(unsafe.Pointer(&data[start]))
	if target.Sector_start != 0 || target.Length == 0 || unix.ByteSliceToString(target.Target_type[:]) != "verity" {
		return false
	}
	parameters := data[start+unix.SizeofDmTargetSpec : size]
	end := strings.IndexByte(string(parameters), 0)
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(parameters[:end]))
	if len(fields) < 10 {
		return false
	}
	if len(fields) == 10 {
		return true
	}
	count, err := strconv.Atoi(fields[10])
	if err != nil || count != len(fields)-11 {
		return false
	}
	// Unknown options fail closed. In particular, ignore_corruption and
	// check_at_most_once cannot guarantee that later reads retain verified bytes.
	for _, option := range fields[11:] {
		switch option {
		case "restart_on_corruption", "panic_on_corruption", "error_as_corruption", "ignore_zero_blocks", "try_verify_in_tasklet", "use_tasklet":
		default:
			return false
		}
	}
	return true
}
