//go:build linux

package nriimagepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// nodeRootFile reports whether source is a regular file reached through the
// measured read-only root, without traversing symlinks or any intervening
// mount. Bind mounts of arbitrary verity devices and writable overlays are not
// node-image evidence.
func nodeRootFile(source string) bool {
	if !cleanAbsolute(source) {
		return false
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(root) //nolint:errcheck // No writes to flush.
	var st unix.Stat_t
	device, ok := measuredRootDevice()
	if !ok || unix.Fstat(root, &st) != nil || uint64(st.Dev) != device {
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

// measuredRoot caches whether the root filesystem is the measured dm-verity
// root. Both facts are fixed for the boot, so a definitive answer is kept;
// an I/O failure is retried on the next lookup.
var measuredRoot = &rootCache{probe: probeMeasuredRoot}

func measuredRootDevice() (uint64, bool) {
	device, reason := measuredRoot.device()
	return device, reason == ""
}

// nodeRootUnavailable explains why node-root provenance is unavailable, or
// returns "" when the root is the measured one.
func nodeRootUnavailable() string {
	_, reason := measuredRoot.device()
	return reason
}

type rootProbe struct {
	device uint64
	// reason is empty when device is the measured root.
	reason string
	// transient marks a reason that a later probe may not repeat.
	transient bool
}

type rootCache struct {
	probe  func() rootProbe
	mu     sync.Mutex
	result *rootProbe
}

func (c *rootCache) device() (uint64, string) {
	c.mu.Lock()
	result := c.result
	c.mu.Unlock()
	if result == nil {
		probe := c.probe()
		result = &probe
		if !probe.transient {
			c.mu.Lock()
			c.result = result
			c.mu.Unlock()
		}
	}
	return result.device, result.reason
}

func probeMeasuredRoot() rootProbe {
	var fs unix.Statfs_t
	if err := unix.Statfs("/", &fs); err != nil {
		return rootProbe{reason: "cannot statfs root filesystem", transient: true}
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		return rootProbe{reason: "root filesystem is not read-only"}
	}
	var st unix.Stat_t
	if err := unix.Stat("/", &st); err != nil {
		return rootProbe{reason: "cannot stat root filesystem", transient: true}
	}
	if reason, transient := rootDeviceVerityMismatch(uint64(st.Dev)); reason != "" {
		return rootProbe{reason: reason, transient: transient}
	}
	return rootProbe{device: uint64(st.Dev)}
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

// rootDeviceVerityMismatch explains why device is not the measured root, or
// returns "" when it is, and whether that reason may be transient. The active
// root device must match roothash in the measured boot command line, which the
// approved node-image launch measurement authenticates.
func rootDeviceVerityMismatch(device uint64) (string, bool) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "cannot read /proc/cmdline", true
	}
	expected := bootRootHash(string(cmdline))
	if expected == "" {
		return "no single roothash= on the boot command line", false
	}
	actual, err := deviceVerityRootHash(device)
	if err != nil {
		// A root that is no device-mapper device never becomes one.
		return err.Error(), !errors.Is(err, unix.ENXIO)
	}
	if actual != expected {
		return "root device is not a strict dm-verity target with the boot roothash", false
	}
	return "", false
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
	if len(fields) < 10 || fields[7] != "sha256" || !canonicalSHA256(fields[8]) {
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
			if root != "" || !canonicalSHA256(value) {
				return ""
			}
			root = value
		}
	}
	return root
}

func canonicalSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}
