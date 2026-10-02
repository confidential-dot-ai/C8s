//go:build linux

package nriimagepolicy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const overlayFSMagic int64 = 0x794c7630

// scratchDiskSerial and scratchMapperName must match the scratch disk serial
// and dm mapping name expected by confidential-os-builder's initrd; changes
// require coordination with that repo.
const (
	scratchDiskSerial = "confai-scratch"
	scratchMapperName = "scratch"
)

type linuxStorageInspector struct {
	sysDevBlock    string
	sysClassBlock  string
	mountInfo      string
	stateDir       string
	provenanceFile string
	bootIDFile     string
}

func newMountStorageInspector() mountStorageInspector {
	return linuxStorageInspector{
		sysDevBlock:    "/sys/dev/block",
		sysClassBlock:  "/sys/class/block",
		mountInfo:      "/proc/self/mountinfo",
		stateDir:       "/usr/lib/confai/state.d",
		provenanceFile: "/run/c8s/scratch-provenance.json",
		bootIDFile:     "/proc/sys/kernel/random/boot_id",
	}
}

func (i linuxStorageInspector) Inspect(source string) allowlist.MountStorage {
	return i.inspect(source, map[string]bool{})
}

func (i linuxStorageInspector) inspect(source string, seen map[string]bool) allowlist.MountStorage {
	// Statfs resolves symlinks, so the mountinfo lookup must match the same
	// path the kernel measured, not the one the caller spelled.
	clean, err := filepath.EvalSymlinks(filepath.Clean(source))
	if err != nil || seen[clean] {
		return allowlist.MountUnknown
	}
	seen[clean] = true
	var fs unix.Statfs_t
	if err := unix.Statfs(clean, &fs); err != nil {
		return allowlist.MountUnknown
	}
	if fs.Type == unix.TMPFS_MAGIC {
		return allowlist.MountMemory
	}
	if fs.Type == overlayFSMagic {
		return i.overlayStorage(clean, seen)
	}
	var st unix.Stat_t
	if err := unix.Stat(clean, &st); err != nil {
		return allowlist.MountUnknown
	}
	dev := fmt.Sprintf("%d:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)))
	if i.isTrustedEncryptedDevice(filepath.Join(i.sysDevBlock, dev), map[string]bool{}) {
		return allowlist.MountEncrypted
	}
	return allowlist.MountUnknown
}

// isTrustedEncryptedDevice accepts C8s volume mappings and the measured initrd
// scratch contract. A host-controlled serial by itself is never sufficient.
func (i linuxStorageInspector) isTrustedEncryptedDevice(device string, seen map[string]bool) bool {
	real, err := filepath.EvalSymlinks(device)
	if err != nil {
		return false
	}
	if seen[real] {
		return false
	}
	seen[real] = true
	if strings.HasPrefix(readTrim(filepath.Join(real, "dm/uuid")), "CRYPT-") &&
		strings.HasPrefix(readTrim(filepath.Join(real, "dm/name")), "c8s-crypt-") {
		return true
	}
	if i.isTrustedScratchMapping(real) {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return i.isTrustedEncryptedDevice(filepath.Join(real, "slaves", entry.Name()), seen)
	})
}

// isTrustedScratchMapping accepts the measured initrd's scratch contract, which
// needs all three facts: exact mapper name, a crypt target UUID, and a backing
// virtio device whose exact serial is the launch contract.
func (i linuxStorageInspector) isTrustedScratchMapping(device string) bool {
	uuid := readTrim(filepath.Join(device, "dm/uuid"))
	return readTrim(filepath.Join(device, "dm/name")) == scratchMapperName &&
		strings.HasPrefix(uuid, "CRYPT-") &&
		i.isTrustedScratchProvenance(device, uuid) &&
		i.hasScratchSlave(device, map[string]bool{})
}

// overlayStorage classifies the writable overlay containing source. The measured
// initrd builds the node's state overlays in a mount namespace that switch_root
// discards, so their recorded upperdir no longer resolves; for those the boot's
// scratch mapping proves the storage instead.
func (i linuxStorageInspector) overlayStorage(source string, seen map[string]bool) allowlist.MountStorage {
	mountpoint, upper, ok := containingOverlay(i.mountInfo, source)
	if !ok {
		return allowlist.MountUnknown
	}
	if device, ok := i.bootScratchDevice(); ok && i.isDeclaredStateDir(mountpoint) && i.isTrustedScratchMapping(device) {
		return allowlist.MountEncrypted
	}
	return i.inspect(upper, seen)
}

// isDeclaredStateDir reports whether mountpoint is one of the directories the
// measured image declares for a writable state overlay, parsed the way the
// initrd parses them: one path per line, blank lines and # comments skipped,
// a leading slash tolerated.
func (i linuxStorageInspector) isDeclaredStateDir(mountpoint string) bool {
	if i.stateDir == "" {
		return false
	}
	confs, err := filepath.Glob(filepath.Join(i.stateDir, "*.conf"))
	if err != nil {
		return false
	}
	for _, conf := range confs {
		b, err := os.ReadFile(conf)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			dir := strings.TrimSpace(line)
			if dir == "" || strings.HasPrefix(dir, "#") {
				continue
			}
			if filepath.Join("/", dir) == mountpoint {
				return true
			}
		}
	}
	return false
}

// bootScratchDevice resolves the sysfs directory of the mapping that
// scratch-enforce.service recorded for this boot. The recorded device number is
// a path component, so anything but major:minor would leave sysDevBlock.
func (i linuxStorageInspector) bootScratchDevice() (string, bool) {
	b, err := os.ReadFile(i.provenanceFile)
	if err != nil {
		return "", false
	}
	var p scratchProvenance
	if json.Unmarshal(b, &p) != nil {
		return "", false
	}
	major, minor, ok := strings.Cut(p.Device, ":")
	_, majorErr := strconv.ParseUint(major, 10, 32)
	_, minorErr := strconv.ParseUint(minor, 10, 32)
	if !ok || majorErr != nil || minorErr != nil {
		return "", false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(i.sysDevBlock, p.Device))
	if err != nil {
		return "", false
	}
	return real, true
}

type scratchProvenance struct {
	Version int    `json:"version"`
	BootID  string `json:"boot_id"`
	Device  string `json:"device"`
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
}

func (i linuxStorageInspector) isTrustedScratchProvenance(device, uuid string) bool {
	b, err := os.ReadFile(i.provenanceFile)
	if err != nil {
		return false
	}
	var p scratchProvenance
	if json.Unmarshal(b, &p) != nil || p.Version != 1 || p.Name != "scratch" || p.UUID != uuid {
		return false
	}
	return p.BootID != "" && p.BootID == readTrim(i.bootIDFile) && p.Device != "" && p.Device == readTrim(filepath.Join(device, "dev"))
}

func (i linuxStorageInspector) hasScratchSlave(device string, seen map[string]bool) bool {
	real, err := filepath.EvalSymlinks(device)
	if err != nil || seen[real] {
		return false
	}
	seen[real] = true
	base := filepath.Base(real)
	if readTrim(filepath.Join(i.sysClassBlock, base, "serial")) == scratchDiskSerial {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(real, "slaves"))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return i.hasScratchSlave(filepath.Join(real, "slaves", entry.Name()), seen)
	})
}

func readTrim(name string) string {
	b, _ := os.ReadFile(name)
	return strings.TrimSpace(string(b))
}

// containingOverlay returns the mountpoint and the writable backing directory
// of the most specific mount containing source, if that mount is a writable
// overlay.
//
// For example, source /var/lib/kubelet/pods/pod-a may sit under an overlay mounted
// at /var with upperdir=/scratch/var-upper. The containing mountpoint is /var;
// the returned directory is /scratch/var-upper.
// If /var/lib is a separate mount, it hides the /var overlay for this source.
// We must use /var/lib's upperdir, or return false if it has none.
//
// mountinfo escapes spaces and a few control characters as octal sequences,
// which unescapeMountInfo handles.
func containingOverlay(mountInfo, source string) (mountpoint, upper string, ok bool) {
	f, err := os.Open(mountInfo)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	containingMountpoint, overlayUpper := "", ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		left, right, split := strings.Cut(s.Text(), " - ")
		if !split {
			continue
		}
		fields, post := strings.Fields(left), strings.Fields(right)
		if len(fields) < 5 || len(post) < 3 {
			continue
		}
		candidate := unescapeMountInfo(fields[4])
		if source != candidate && !strings.HasPrefix(source, strings.TrimSuffix(candidate, "/")+"/") {
			continue
		}
		if len(candidate) > len(containingMountpoint) {
			// A nested mount hides its ancestor, even when it cannot provide
			// an overlay upperdir whose storage we can verify.
			containingMountpoint, overlayUpper = candidate, ""
			if post[0] == "overlay" {
				overlayUpper = unescapeMountInfo(optionValue(post[2], "upperdir"))
			}
		}
	}
	return containingMountpoint, overlayUpper, s.Err() == nil && overlayUpper != ""
}

func optionValue(options, name string) string {
	for option := range strings.SplitSeq(options, ",") {
		if value, ok := strings.CutPrefix(option, name+"="); ok {
			return value
		}
	}
	return ""
}

func unescapeMountInfo(s string) string {
	// Octal escapes for space, tab, newline, and backslash, respectively.
	for _, code := range []string{"040", "011", "012", "134"} {
		value, _ := strconv.ParseInt(code, 8, 8)
		s = strings.ReplaceAll(s, `\`+code, string(rune(value)))
	}
	return s
}
