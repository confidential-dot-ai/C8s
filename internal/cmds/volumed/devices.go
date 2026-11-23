package volumed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volume"
)

// SerialPrefix precedes the volume name in a device's disk serial.
// VIRTIO_BLK_ID_BYTES is 20, so this leaves 12 characters for the name — which
// is why `c8s volume create` caps it there.
const SerialPrefix = volume.SerialPrefix

// SysBlock is the sysfs directory listing block devices.
const SysBlock = "/sys/block"

// SerialDevices finds a volume's device by its disk serial.
//
// The serial is read from sysfs rather than resolved through
// /dev/disk/by-id, which only exists where udev has run. This is the same
// signal the confos initrd matches on to find its scratch disk.
//
// Two sysfs spellings, because the transport decides which one exists.
// virtio-blk publishes the serial at <dev>/serial. SCSI does not, and
// publishes it as VPD page 0x80 at <dev>/device/vpd_pg80 instead — which is
// the only spelling available for a KubeVirt hotplugged disk, since its
// validating webhook admits hotplugs on a scsi bus alone.
//
// The serial is a **selector, not a trust input**: the host chooses it, and
// answers the query per read. Naming the wrong device fails closed later — the
// key will not decrypt it, and verity will not accept it — so nothing here has
// to establish that the device is the right one, only which one was named.
type SerialDevices struct {
	// SysBlock is the sysfs block directory; empty means SysBlock.
	SysBlock string
	// DevDir is where the device nodes live; empty means "/dev".
	DevDir string
}

// Device returns the block device carrying the named volume.
//
// A serial matching more than one device is refused rather than resolved to
// whichever was read first: the host can attach two devices claiming the same
// serial, and picking one would make which volume a pod gets depend on scan
// order.
func (d SerialDevices) Device(name string) (string, error) {
	if err := ValidVolumeName(name); err != nil {
		return "", err
	}
	want := SerialPrefix + name

	entries, err := os.ReadDir(d.sysBlock())
	if err != nil {
		return "", fmt.Errorf("volumed: list block devices: %w", err)
	}
	var found []string
	for _, e := range entries {
		serial, ok := d.serialOf(e.Name())
		if !ok {
			// A device without a serial is simply not a candidate.
			continue
		}
		if serial == want {
			found = append(found, e.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("volumed: no block device carries serial %s", want)
	case 1:
		return filepath.Join(d.devDir(), found[0]), nil
	default:
		return "", fmt.Errorf("volumed: %d block devices carry serial %s: %s",
			len(found), want, strings.Join(found, ", "))
	}
}

// ValidVolumeName reports whether name can be both a Kubernetes volume and a
// disk serial. The webhook, the sidecar and this daemon all apply it, so a
// name accepted at admission is one the node can resolve to a device.
func ValidVolumeName(name string) error {
	if err := volume.ValidVolumeName(name); err != nil {
		return fmt.Errorf("volumed: %w", err)
	}
	return nil
}

// serialOf returns a device's serial, from whichever sysfs spelling its
// transport provides. Reports false when the device has no serial at all,
// which makes it simply not a candidate.
func (d SerialDevices) serialOf(dev string) (string, bool) {
	if b, err := os.ReadFile(filepath.Join(d.sysBlock(), dev, "serial")); err == nil {
		return strings.TrimSpace(string(b)), true
	}
	b, err := os.ReadFile(filepath.Join(d.sysBlock(), dev, "device", "vpd_pg80"))
	if err != nil {
		return "", false
	}
	return parseVPD80(b)
}

// vpd80HeaderLen is the SPC peripheral-device header preceding the serial:
// device type, page code 0x80, then the length as a big-endian uint16.
const vpd80HeaderLen = 4

// parseVPD80 pulls the unit serial out of SCSI VPD page 0x80.
//
// The declared length is trusted only as far as the buffer allows — a short
// read yields a short serial rather than a panic, and a device whose serial
// does not match is a non-candidate either way. Trailing NULs and spaces are
// stripped: the field is fixed-width and padded, so a serial written by
// QEMU arrives padded to the device's width.
func parseVPD80(b []byte) (string, bool) {
	if len(b) < vpd80HeaderLen {
		return "", false
	}
	n := int(b[2])<<8 | int(b[3])
	if end := vpd80HeaderLen + n; n > 0 && end <= len(b) {
		b = b[vpd80HeaderLen:end]
	} else {
		b = b[vpd80HeaderLen:]
	}
	s := strings.Trim(string(b), "\x00 \t\r\n")
	if s == "" {
		return "", false
	}
	return s, true
}

func (d SerialDevices) sysBlock() string {
	if d.SysBlock != "" {
		return d.SysBlock
	}
	return SysBlock
}

func (d SerialDevices) devDir() string {
	if d.DevDir != "" {
		return d.DevDir
	}
	return "/dev"
}
