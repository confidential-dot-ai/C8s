package volume

import (
	"fmt"
	"regexp"
)

// SerialPrefix precedes a volume name in its disk serial.
const SerialPrefix = "c8s-vol-"

// KubeVolumePrefix precedes a volume name in the injected Kubernetes volume.
const KubeVolumePrefix = "c8s-volume-"

// MaxNameLen is what remains of VIRTIO_BLK_ID_BYTES after SerialPrefix. virtio
// is the tighter of the two transports the serial may arrive over, so its limit
// is the one that binds.
const MaxNameLen = 20 - len(SerialPrefix)

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidVolumeName reports whether name can be both a Kubernetes volume and a
// disk serial without truncation.
func ValidVolumeName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("volume name %q is not a dns-1123 label", name)
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("volume name %q is %d characters; the device serial holds %d",
			name, len(name), MaxNameLen)
	}
	return nil
}

// KubeVolumeName is the Kubernetes volume carrying the named volume.
func KubeVolumeName(name string) string { return KubeVolumePrefix + name }
