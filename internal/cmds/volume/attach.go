package volume

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// Attaching a volume means presenting its image to the node as a block device
// whose disk serial is c8s-vol-<name>, because that serial is the only thing
// volumed matches on. How you get one depends on the hypervisor: a QEMU/KVM
// node takes `-device virtio-blk,serial=...` and is done. Hyper-V has no virtio
// bus at all, and a cloud disk's serial belongs to the provider, so there is
// nothing to set. This drives LIO's loopback target instead — a local SCSI disk
// whose unit serial (VPD page 0x80) is ours to choose.
//
// The serial is a selector, not a trust input: naming the wrong device fails
// closed later, when the key does not decrypt it and verity refuses it.

// DefaultConfigRoot is the configfs mount LIO is driven through.
const DefaultConfigRoot = "/sys/kernel/config"

// lioHBA is the fileio HBA every C8s backstore hangs off. Arbitrary but stable:
// detach locates a backstore by this name.
const lioHBA = "fileio_0"

// lioTPGT is the one portal group per loopback target. Attach gives each volume
// its own target, so a single group per target is all that is ever needed.
const lioTPGT = "tpgt_1"

// lioModules back the configfs tree below. Loaded before it is touched, since
// on a node that has never served a volume none of it exists yet.
var lioModules = []string{"target_core_mod", "target_core_file", "tcm_loop"}

// ErrNotAttached is returned by Detach when the volume has no backstore.
var ErrNotAttached = errors.New("volume: not attached")

// ErrInUse is returned by Detach when something still holds the volume's disk.
var ErrInUse = errors.New("volume: in use")

// DefaultSysRoot is the sysfs mount the attached disk is found through.
const DefaultSysRoot = "/sys"

// Attacher presents volume images to the node as SCSI disks.
type Attacher struct {
	// Root is the configfs mount; empty means DefaultConfigRoot.
	Root string
	// SysRoot is the sysfs mount; empty means DefaultSysRoot. Tests point it at
	// a tree they build.
	SysRoot string
	// Run loads the kernel modules; nil uses execRunner. Tests set it so the
	// configfs orchestration is exercised without root or a real LIO stack.
	Run Runner
	// RemoveGroup removes one configfs group; nil uses os.Remove.
	//
	// configfs frees a group's attributes along with its directory, so rmdir on
	// a group that still lists control/enable/wwn is correct there and is what
	// production must issue. An ordinary directory does not behave that way,
	// which is why the temp-dir fake substitutes os.RemoveAll.
	RemoveGroup func(string) error
}

// Attach exposes image as a disk carrying the serial for name, and returns that
// serial.
//
// Every step is unwound if a later one fails. A half-built target would occupy
// the name while carrying no device, so the next attach would refuse and the
// operator would have nothing to detach.
func (a Attacher) Attach(ctx context.Context, name, image string) (serial string, err error) {
	if err := ValidVolumeName(name); err != nil {
		return "", err
	}
	image, size, err := checkImage(image)
	if err != nil {
		return "", err
	}
	if err := a.loadModules(ctx); err != nil {
		return "", err
	}
	if _, err := os.Stat(a.targetRoot()); err != nil {
		return "", fmt.Errorf("volume: %s is absent; is configfs mounted and the target stack loaded?: %w",
			a.targetRoot(), err)
	}

	store := a.backstore(name)
	if _, err := os.Stat(store); err == nil {
		// The kernel opened the image once, at the attach that built this
		// backstore, and serves that file for as long as the backstore lives.
		// Replacing the image at the same path since then — kubectl cp, or any
		// mv into place — left the device on the old file, where hashing the
		// path confirms bytes nothing is reading.
		return "", fmt.Errorf("volume: %q is already attached, and the device serves the file that attach opened rather than whatever is at its path now; detach it first, then attach again", name)
	}

	var undo []func()
	defer func() {
		if err == nil {
			return
		}
		for _, u := range slices.Backward(undo) {
			u()
		}
	}()

	if err := os.MkdirAll(store, 0o755); err != nil {
		return "", fmt.Errorf("volume: create backstore %s: %w", store, err)
	}
	undo = append(undo, func() { _ = a.rmGroup(store) })

	if err := writeAttr(filepath.Join(store, "control"),
		fmt.Sprintf("fd_dev_name=%s,fd_dev_size=%d", image, size)); err != nil {
		return "", err
	}
	serial = SerialPrefix + name
	// The kernel owns wwn/; MkdirAll is a no-op against real configfs and is
	// what lets a temp-dir fake stand in for it under test.
	if err := os.MkdirAll(filepath.Join(store, "wwn"), 0o755); err != nil {
		return "", fmt.Errorf("volume: create %s/wwn: %w", store, err)
	}
	if err := writeAttr(filepath.Join(store, "wwn", "vpd_unit_serial"), serial); err != nil {
		return "", err
	}
	if err := writeAttr(filepath.Join(store, "enable"), "1"); err != nil {
		return "", err
	}

	wwn := loopbackWWN(name)
	tpgt := a.tpgt(name)
	if err := os.MkdirAll(tpgt, 0o755); err != nil {
		return "", fmt.Errorf("volume: create loopback target %s: %w", tpgt, err)
	}
	undo = append(undo, func() { _ = a.rmGroup(tpgt); _ = a.rmGroup(filepath.Dir(tpgt)) })

	// The nexus is what turns the target into a local initiator; without it the
	// LUN below is exported to nobody and no disk appears.
	if err := writeAttr(filepath.Join(tpgt, "nexus"), wwn); err != nil {
		return "", err
	}
	lun := filepath.Join(tpgt, "lun", "lun_0")
	if err := os.MkdirAll(lun, 0o755); err != nil {
		return "", fmt.Errorf("volume: create lun %s: %w", lun, err)
	}
	undo = append(undo, func() { _ = a.rmGroup(lun) })

	link := filepath.Join(lun, name)
	if err := os.Symlink(store, link); err != nil {
		return "", fmt.Errorf("volume: map %s into %s: %w", name, lun, err)
	}
	return serial, nil
}

// Detach unwinds what Attach built. It tolerates a partially-present tree so a
// failed attach can always be cleaned up, and reports ErrNotAttached only when
// there was no backstore to begin with.
//
// A disk something has opened is refused: the kernel unbinds it regardless, and
// what held it is left mapping a device that no longer exists.
func (a Attacher) Detach(ctx context.Context, name string) error {
	if err := ValidVolumeName(name); err != nil {
		return err
	}
	holders, err := a.holders(name)
	if err != nil {
		return err
	}
	if len(holders) > 0 {
		return fmt.Errorf("%w: %q is held by %s; remove what is using it first",
			ErrInUse, name, strings.Join(holders, ", "))
	}
	store := a.backstore(name)
	_, statErr := os.Stat(store)

	tpgt := a.tpgt(name)
	// LIO refuses to release a backstore while a LUN still references it, so the
	// mapping goes first and the backstore last.
	if entries, err := os.ReadDir(filepath.Join(tpgt, "lun", "lun_0")); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(tpgt, "lun", "lun_0", e.Name()))
		}
	}
	_ = a.rmGroup(filepath.Join(tpgt, "lun", "lun_0"))
	_ = a.rmGroup(tpgt)
	_ = a.rmGroup(filepath.Dir(tpgt))

	if statErr != nil {
		return fmt.Errorf("%w: %q", ErrNotAttached, name)
	}
	// Best effort: some kernels refuse to un-enable a device, and the rmdir
	// below is what actually releases it.
	_ = writeAttr(filepath.Join(store, "enable"), "0")
	if err := a.rmGroup(store); err != nil {
		return fmt.Errorf("volume: remove backstore %s: %w", store, err)
	}
	return nil
}

// holders names the kernel devices stacked on this volume's disk — volumed's
// dm-crypt target is one.
//
// The disk is reached through the SCSI address LIO publishes for the target
// attach built, rather than by scanning for the serial: the address names this
// target's disk and no other, and a host is free to give a second disk the same
// serial. A tree that was never built, or a disk the kernel has already dropped,
// holds nothing.
func (a Attacher) holders(name string) ([]string, error) {
	addr, err := os.ReadFile(filepath.Join(a.tpgt(name), "address"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("volume: read target address for %q: %w", name, err)
	}

	// address is the "host:channel:target" of the portal group; attach maps the
	// image at lun_0, which completes the SCSI device's four-part name.
	blockDir := filepath.Join(a.sysRoot(), "class", "scsi_device",
		strings.TrimSpace(string(addr))+":0", "device", "block")
	disks, err := os.ReadDir(blockDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("volume: list disks for %q: %w", name, err)
	}

	var held []string
	for _, disk := range disks {
		entries, err := os.ReadDir(filepath.Join(blockDir, disk.Name(), "holders"))
		if err != nil {
			// A disk with no holders directory holds nothing.
			continue
		}
		for _, e := range entries {
			held = append(held, e.Name())
		}
	}
	return held, nil
}

func (a Attacher) rmGroup(path string) error {
	if a.RemoveGroup != nil {
		return a.RemoveGroup(path)
	}
	return os.Remove(path)
}

func (a Attacher) root() string {
	if a.Root != "" {
		return a.Root
	}
	return DefaultConfigRoot
}

func (a Attacher) sysRoot() string {
	if a.SysRoot != "" {
		return a.SysRoot
	}
	return DefaultSysRoot
}

func (a Attacher) targetRoot() string { return filepath.Join(a.root(), "target") }

func (a Attacher) backstore(name string) string {
	return filepath.Join(a.targetRoot(), "core", lioHBA, name)
}

func (a Attacher) tpgt(name string) string {
	return filepath.Join(a.targetRoot(), "loopback", loopbackWWN(name), lioTPGT)
}

func (a Attacher) loadModules(ctx context.Context) error {
	run := a.Run
	if run == nil {
		run = execRunner
	}
	for _, m := range lioModules {
		if _, err := run(ctx, "modprobe", m); err != nil {
			return fmt.Errorf("volume: attach requires LIO kernel support; the c8s node image omits LIO and disables module loading after boot; attach through the hypervisor instead (see docs/volumes.md): load %s: %w", m, err)
		}
	}
	return nil
}

// loopbackWWN derives a target name from the volume name, so detach can find
// what attach built without keeping state on the node. The leading 5 is the
// NAA IEEE-registered format LIO expects.
func loopbackWWN(name string) string {
	sum := sha256.Sum256([]byte(SerialPrefix + name))
	return "naa.5" + hex.EncodeToString(sum[:])[:15]
}

// checkImage resolves the image and returns its size.
//
// A size that is not a whole number of image blocks is a truncated or
// corrupted copy. Attaching it would defer the failure to a read error deep
// inside a consumer, which says nothing about what went wrong.
func checkImage(image string) (string, int64, error) {
	abs, err := filepath.Abs(image)
	if err != nil {
		return "", 0, fmt.Errorf("volume: resolve %s: %w", image, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", 0, fmt.Errorf("volume: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("volume: %s is not a regular file", abs)
	}
	size := fi.Size()
	if size == 0 || size%ImageBlockSize != 0 {
		return "", 0, fmt.Errorf("volume: %s is %d bytes, not a whole number of %d-byte blocks; truncated copy?",
			abs, size, ImageBlockSize)
	}
	return abs, size, nil
}

// writeAttr sets one configfs attribute.
func writeAttr(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("volume: write %s: %w", path, err)
	}
	return nil
}

// newAttachCmd builds the command around a. Its Run and RemoveGroup are not
// flags: tests set them so the command runs without root or a real LIO stack.
func newAttachCmd(a Attacher) *cobra.Command {
	var (
		image  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "attach <name>",
		Short: "Present a volume image to this node as a disk",
		Long: `Expose --image as a block device whose disk serial is c8s-vol-<name>, which is
what the node matches on to find a volume.

Run this ON THE NODE holding the image, as root, on a Linux node with LIO
kernel support and configfs mounted. Use it where the hypervisor cannot set
the disk serial. It builds a local SCSI disk through LIO's loopback target.

This command is unsupported on the c8s node image, which omits LIO and disables
module loading after boot. For QEMU/KVM, cold-plug virtio-blk at VM launch or
hot-attach scsi-hd on a virtio-scsi controller provisioned at launch; see
docs/volumes.md for both recipes.

The image is ciphertext and this does not read it. Pointing a pod at the wrong
device fails closed — the key will not decrypt it to anything that mounts.

The device serves the file this command opens, not the path. Replace an image
by 'detach', overwrite, then 'attach' again: writing a new file over the path
of an attached image leaves the device on the old one.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if image == "" {
				return errors.New("--image is required")
			}
			serial, err := a.Attach(cmd.Context(), args[0], image)
			if err != nil {
				return err
			}
			if asJSON {
				fmt.Fprintf(cmd.OutOrStdout(), "{\"name\":%q,\"serial\":%q}\n", args[0], serial)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "+ %s attached as a disk with serial %s\n", args[0], serial)
			fmt.Fprintf(cmd.OutOrStdout(), "  confirm: grep -l %s /sys/block/*/device/vpd_pg80\n", serial)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&image, "image", "", "path on this node to the encrypted image (required)")
	f.StringVar(&a.Root, "config-root", "", "configfs mount (default "+DefaultConfigRoot+")")
	f.BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}

func newDetachCmd(a Attacher) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detach <name>",
		Short: "Remove a volume's disk from this node",
		Long: `Unwind what 'attach' built for <name>.

This removes the device, not the image: the ciphertext stays where it is, and
the key stays in CDS. A volume still mounted into a running pod should be
released by deleting that pod first — the node tears a mount down when the pod's
cgroup goes away.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Detach(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "+ %s detached\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&a.Root, "config-root", "", "configfs mount (default "+DefaultConfigRoot+")")
	return cmd
}
