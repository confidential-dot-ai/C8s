package volumed

import (
	"context"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volume"
)

// A volumeMode is how one mode builds the device stack above the dm-crypt
// mapping and mounts its top: an immutable volume stacks dm-verity and mounts
// the verified erofs read-only, a mutable one mounts the crypt device itself,
// writable ext4.
type volumeMode interface {
	// open builds the layers above cryptMapper and mounts the top at target.
	open(ctx context.Context, ops DeviceOps, podUID, name, cryptMapper string, b volume.Blob, target *os.File) error
	// close unwinds what open built, mount included.
	close(ctx context.Context, ops DeviceOps, podUID, name, target string)
}

// modeFor selects the stack a mode builds.
func modeFor(mutable bool) volumeMode {
	if mutable {
		return mutableMode{}
	}
	return immutableMode{}
}

// immutableMode stacks dm-verity over the crypt mapping and mounts the
// verified device, read-only erofs.
type immutableMode struct{}

func (immutableMode) open(ctx context.Context, ops DeviceOps, podUID, name, cryptMapper string, b volume.Blob, target *os.File) error {
	verityMapper := mapperName(verityKind, podUID, name)
	if err := ops.VerityOpen(ctx, devPath(cryptMapper), verityMapper, *b.Verity); err != nil {
		return fmt.Errorf("volumed: open dm-verity: %w", err)
	}
	if err := ops.MountRO(ctx, devPath(verityMapper), target, fsTypeErofs); err != nil {
		_ = ops.VerityClose(ctx, verityMapper)
		return fmt.Errorf("volumed: mount: %w", err)
	}
	return nil
}

func (immutableMode) close(ctx context.Context, ops DeviceOps, podUID, name, target string) {
	_ = ops.Unmount(ctx, target)
	_ = ops.VerityClose(ctx, mapperName(verityKind, podUID, name))
}

// mutableMode mounts the crypt device itself, writable ext4: there is no
// integrity layer to build or unwind.
type mutableMode struct{}

func (mutableMode) open(ctx context.Context, ops DeviceOps, _, _, cryptMapper string, _ volume.Blob, target *os.File) error {
	if err := ops.MountRW(ctx, devPath(cryptMapper), target, fsTypeExt4); err != nil {
		return fmt.Errorf("volumed: mount: %w", err)
	}
	return nil
}

func (mutableMode) close(ctx context.Context, ops DeviceOps, _, _, target string) {
	_ = ops.Unmount(ctx, target)
}
