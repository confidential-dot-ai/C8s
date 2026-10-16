package nriimagepolicy

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Kernel-protected bytes need an authenticated identity as well as integrity.
// node-root is authenticated by measured boot; fs-verity by a digest in policy.
func canonicalVerityDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

const maxVerifiedMounts = 1024

// A mount that is not staged keeps its path-only evidence, so final matching
// denies it unless an entry admits it without provenance. Staging failures
// never deny by themselves: another entry may admit the unstaged mount.
var (
	errVerityNotPinned = errors.New("fs-verity digest is not pinned in workload policy")
	errVerityCapacity  = errors.New("verified mount limit reached")
	// errStillMounted marks an unpin that left the staging mount attached.
	errStillMounted = errors.New("staging mount still attached")
)

// Tests replace these to reach the staging outcomes without a verity-enabled
// filesystem or mount privileges.
var (
	pinFSVerity   = pinFSVerityFile
	unpinFSVerity = unpinFSVerityFile
)

type verifiedMount struct {
	source, digest, containerID, sandboxID, podUID, destination string
	// stale marks a pin whose container is gone but whose unmount failed;
	// every later release retries it.
	stale bool
}

// This registry is owned by the measured node, never serialized by the operator.
// Losing it on restart fails closed for existing staged mounts. Retaining a
// kernel bind pins the verified inode even if the original path is replaced.
// The lock is never held across filesystem or mount syscalls: a hung source
// filesystem must not stall every NRI callback on the node.
var verifiedMountRegistry = struct {
	sync.Mutex
	mounts   map[string]verifiedMount
	reserved int
}{mounts: make(map[string]verifiedMount)}

// verityStagingBudget bounds the staging work in one CreateContainer call,
// inside containerd's per-request NRI timeout. Syscalls on a hung filesystem
// cannot be cancelled, so staging that overruns finishes in the background and
// releases what it pinned. Reserved capacity bounds those stragglers.
var verityStagingBudget = time.Second

type stagedMount struct {
	mount *api.Mount
	path  string
	// created marks a pin made by this call rather than reused from a retry.
	created bool
}

func stageVerityMounts(ctx context.Context, logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, adjust *api.ContainerAdjustment, rules []allowlist.MountRule) *api.ContainerAdjustment {
	if len(rules) == 0 || pod.GetUid() == "" || pod.GetId() == "" || ctr.GetId() == "" || ctr.GetPodSandboxId() != pod.GetId() {
		return adjust
	}
	result := make(chan []stagedMount, 1)
	go func() { result <- stageMounts(logger, pod, ctr, rules) }()
	ctx, cancel := context.WithTimeout(ctx, verityStagingBudget)
	defer cancel()
	var staged []stagedMount
	select {
	case staged = <-result:
	case <-ctx.Done():
		logger.Warn("fs-verity staging timed out", "container", ctr.GetId(), "reason", ctx.Err())
		go func() {
			var created []string
			for _, mount := range <-result {
				if mount.created {
					created = append(created, mount.path)
				}
			}
			releaseVerifiedPaths(logger, func(path string, _ verifiedMount) bool { return slices.Contains(created, path) })
		}()
		return adjust
	}
	for _, mount := range staged {
		if adjust == nil {
			adjust = &api.ContainerAdjustment{}
		}
		edit := proto.Clone(mount.mount).(*api.Mount)
		edit.Source = mount.path
		adjust.AddMount(edit)
	}
	return adjust
}

func stageMounts(logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, rules []allowlist.MountRule) []stagedMount {
	var staged []stagedMount
	for _, mount := range ctr.GetMounts() {
		if !fileBind(mount) {
			continue
		}
		var accepted []string
		for _, rule := range rules {
			if rule.Source == mount.GetSource() && rule.Destination == mount.GetDestination() && rule.Provenance == allowlist.ProvenanceFSVerity && canonicalVerityDigest(rule.VerityDigest) {
				accepted = append(accepted, rule.VerityDigest)
			}
		}
		if len(accepted) == 0 {
			continue
		}
		evidence := observeHostMount(mount)
		// A node-root file already carries its fs-verity digest; staging would
		// replace its node-root proof and break entries that rely on it.
		if !evidence.ReadOnly || evidence.HostSourceDigest == "" || evidence.Provenance == allowlist.ProvenanceNodeRoot {
			continue
		}
		path, created, err := stageVerityMount(logger, pod, ctr, mount, accepted)
		if err != nil {
			logger.Warn("fs-verity mount not staged", "container", ctr.GetId(), "source", mount.GetSource(), "destination", mount.GetDestination(), "reason", err)
			continue
		}
		if path != "" {
			staged = append(staged, stagedMount{mount: mount, path: path, created: created})
		}
	}
	return staged
}

// stageVerityMount returns the staging path for mount and whether this call
// created it. An idempotent create retry reuses the container's pinned inode
// rather than resolving the operator pathname again; final policy matching
// still checks its digest.
func stageVerityMount(logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, mount *api.Mount, accepted []string) (string, bool, error) {
	want := verifiedMount{source: mount.GetSource(), containerID: ctr.GetId(), sandboxID: pod.GetId(), podUID: pod.GetUid(), destination: mount.GetDestination()}
	verifiedMountRegistry.Lock()
	for path, entry := range verifiedMountRegistry.mounts {
		entry.digest = ""
		if entry == want {
			verifiedMountRegistry.Unlock()
			return path, false, nil
		}
	}
	full := len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved >= maxVerifiedMounts
	verifiedMountRegistry.Unlock()
	if full {
		// Stale pins otherwise wait for another container's removal.
		releaseVerifiedPaths(logger, func(_ string, entry verifiedMount) bool { return entry.stale })
	}

	verifiedMountRegistry.Lock()
	capacity := len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved < maxVerifiedMounts
	if capacity {
		verifiedMountRegistry.reserved++
	}
	verifiedMountRegistry.Unlock()

	path, digest, err := pinFSVerity(mount.GetSource(), capacity, accepted)

	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	if capacity {
		verifiedMountRegistry.reserved--
	}
	if err != nil && path != "" {
		// A mount that could not be detached keeps counting until a retry
		// releases it.
		stale := want
		stale.stale = true
		verifiedMountRegistry.mounts[path] = stale
		return "", false, err
	}
	if err != nil || path == "" {
		return "", false, err
	}
	want.digest = digest
	verifiedMountRegistry.mounts[path] = want
	return path, true, nil
}

func verifiedHostMount(ctx MountContext, mount *api.Mount) (allowlist.ObservedMount, bool) {
	verifiedMountRegistry.Lock()
	entry, ok := verifiedMountRegistry.mounts[mount.GetSource()]
	verifiedMountRegistry.Unlock()
	if !ok || entry.stale || !ctx.valid() || !fileBind(mount) || entry.containerID != ctx.Container.GetId() || entry.sandboxID != ctx.SandboxID || entry.podUID != ctx.PodUID || entry.destination != mount.GetDestination() {
		return allowlist.ObservedMount{}, false
	}
	observed := observeHostMount(mount)
	// Requery the inode that runc will bind, including the staging mount's mode.
	if !observed.ReadOnly || observed.HostSourceDigest == "" || !pinnedFSVerityFile(mount.GetSource(), entry.digest) {
		return allowlist.ObservedMount{}, false
	}
	observed.HostSourceDigest, _ = allowlist.HostSourceDigest(entry.source)
	observed.Provenance = allowlist.ProvenanceFSVerity
	observed.VerityDigest = entry.digest
	return observed, true
}

// releaseVerifiedMounts unpins the container's staging mounts and retries
// stale pins left by earlier failed unmounts.
func releaseVerifiedMounts(logger *slog.Logger, containerID string) {
	releaseVerifiedPaths(logger, func(_ string, entry verifiedMount) bool { return entry.containerID == containerID || entry.stale })
}

// releaseVerifiedPaths unpins every registered mount that match selects. A pin
// whose unmount fails stays registered as stale, and counted against
// maxVerifiedMounts, until a retry succeeds.
func releaseVerifiedPaths(logger *slog.Logger, match func(string, verifiedMount) bool) {
	verifiedMountRegistry.Lock()
	release := map[string]verifiedMount{}
	for path, entry := range verifiedMountRegistry.mounts {
		if match(path, entry) {
			release[path] = entry
			delete(verifiedMountRegistry.mounts, path)
		}
	}
	verifiedMountRegistry.Unlock()

	for path, entry := range release {
		err := unpinFSVerity(path)
		if err == nil {
			continue
		}
		logger.Warn("cannot release fs-verity staging mount", "container", entry.containerID, "path", path, "error", err)
		if errors.Is(err, errStillMounted) {
			entry.stale = true
			verifiedMountRegistry.Lock()
			verifiedMountRegistry.mounts[path] = entry
			verifiedMountRegistry.Unlock()
		}
	}
}
