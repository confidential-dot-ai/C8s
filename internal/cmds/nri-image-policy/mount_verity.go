package nriimagepolicy

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
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
	errVerityReleasing = errors.New("container's staging mount is being released")
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
	// releasing marks a pin being unmounted. It still counts against
	// maxVerifiedMounts but no longer proves anything.
	releasing bool
	// attempt is the staging call that created the pin until that call
	// commits it, then 0. A pending pin is private: no retry reuses it and no
	// validation accepts it, so an abandoned attempt can release it safely.
	attempt uint64
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
	attempts uint64
}{mounts: make(map[string]verifiedMount)}

// verityStagingBudget bounds the staging work in one CreateContainer call,
// inside containerd's per-request NRI timeout. Syscalls on a hung filesystem
// cannot be cancelled, so staging that overruns finishes in the background and
// releases what it pinned. stagingWorkers bounds those stragglers: a call that
// finds every permit taken stages nothing.
var (
	verityStagingBudget = time.Second
	stagingWorkers      = make(chan struct{}, 16)
)

type stagedMount struct {
	mount *api.Mount
	path  string
}

func stageVerityMounts(ctx context.Context, logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, adjust *api.ContainerAdjustment, rules []allowlist.MountRule) *api.ContainerAdjustment {
	if len(rules) == 0 || pod.GetUid() == "" || pod.GetId() == "" || ctr.GetId() == "" || ctr.GetPodSandboxId() != pod.GetId() {
		return adjust
	}
	select {
	case stagingWorkers <- struct{}{}:
	default:
		logger.Warn("fs-verity staging skipped: every staging worker is busy", "container", ctr.GetId())
		return adjust
	}
	ctx, cancel := context.WithTimeout(ctx, verityStagingBudget)
	defer cancel()
	verifiedMountRegistry.Lock()
	verifiedMountRegistry.attempts++
	attempt := verifiedMountRegistry.attempts
	verifiedMountRegistry.Unlock()
	result := make(chan []stagedMount, 1)
	go func() {
		defer func() { <-stagingWorkers }()
		result <- stageMounts(ctx, logger, attempt, pod, ctr, rules)
	}()
	var staged []stagedMount
	select {
	case staged = <-result:
	case <-ctx.Done():
		logger.Warn("fs-verity staging timed out", "container", ctr.GetId(), "reason", ctx.Err())
		go func() {
			<-result
			releaseVerifiedPaths(logger, func(_ string, entry verifiedMount) bool { return entry.attempt == attempt })
		}()
		return adjust
	}
	verifiedMountRegistry.Lock()
	for path, entry := range verifiedMountRegistry.mounts {
		if entry.attempt == attempt {
			entry.attempt = 0
			verifiedMountRegistry.mounts[path] = entry
		}
	}
	verifiedMountRegistry.Unlock()
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

func stageMounts(ctx context.Context, logger *slog.Logger, attempt uint64, pod *api.PodSandbox, ctr *api.Container, rules []allowlist.MountRule) []stagedMount {
	var staged []stagedMount
	for _, mount := range ctr.GetMounts() {
		if ctx.Err() != nil {
			return staged
		}
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
		path, err := stageVerityMount(logger, attempt, pod, ctr, mount, accepted)
		if err != nil {
			logger.Warn("fs-verity mount not staged", "container", ctr.GetId(), "source", mount.GetSource(), "destination", mount.GetDestination(), "reason", err)
			continue
		}
		if path != "" {
			staged = append(staged, stagedMount{mount: mount, path: path})
		}
	}
	return staged
}

// stageVerityMount returns the staging path for mount. An idempotent create
// retry reuses the container's committed pin rather than resolving the
// operator pathname again; final policy matching still checks its digest.
func stageVerityMount(logger *slog.Logger, attempt uint64, pod *api.PodSandbox, ctr *api.Container, mount *api.Mount, accepted []string) (string, error) {
	want := verifiedMount{source: mount.GetSource(), containerID: ctr.GetId(), sandboxID: pod.GetId(), podUID: pod.GetUid(), destination: mount.GetDestination()}
	verifiedMountRegistry.Lock()
	for path, entry := range verifiedMountRegistry.mounts {
		entry.digest = ""
		if entry == want {
			verifiedMountRegistry.Unlock()
			return path, nil
		}
		entry.releasing = false
		if entry == want {
			verifiedMountRegistry.Unlock()
			return "", errVerityReleasing
		}
	}
	full := len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved >= maxVerifiedMounts
	verifiedMountRegistry.Unlock()
	if full {
		// Stale pins otherwise wait for another container's removal.
		releaseVerifiedPaths(logger, func(_ string, entry verifiedMount) bool { return entry.stale })
	}

	verifiedMountRegistry.Lock()
	if len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved >= maxVerifiedMounts {
		verifiedMountRegistry.Unlock()
		return "", errVerityCapacity
	}
	verifiedMountRegistry.reserved++
	verifiedMountRegistry.Unlock()

	path, digest, err := pinFSVerity(mount.GetSource(), accepted)

	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	verifiedMountRegistry.reserved--
	if err != nil && path != "" {
		// A mount that could not be detached keeps counting until a retry
		// releases it.
		stale := want
		stale.stale = true
		verifiedMountRegistry.mounts[path] = stale
		return "", err
	}
	if err != nil || path == "" {
		return "", err
	}
	want.digest = digest
	want.attempt = attempt
	verifiedMountRegistry.mounts[path] = want
	return path, nil
}

func verifiedHostMount(ctx MountContext, mount *api.Mount) (allowlist.ObservedMount, bool) {
	verifiedMountRegistry.Lock()
	entry, ok := verifiedMountRegistry.mounts[mount.GetSource()]
	verifiedMountRegistry.Unlock()
	if !ok || entry.stale || entry.releasing || entry.attempt != 0 || !ctx.valid() || !fileBind(mount) || entry.containerID != ctx.Container.GetId() || entry.sandboxID != ctx.SandboxID || entry.podUID != ctx.PodUID || entry.destination != mount.GetDestination() {
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

// releaseVerifiedPaths unpins every registered mount that match selects. An
// entry stays registered, and counted against maxVerifiedMounts, until its
// unmount succeeds; one whose unmount fails becomes stale until a retry
// succeeds.
func releaseVerifiedPaths(logger *slog.Logger, match func(string, verifiedMount) bool) {
	verifiedMountRegistry.Lock()
	release := map[string]verifiedMount{}
	for path, entry := range verifiedMountRegistry.mounts {
		if !entry.releasing && match(path, entry) {
			entry.releasing = true
			verifiedMountRegistry.mounts[path] = entry
			release[path] = entry
		}
	}
	verifiedMountRegistry.Unlock()

	for path, entry := range release {
		err := unpinFSVerity(path)
		verifiedMountRegistry.Lock()
		if errors.Is(err, errStillMounted) {
			entry.releasing, entry.stale, entry.attempt = false, true, 0
			verifiedMountRegistry.mounts[path] = entry
		} else {
			delete(verifiedMountRegistry.mounts, path)
		}
		verifiedMountRegistry.Unlock()
		if err != nil {
			logger.Warn("cannot release fs-verity staging mount", "container", entry.containerID, "path", path, "error", err)
		}
	}
}
