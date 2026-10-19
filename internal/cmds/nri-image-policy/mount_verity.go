package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const maxVerifiedMounts = 1024

var verifiedMountRoot = "/run/c8s/verity-mounts"

// A mount that is not staged keeps its path-only evidence, so final matching
// denies it unless an entry admits it without provenance. Staging failures
// never deny by themselves: another entry may admit the unstaged mount.
var (
	errVerityNotPinned   = errors.New("fs-verity digest is not pinned in workload policy")
	errVerityFilesystem  = errors.New("filesystem does not enforce fs-verity")
	errVerityUnavailable = errors.New("source has no fs-verity digest")
	errVerityCapacity    = errors.New("verified mount limit reached")
	errVerityReleasing   = errors.New("container's staging mount is being released")
	errVerityMismatch    = errors.New("staging mount no longer has its recorded fs-verity digest")
	errStagingOrphaned   = errors.New("no listed container uses this staging mount")
	// errStillMounted marks an unpin that left the staging mount attached.
	errStillMounted = errors.New("staging mount still attached")
)

// Tests replace these to reach the staging outcomes without a verity-enabled
// filesystem or mount privileges.
var (
	pinFSVerity   = pinFSVerityFile
	unpinFSVerity = unpinFSVerityFile
	measureStaged = stagedDigest
)

type verifiedMount struct {
	source, digest, containerID, sandboxID, podUID, destination string
	// stale marks a pin whose unmount failed; every later release retries it.
	stale bool
	// releasing marks a pin being unmounted. It still counts against
	// maxVerifiedMounts but no longer proves anything.
	releasing bool
}

// verifiedMountRegistry holds committed pins only. A staging call keeps its
// new pins private, covered by a reservation, until it commits or discards
// them all at once; so no validation can see a pin from an abandoned call.
// Each committed pin also has a record on disk, from which a restarted
// enforcer rebuilds the registry (restoreVerifiedMounts). The lock is never held across filesystem or mount
// syscalls, so a hung source filesystem cannot stall every NRI callback.
var verifiedMountRegistry = struct {
	sync.Mutex
	mounts   map[string]verifiedMount
	reserved int
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
	entry verifiedMount
	// reused marks a committed pin from an earlier call for the same mount;
	// this call holds no reservation for it and never releases it.
	reused bool
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
	result := make(chan []stagedMount, 1)
	go func() {
		defer func() { <-stagingWorkers }()
		result <- stageMounts(ctx, logger, pod, ctr, rules)
	}()
	select {
	case staged := <-result:
		err := commitStaged(ctx, staged)
		if err == nil {
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
		discardStaged(logger, staged)
		logger.Warn("fs-verity staging not committed", "container", ctr.GetId(), "reason", err)
	case <-ctx.Done():
		go func() { discardStaged(logger, <-result) }()
		logger.Warn("fs-verity staging abandoned", "container", ctr.GetId(), "reason", ctx.Err())
	}
	return adjust
}

// commitStaged registers every new pin of a staging call that finished within
// its budget, or returns why it registered none. The deadline is checked under
// the registry lock, so an expired call never commits, even when its result
// and its deadline arrive together.
func commitStaged(ctx context.Context, staged []stagedMount) error {
	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, mount := range staged {
		entry, ok := verifiedMountRegistry.mounts[mount.path]
		if mount.reused && (!ok || entry.releasing || entry.stale) {
			return errVerityReleasing
		}
	}
	for _, mount := range staged {
		if !mount.reused {
			verifiedMountRegistry.reserved--
			verifiedMountRegistry.mounts[mount.path] = mount.entry
		}
	}
	return nil
}

// discardStaged unpins the new pins of a staging call that will not commit.
// A pin it cannot detach is registered as stale so that later releases retry it.
func discardStaged(logger *slog.Logger, staged []stagedMount) {
	for _, mount := range staged {
		if mount.reused {
			continue
		}
		err := unpinFSVerity(mount.path)
		verifiedMountRegistry.Lock()
		verifiedMountRegistry.reserved--
		if errors.Is(err, errStillMounted) {
			stale := mount.entry
			stale.stale = true
			verifiedMountRegistry.mounts[mount.path] = stale
		}
		verifiedMountRegistry.Unlock()
		if err != nil {
			logger.Warn("cannot release fs-verity staging mount", "container", mount.entry.containerID, "path", mount.path, "error", err)
		}
	}
}

// stageMounts pins every fs-verity candidate of ctr. Once ctx expires it stops
// and returns what it pinned so far, which the caller then discards.
func stageMounts(ctx context.Context, logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, rules []allowlist.MountRule) []stagedMount {
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
			if rule.Source == mount.GetSource() && rule.Destination == mount.GetDestination() && rule.Kind == allowlist.MountFSVerityFile && allowlist.CanonicalVerityDigest(rule.VerityDigest) {
				accepted = append(accepted, rule.VerityDigest)
			}
		}
		if len(accepted) == 0 {
			continue
		}
		evidence := observeHostMount(mount)
		// Staging would replace a node-root file's own proof.
		if !evidence.ReadOnly || evidence.HostSourceDigest == "" || evidence.Provenance == allowlist.ProvenanceNodeRoot {
			continue
		}
		pin, err := stageVerityMount(logger, pod, ctr, mount, accepted)
		if err != nil {
			logger.Warn("fs-verity mount not staged", "container", ctr.GetId(), "source", mount.GetSource(), "destination", mount.GetDestination(), "reason", err)
			continue
		}
		staged = append(staged, pin)
	}
	return staged
}

// stageVerityMount pins one mount and keeps its reservation for the caller to
// commit or discard. An idempotent create retry reuses the container's
// committed pin rather than resolving the operator pathname again; final
// policy matching still checks its digest.
func stageVerityMount(logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, mount *api.Mount, accepted []string) (stagedMount, error) {
	want := verifiedMount{source: mount.GetSource(), containerID: ctr.GetId(), sandboxID: pod.GetId(), podUID: pod.GetUid(), destination: mount.GetDestination()}
	verifiedMountRegistry.Lock()
	for path, entry := range verifiedMountRegistry.mounts {
		entry.digest = ""
		if entry == want {
			verifiedMountRegistry.Unlock()
			return stagedMount{mount: mount, path: path, reused: true}, nil
		}
		entry.releasing = false
		if entry == want {
			verifiedMountRegistry.Unlock()
			return stagedMount{}, errVerityReleasing
		}
	}
	full := len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved >= maxVerifiedMounts
	verifiedMountRegistry.Unlock()
	if full {
		// Stale pins otherwise wait for another container's removal.
		releaseVerifiedPaths(logger, func(entry verifiedMount) bool { return entry.stale })
	}

	verifiedMountRegistry.Lock()
	if len(verifiedMountRegistry.mounts)+verifiedMountRegistry.reserved >= maxVerifiedMounts {
		verifiedMountRegistry.Unlock()
		return stagedMount{}, errVerityCapacity
	}
	verifiedMountRegistry.reserved++
	verifiedMountRegistry.Unlock()

	path, digest, err := pinFSVerity(mount.GetSource(), accepted)
	if err == nil && path != "" {
		want.digest = digest
		if err = writeStagingRecord(path, want); err == nil {
			return stagedMount{mount: mount, path: path, entry: want}, nil
		}
		if !errors.Is(unpinFSVerity(path), errStillMounted) {
			path = ""
		}
	}
	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	verifiedMountRegistry.reserved--
	if path != "" {
		// A mount that could not be detached keeps counting until a release
		// retries it.
		want.stale = true
		verifiedMountRegistry.mounts[path] = want
	}
	if err == nil {
		err = errVerityUnavailable
	}
	return stagedMount{}, err
}

func verifiedHostMount(ctx MountContext, mount *api.Mount) (allowlist.ObservedMount, bool) {
	verifiedMountRegistry.Lock()
	entry, ok := verifiedMountRegistry.mounts[mount.GetSource()]
	verifiedMountRegistry.Unlock()
	if !ok || entry.stale || entry.releasing || !ctx.valid() || !fileBind(mount) || entry.containerID != ctx.Container.GetId() || entry.sandboxID != ctx.SandboxID || entry.podUID != ctx.PodUID || entry.destination != mount.GetDestination() {
		return allowlist.ObservedMount{}, false
	}
	observed := observeHostMount(mount)
	// Requery the inode that runc will bind, including the staging mount's mode.
	if !observed.ReadOnly || observed.HostSourceDigest == "" || !pinnedFSVerity(mount.GetSource(), entry.digest) {
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
	releaseVerifiedPaths(logger, func(entry verifiedMount) bool { return entry.containerID == containerID || entry.stale })
}

// releaseVerifiedPaths unpins every committed pin that match selects. An entry
// stays registered, and counted against maxVerifiedMounts, until its unmount
// succeeds; one whose unmount fails becomes stale until a retry succeeds.
func releaseVerifiedPaths(logger *slog.Logger, match func(verifiedMount) bool) {
	verifiedMountRegistry.Lock()
	release := map[string]verifiedMount{}
	for path, entry := range verifiedMountRegistry.mounts {
		if !entry.releasing && match(entry) {
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
			entry.releasing, entry.stale = false, true
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

// pinnedFSVerity reports whether the staging mount at path still has digest.
func pinnedFSVerity(path, digest string) bool {
	return digest != "" && measureStaged(path) == digest
}

// stagingRecord is the on-disk form of a committed pin, next to its inode.
type stagingRecord struct {
	Source      string `json:"source"`
	Digest      string `json:"digest"`
	ContainerID string `json:"containerID"`
	SandboxID   string `json:"sandboxID"`
	PodUID      string `json:"podUID"`
	Destination string `json:"destination"`
}

func stagingRecordPath(path string) string {
	return filepath.Join(filepath.Dir(path), "record.json")
}

func writeStagingRecord(path string, entry verifiedMount) error {
	data, err := json.Marshal(stagingRecord{Source: entry.source, Digest: entry.digest, ContainerID: entry.containerID, SandboxID: entry.sandboxID, PodUID: entry.podUID, Destination: entry.destination})
	if err != nil {
		return err
	}
	return os.WriteFile(stagingRecordPath(path), data, 0600)
}

func readStagingRecord(path string) (verifiedMount, error) {
	data, err := os.ReadFile(stagingRecordPath(path))
	if err != nil {
		return verifiedMount{}, err
	}
	var record stagingRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return verifiedMount{}, err
	}
	return verifiedMount{source: record.Source, digest: record.Digest, containerID: record.ContainerID, sandboxID: record.SandboxID, podUID: record.PodUID, destination: record.Destination}, nil
}

// removeStaging deletes the directory of a detached staging mount. Parts that
// a crash never created are skipped.
func removeStaging(path string) error {
	for _, file := range []string{stagingRecordPath(path), path} {
		if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return os.Remove(filepath.Dir(path))
}

// restoreVerifiedMounts rebuilds the registry from the staging that an earlier
// enforcer process left under verifiedMountRoot. A pin is registered again only when its
// inode still has the recorded digest on a filesystem that enforces fs-verity,
// and the container its record names is listed with that mount; every other
// staging directory is released. Call it once per process, before any staging
// or check of existing containers. It assumes a single enforcer per node: a
// second instance would release the pins the first is still staging.
func restoreVerifiedMounts(logger *slog.Logger, pods []*api.PodSandbox, ctrs []*api.Container) {
	dirs, err := filepath.Glob(filepath.Join(verifiedMountRoot, "file-*"))
	if err != nil {
		logger.Warn("cannot list fs-verity staging", "error", err)
		return
	}
	podUIDs := make(map[string]string, len(pods))
	for _, pod := range pods {
		podUIDs[pod.GetId()] = pod.GetUid()
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, "inode")
		entry, err := restoredEntry(path, podUIDs, ctrs)
		if err == nil {
			verifiedMountRegistry.Lock()
			verifiedMountRegistry.mounts[path] = entry
			verifiedMountRegistry.Unlock()
			logger.Info("fs-verity staging restored", "container", entry.containerID, "path", path)
			continue
		}
		logger.Info("releasing fs-verity staging", "path", path, "reason", err)
		err = unpinFSVerity(path)
		if errors.Is(err, errStillMounted) {
			entry.stale = true
			verifiedMountRegistry.Lock()
			verifiedMountRegistry.mounts[path] = entry
			verifiedMountRegistry.Unlock()
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("cannot release fs-verity staging mount", "path", path, "error", err)
		}
	}
}

func restoredEntry(path string, podUIDs map[string]string, ctrs []*api.Container) (verifiedMount, error) {
	entry, err := readStagingRecord(path)
	if err != nil {
		return entry, err
	}
	used := slices.ContainsFunc(ctrs, func(ctr *api.Container) bool {
		return ctr.GetId() == entry.containerID && ctr.GetPodSandboxId() == entry.sandboxID && podUIDs[entry.sandboxID] == entry.podUID &&
			slices.ContainsFunc(ctr.GetMounts(), func(m *api.Mount) bool { return m.GetSource() == path && m.GetDestination() == entry.destination })
	})
	if !used {
		return entry, errStagingOrphaned
	}
	if !pinnedFSVerity(path, entry.digest) {
		return entry, errVerityMismatch
	}
	return entry, nil
}
