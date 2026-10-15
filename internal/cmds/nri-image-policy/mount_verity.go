package nriimagepolicy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"

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
// denies it unless an entry admits it without provenance. Only failures after
// a digest match are fatal: they leave a pinned file unstaged.
var (
	errVerityNotPinned = errors.New("fs-verity digest is not pinned in workload policy")
	errVerityCapacity  = errors.New("verified mount limit reached")
)

// Tests replace these to reach the staging outcomes without a verity-enabled
// filesystem or mount privileges.
var (
	pinFSVerity   = pinFSVerityFile
	unpinFSVerity = unpinFSVerityFile
)

type verifiedMount struct {
	source, digest, containerID, sandboxID, podUID, destination string
}

// This registry is owned by the measured node, never serialized by the operator.
// Losing it on restart fails closed for existing staged mounts. Retaining a
// kernel bind pins the verified inode even if the original path is replaced.
var verifiedMountRegistry = struct {
	sync.Mutex
	mounts map[string]verifiedMount
}{mounts: make(map[string]verifiedMount)}

func stageVerityMounts(logger *slog.Logger, pod *api.PodSandbox, ctr *api.Container, adjust *api.ContainerAdjustment, rules []allowlist.MountRule) (*api.ContainerAdjustment, error) {
	if pod.GetUid() == "" || pod.GetId() == "" || ctr.GetId() == "" || ctr.GetPodSandboxId() != pod.GetId() {
		return adjust, nil
	}
	for _, mount := range ctr.GetMounts() {
		if !carriesHostBytes(mount) {
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
		if !evidence.ReadOnly || evidence.HostSourceDigest == "" {
			continue
		}
		verifiedMountRegistry.Lock()
		// Idempotent create retries use the same pinned inode, not a newly resolved
		// operator pathname. Final policy matching still checks its digest.
		var existing string
		for path, entry := range verifiedMountRegistry.mounts {
			if entry.containerID == ctr.GetId() && entry.sandboxID == pod.GetId() && entry.podUID == pod.GetUid() && entry.destination == mount.GetDestination() && entry.source == mount.GetSource() {
				existing = path
				break
			}
		}
		if existing != "" {
			verifiedMountRegistry.Unlock()
			if adjust == nil {
				adjust = &api.ContainerAdjustment{}
			}
			edit := proto.Clone(mount).(*api.Mount)
			edit.Source = existing
			adjust.AddMount(edit)
			continue
		}
		path, digest, err := pinFSVerity(mount.GetSource(), len(verifiedMountRegistry.mounts) < maxVerifiedMounts, accepted)
		if errors.Is(err, errVerityNotPinned) || errors.Is(err, errVerityCapacity) {
			verifiedMountRegistry.Unlock()
			logger.Warn("fs-verity mount not staged", "container", ctr.GetId(), "destination", mount.GetDestination(), "reason", err)
			continue
		}
		if err != nil {
			verifiedMountRegistry.Unlock()
			return nil, fmt.Errorf("pin fs-verity source: %w", err)
		}
		if path != "" {
			verifiedMountRegistry.mounts[path] = verifiedMount{source: mount.GetSource(), digest: digest, containerID: ctr.GetId(), sandboxID: pod.GetId(), podUID: pod.GetUid(), destination: mount.GetDestination()}
		}
		verifiedMountRegistry.Unlock()
		if path == "" {
			continue
		}
		if adjust == nil {
			adjust = &api.ContainerAdjustment{}
		}
		edit := proto.Clone(mount).(*api.Mount)
		edit.Source = path
		adjust.AddMount(edit)
	}
	return adjust, nil
}

func verifiedHostMount(ctx MountContext, mount *api.Mount) (allowlist.ObservedMount, bool) {
	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	entry, ok := verifiedMountRegistry.mounts[mount.GetSource()]
	if !ok || !ctx.valid() || entry.containerID != ctx.Container.GetId() || entry.sandboxID != ctx.SandboxID || entry.podUID != ctx.PodUID || entry.destination != mount.GetDestination() {
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

func releaseVerifiedMounts(containerID string) {
	verifiedMountRegistry.Lock()
	defer verifiedMountRegistry.Unlock()
	for path, entry := range verifiedMountRegistry.mounts {
		if entry.containerID == containerID {
			if unpinFSVerity(path) == nil {
				delete(verifiedMountRegistry.mounts, path)
			}
		}
	}
}
