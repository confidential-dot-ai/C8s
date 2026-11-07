package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// PodGrant is the allowlist entry whose secrets grant a pod CVM's snapshot
// matched, and the image digests that entry names: the containers the guest
// may let read a released value.
type PodGrant struct {
	Workload string
	Secrets  *pkgallowlist.SecretsPolicy
	Readers  []string
}

// ErrPodSecretUngranted is a path the matched grant neither reads nor creates.
var ErrPodSecretUngranted = errors.New("path is not granted to this pod")

// MatchPodGrant selects the allowlist entry whose secrets grant a pod CVM
// holds. The pod's workload observations (every retained admission without
// a platform role: image, argv, env commitment and mounts, which its spec
// digests commit to) must match the entry as a whole workload, as node
// release requires.
//
// A pod with an assigned workload ID (the signed confidential.ai/cw) may only
// match the entry of that name, so two users' entries with the same images
// and launches release different secrets to their own pods. Without one, the
// observations must match exactly one entry of the whole allowlist.
func MatchPodGrant(al *pkgallowlist.Allowlist, claims workloadclaims.PodClaims) (PodGrant, error) {
	running := WorkloadContainers(claims.Containers)
	if len(running) == 0 {
		return PodGrant{}, fmt.Errorf("pod reports no workload containers")
	}
	candidates := al
	if id := claims.AssignedWorkloadID; id != "" {
		w, ok := al.Workloads[id]
		if !ok {
			return PodGrant{}, fmt.Errorf("no allowlist entry for the assigned workload %q", id)
		}
		candidates = &pkgallowlist.Allowlist{Schema: al.Schema, Workloads: map[string]pkgallowlist.Workload{id: w}}
	}
	name, w, err := candidates.MatchWorkload(running)
	if err != nil {
		return PodGrant{}, fmt.Errorf("pod workload: %w", err)
	}
	if w.Secrets == nil {
		return PodGrant{}, fmt.Errorf("workload %q holds no secrets grant", name)
	}
	if err := w.PinnedForGrant(); err != nil {
		return PodGrant{}, fmt.Errorf("workload %q: %w", name, err)
	}
	readers := map[string]bool{}
	for _, d := range w.Digests() {
		readers[d.String()] = true
	}
	return PodGrant{Workload: name, Secrets: w.Secrets, Readers: slices.Sorted(maps.Keys(readers))}, nil
}

// ReleasePodSecret reads path under g, minting it first when it is empty and
// g may create it, as the node fetcher's GET-then-POST does in one step. A
// value another replica created first is read back, never returned by the
// create.
func ReleasePodSecret(ctx context.Context, store Store, g PodGrant, path string) ([]byte, error) {
	read := g.Secrets.Allows(path, pkgallowlist.OpRead)
	if read {
		value, err := store.Get(ctx, path)
		if !errors.Is(err, ErrNotFound) {
			return value, err
		}
	}
	if !g.Secrets.Allows(path, pkgallowlist.OpWrite) {
		if read {
			return nil, ErrNotFound
		}
		return nil, ErrPodSecretUngranted
	}
	candidate, err := Generate()
	if err != nil {
		return nil, err
	}
	_, held, err := store.PutIfAbsent(ctx, path, candidate, WorkloadHolder(g.Workload))
	if err != nil {
		return nil, err
	}
	if !held.Exists {
		return candidate, nil
	}
	if !read {
		return nil, ErrPodSecretUngranted
	}
	return store.Get(ctx, path)
}
