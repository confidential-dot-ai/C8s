package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

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

// podAssignedWorkload is the hook for a pod identity the claims carry (the
// signed assignment's confidential.ai/cw, or a whole-workload match over
// observed launches). Digest-only claims carry none, so it returns "". When
// one is present, only the entry of that name may grant.
var podAssignedWorkload = func(workloadclaims.PodClaims) string { return "" }

// MatchPodGrant selects the one allowlist entry carrying a secrets grant whose
// container image set equals the pod's workload image set: every distinct
// digest the guest admitted without a platform role. Platform containers
// (the mesh endpoint) are the guest's, never part of a grant.
//
// Digest-only claims cannot tell two entries with the same images apart, nor
// two pods that run the same images with different arguments, so two
// matching entries are refused rather than choosing one. Per-user isolation
// needs podAssignedWorkload.
func MatchPodGrant(al *pkgallowlist.Allowlist, claims workloadclaims.PodClaims) (PodGrant, error) {
	running := map[string]bool{}
	for _, c := range claims.Containers {
		if c.Role == "" {
			running[c.Digest] = true
		}
	}
	if len(running) == 0 {
		return PodGrant{}, fmt.Errorf("pod reports no workload containers")
	}
	assigned := podAssignedWorkload(claims)
	var matches []PodGrant
	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		w := al.Workloads[name]
		if w.Secrets == nil || (assigned != "" && name != assigned) {
			continue
		}
		declared := map[string]bool{}
		for _, d := range w.Digests() {
			declared[d.String()] = true
		}
		if !maps.Equal(declared, running) || w.PinnedForGrant() != nil {
			continue
		}
		matches = append(matches, PodGrant{Workload: name, Secrets: w.Secrets, Readers: slices.Sorted(maps.Keys(declared))})
	}
	switch len(matches) {
	case 0:
		return PodGrant{}, fmt.Errorf("no secrets grant matches the pod's images")
	case 1:
		return matches[0], nil
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.Workload
	}
	return PodGrant{}, fmt.Errorf("pod images match several secrets grants (%s); digest-only claims cannot choose", strings.Join(names, ", "))
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
