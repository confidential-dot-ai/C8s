package allowlist

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// Confined reports whether a mount keeps what a container writes inside the
// node's TEE boundary: a node-created platform mount, a read-only host path, or
// an emptyDir or data volume on memory or encrypted storage. The host can read
// what a container writes to a writable host path, or to a volume on storage
// the node cannot vouch for (a disk-backed emptyDir, a PVC).
func (m ObservedMount) Confined() bool {
	switch m.Class {
	case MountPlatform:
		return true
	case MountHost:
		return m.ReadOnly
	case MountEmptyDir, MountData:
		return m.Storage == MountMemory || m.Storage == MountEncrypted
	default:
		return false
	}
}

// normalizeConfined validates the confined policy's path lists and sorts them,
// dropping duplicates, so the canonical form is a function of content alone.
func normalizeConfined(p *MountPolicy) error {
	var err error
	if p.DenyBelow, err = normalizePaths("denyBelow", p.DenyBelow); err != nil {
		return err
	}
	if p.Unconfined, err = normalizePaths("unconfined", p.Unconfined); err != nil {
		return err
	}
	// A mount there would always be refused, so the entry says two things at once.
	for _, destination := range p.Unconfined {
		if i := slices.IndexFunc(p.DenyBelow, func(denied string) bool { return pathsOverlap(destination, denied) }); i >= 0 {
			return fmt.Errorf("unconfined destination %q overlaps denyBelow path %q", destination, p.DenyBelow[i])
		}
	}
	return nil
}

func normalizePaths(field string, paths []string) ([]string, error) {
	for _, p := range paths {
		if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsRune(p, 0) {
			return nil, fmt.Errorf("%s path %q is not a clean absolute path", field, p)
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	out := slices.Clone(paths)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// admitsConfined checks a confined policy against classified mount evidence.
// Unavailable evidence fails closed, as under exact.
func (p MountPolicy) admitsConfined(mounts []ObservedMount) bool {
	if mounts == nil {
		return false
	}
	for _, m := range mounts {
		if m.Class == MountPlatform {
			continue
		}
		if !path.IsAbs(m.Destination) {
			return false
		}
		destination := path.Clean(m.Destination)
		if slices.ContainsFunc(p.DenyBelow, func(denied string) bool { return pathsOverlap(destination, denied) }) {
			return false
		}
		if !m.Confined() && !slices.Contains(p.Unconfined, destination) {
			return false
		}
	}
	return true
}

// pathsOverlap reports whether a mount at one clean absolute path would cover
// or sit inside the other: equal, or one below the other. A mount above a
// denied path replaces it as surely as one at it.
func pathsOverlap(a, b string) bool {
	return within(a, b) || within(b, a)
}

// within reports whether clean absolute path p is dir or below it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}
