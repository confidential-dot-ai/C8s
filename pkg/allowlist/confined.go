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
// the node cannot vouch for (a disk-backed emptyDir, a PVC). The node reports
// a host path read-only only when nothing below it is writable (see ReadOnly),
// and it must carry its source commitment.
func (m ObservedMount) Confined() bool {
	switch m.Class {
	case MountPlatform:
		return true
	case MountHost:
		return m.ReadOnly && m.HostSourceDigest != ""
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
//
// No mount may sit at or below another mount it could be carried through
// (nestedIn): the runtime follows symlinks inside earlier volumes when it
// creates a later mount, so a volume holding a symlink to a denyBelow path
// would carry the nested mount there.
func (p MountPolicy) admitsConfined(mounts []ObservedMount) bool {
	if mounts == nil {
		return false
	}
	for i, m := range mounts {
		if !path.IsAbs(m.Destination) {
			return false
		}
		destination := path.Clean(m.Destination)
		for j, other := range mounts {
			if j != i && nestedIn(m, other) && within(destination, path.Clean(other.Destination)) {
				return false
			}
		}
		if m.Class == MountPlatform {
			continue
		}
		if slices.ContainsFunc(p.DenyBelow, func(denied string) bool { return pathsOverlap(destination, denied) }) {
			return false
		}
		if !m.Confined() && !slices.Contains(p.Unconfined, destination) {
			return false
		}
	}
	return true
}

// nestedIn reports whether m, created inside other, could be carried elsewhere
// by a symlink in other. A pod volume can hold one, and so can /dev/shm, which
// every container in the pod writes. A node-created mount inside a host volume
// follows the node's own layout: volumed mounts the host's /dev at /dev, and
// the runtime still adds /dev/shm and /dev/termination-log there.
func nestedIn(m, other ObservedMount) bool {
	switch {
	case other.Class == MountPlatform:
		return path.Clean(other.Destination) == "/dev/shm"
	case m.Class == MountPlatform:
		return other.Class != MountHost
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
