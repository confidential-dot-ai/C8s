package allowlist

import (
	"slices"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Index answers admission queries for enforcers in O(1). Build it once from a
// normalized Allowlist (BuildIndex). A nil *Index admits nothing, so an
// enforcer with no policy yet can query it without a guard.
type Index struct {
	byDigest map[string][]Container
}

// BuildIndex projects an Allowlist into an admission index.
func (a *Allowlist) BuildIndex() *Index {
	idx := &Index{byDigest: map[string][]Container{}}
	for _, w := range a.Workloads {
		for _, c := range w.InitContainers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], c)
		}
		for _, c := range w.Containers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], c)
		}
	}
	return idx
}

// Size reports how many distinct digests the index lists. Enforcers log it to
// say how much policy is in force.
func (i *Index) Size() int {
	if i == nil {
		return 0
	}
	return len(i.byDigest)
}

// AdmitsDigest reports whether an image with this digest may run at all — as
// any workload container. It ignores argv, so it answers the coarse "are these
// bytes allowlisted" question the CDS issuance gate asks.
func (i *Index) AdmitsDigest(digest string) bool {
	if i == nil {
		return false
	}
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	_, ok := i.byDigest[d.String()]
	return ok
}

// AdmitsContainer reports whether an observed container may run. Admission is
// the union across every entry that lists the digest: the observation must
// satisfy some declared container's argv, mount and env policy together.
func (i *Index) AdmitsContainer(r RunningContainer) bool {
	if i == nil {
		return false
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return false
	}
	r.Digest = d.String()
	for _, c := range i.byDigest[d.String()] {
		if c.admits(r) {
			return true
		}
	}
	return false
}

// matchCommand matches a command policy against the front of argv. exact pins a
// prefix (argv must start with Argv) and returns the remaining args; any pins no
// prefix and passes the whole argv through; deny requires an empty argv.
func (p ArgvPolicy) matchCommand(argv []string) (rest []string, ok bool) {
	switch p.Policy {
	case PolicyAny:
		return argv, true
	case PolicyDeny:
		return argv, len(argv) == 0
	case PolicyExact:
		if len(argv) < len(p.Argv) {
			return nil, false
		}
		for i, tok := range p.Argv {
			if argv[i] != tok {
				return nil, false
			}
		}
		return argv[len(p.Argv):], true
	default:
		return nil, false
	}
}

// matchArgs matches an args policy against the argv left after the command:
// any accepts anything, deny requires none, exact requires equality.
func (p ArgvPolicy) matchArgs(rest []string) bool {
	switch p.Policy {
	case PolicyAny:
		return true
	case PolicyDeny:
		return len(rest) == 0
	case PolicyExact:
		return equalStrings(rest, p.Argv)
	default:
		return false
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// noRole is what a container holds until a declaration grants it a role.
const noRole = ""

// RoleOf reports the platform role this policy binds to an observed
// container. A role rides on the whole verified identity, and two
// declarations naming different roles for one launch bind none.
func (i *Index) RoleOf(r RunningContainer) string {
	if i == nil {
		return noRole
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return noRole
	}
	r.Digest = d.String()
	var roles []string
	for _, c := range i.byDigest[r.Digest] {
		if c.Role != noRole && c.admits(r) && !slices.Contains(roles, c.Role) {
			roles = append(roles, c.Role)
		}
	}
	if len(roles) != 1 {
		return noRole
	}
	return roles[0]
}

// BindsRoleMounts reports whether a declaration that grants this launch the
// role also pins its mount set. A namespace whose pods separate credentials by
// mount set admits a role container only under such a declaration, so an entry
// leaving mounts to the host carries no role there.
func (i *Index) BindsRoleMounts(r RunningContainer, role string) bool {
	if i == nil || role == noRole {
		return false
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return false
	}
	r.Digest = d.String()
	for _, c := range i.byDigest[r.Digest] {
		if c.Role == role && c.Mounts.pinned() && c.admits(r) {
			return true
		}
	}
	return false
}

// AdmitsProcess is the preliminary NRI create-time check. It deliberately checks
// only digest/argv; a successful result MUST be followed by AdmitsContainer on
// the finalized OCI spec before start, and must never authorize secret release.
func (i *Index) AdmitsProcess(r RunningContainer) bool {
	if i == nil {
		return false
	}
	d, err := types.ParseDigest(r.Digest)
	if err != nil {
		return false
	}
	r.Digest = d.String()
	for _, c := range i.byDigest[r.Digest] {
		if c.admitsProcess(r) {
			return true
		}
	}
	return false
}
