package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"golang.org/x/mod/semver"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// SupportedComponentMajor is the major version of the component sets this
// reader judges. Within one major version every set works with every enforcer
// and CDS; a set of another major version is refused or dropped unjudged.
const SupportedComponentMajor = 0

// ComponentSet is one release's entries for the c8s components: the injected
// sidecars, the router and the node services. A document keys it by the
// release that built it, MAJOR.MINOR.PATCH with the pre-release a beta tag
// carries.
//
// A set with no retirement is current; one with a retirement runs until its
// deadline. See docs/allowlist-entries.md.
type ComponentSet struct {
	Retire  *Retirement         `json:"retire,omitempty"`
	Entries map[string]Workload `json:"entries"`
	// unreadable is why this reader cannot judge the set; normalization
	// refuses a set carrying it.
	unreadable error
}

// UnmarshalJSON never fails: a set this reader cannot decode whole becomes one
// normalization refuses, so an authored document is refused over it and a
// served document loses that set alone.
func (s *ComponentSet) UnmarshalJSON(data []byte) error {
	type strictSet ComponentSet
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded strictSet
	if err := dec.Decode(&decoded); err != nil {
		*s = ComponentSet{unreadable: err}
		return nil
	}
	*s = ComponentSet(decoded)
	return nil
}

// Retirement ends a set: from its deadline the set admits nothing.
type Retirement struct {
	Deadline Deadline `json:"deadline"`
}

// Deadline is an instant in the one spelling a document carries: RFC 3339 UTC
// with second precision, so an instant has a single canonical form.
type Deadline struct {
	time.Time
}

// deadlineLayout spells the UTC designator literally, so an offset, a
// fraction or a lower-case designator does not parse.
const deadlineLayout = "2006-01-02T15:04:05Z"

func (d Deadline) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.UTC().Format(deadlineLayout))
}

func (d *Deadline) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("a deadline is a %s string", deadlineLayout)
	}
	// time.Parse accepts a fractional second the layout does not signify, so
	// the only spelling admitted is the one the instant marshals back to.
	parsed, err := time.Parse(deadlineLayout, text)
	if err != nil || parsed.Format(deadlineLayout) != text {
		return fmt.Errorf("deadline %q is not RFC 3339 UTC with second precision (%s)", text, deadlineLayout)
	}
	d.Time = parsed
	return nil
}

// Digest is SHA-256 over the set's entries as the document carries them:
// json.Marshal of the normalized map. A retirement leaves it unchanged, so the
// digest names what the release published.
func (s ComponentSet) Digest() ([]byte, error) {
	canonical, err := json.Marshal(s.Entries)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// Current reports whether the set is one new pods join: it carries no
// retirement.
func (s ComponentSet) Current() bool {
	return s.Retire == nil
}

// InForce reports whether the set admits what it declares at now: it is
// current, or retiring with its deadline still ahead. At the deadline itself
// the set has ended.
func (s ComponentSet) InForce(now time.Time) bool {
	return s.Current() || now.Before(s.Retire.Deadline.Time)
}

// SetRef names one set: its version and the digest of its bytes, "sha256:<hex>".
type SetRef struct {
	Version string
	Digest  string
}

// SetsInForce are the sets in force at now, in version order.
func (a *Allowlist) SetsInForce(now time.Time) []SetRef {
	refs := make([]SetRef, 0, len(a.Components))
	for version, set := range a.Components {
		if !set.InForce(now) {
			continue
		}
		refs = append(refs, SetRef{Version: version, Digest: set.DigestString()})
	}
	slices.SortFunc(refs, func(x, y SetRef) int {
		return CompareSetVersions(x.Version, y.Version)
	})
	return refs
}

// SetsAdmitting are the sets in force at now with an entry that admits the
// running container whole.
func (a *Allowlist) SetsAdmitting(r RunningContainer, now time.Time) []SetRef {
	digest, err := types.ParseDigest(r.Digest)
	if err != nil {
		return nil
	}
	r.Digest = digest.String()
	var admitting []SetRef
	for _, ref := range a.SetsInForce(now) {
		if a.Components[ref.Version].admits(r) {
			admitting = append(admitting, ref)
		}
	}
	return admitting
}

// NodeServiceRef names a node-service entry: the entry's name and the set it
// comes from.
type NodeServiceRef struct {
	Set   SetRef
	Entry string
}

// NodeServiceAdmitting is the node-service entry admitting r whole, under the
// newest set in force at now that carries one.
func (a *Allowlist) NodeServiceAdmitting(r RunningContainer, now time.Time) (NodeServiceRef, bool) {
	digest, err := types.ParseDigest(r.Digest)
	if err != nil {
		return NodeServiceRef{}, false
	}
	r.Digest = digest.String()
	inForce := a.SetsInForce(now)
	for i := len(inForce) - 1; i >= 0; i-- {
		for name, entry := range a.Components[inForce[i].Version].Entries {
			if entry.NodeService && admittedBy(entry.Containers, r) {
				return NodeServiceRef{Set: inForce[i], Entry: name}, true
			}
		}
	}
	return NodeServiceRef{}, false
}

// DeclaresNodeService reports whether a set in force at now marks an entry as
// a node service.
func (a *Allowlist) DeclaresNodeService(now time.Time) bool {
	for _, ref := range a.SetsInForce(now) {
		for _, entry := range a.Components[ref.Version].Entries {
			if entry.NodeService {
				return true
			}
		}
	}
	return false
}

// EarliestDeadline is the first deadline among the retiring sets still in
// force at now, where there is one.
func (a *Allowlist) EarliestDeadline(now time.Time) (time.Time, bool) {
	var earliest time.Time
	for _, set := range a.Components {
		if set.Current() || !set.InForce(now) {
			continue
		}
		if deadline := set.Retire.Deadline.Time; earliest.IsZero() || deadline.Before(earliest) {
			earliest = deadline
		}
	}
	return earliest, !earliest.IsZero()
}

// admits reports whether an entry of the set declares a container admitting r.
func (s ComponentSet) admits(r RunningContainer) bool {
	for _, entry := range s.Entries {
		if admittedBy(entry.containers(), r) {
			return true
		}
	}
	return false
}

// DigestString is the set's digest spelled "sha256:<hex>".
func (s ComponentSet) DigestString() string {
	digest, _ := s.Digest()
	return "sha256:" + hex.EncodeToString(digest)
}

// CompareSetVersions orders two set versions as semver orders the releases
// that built them, a pre-release before the version it leads to.
func CompareSetVersions(a, b string) int {
	return semver.Compare("v"+a, "v"+b)
}

// normalizeComponents canonicalizes the components section. A set that fails a
// check is refused with the document under an authored posture, and dropped
// alone under the served one.
func (a *Allowlist) normalizeComponents(p ingestPosture) error {
	for version, set := range a.Components {
		err := set.normalize(version)
		if err == nil {
			a.Components[version] = set
			continue
		}
		if refusal := p.refuseSet(version, err); refusal != nil {
			return refusal
		}
		delete(a.Components, version)
	}
	return nil
}

// normalize validates the set against its version key and canonicalizes its
// entries as the workloads section's are.
func (s *ComponentSet) normalize(version string) error {
	if s.unreadable != nil {
		return s.unreadable
	}
	if err := checkComponentVersion(version); err != nil {
		return err
	}
	if s.Retire != nil && s.Retire.Deadline.IsZero() {
		return fmt.Errorf("retire names no deadline")
	}
	// A set's entries are judged strictly under every posture: an entry's
	// failure ends the set, not the field.
	for name, entry := range s.Entries {
		if _, err := normalizeEntry(name, &entry, authoredDocument{}); err != nil {
			return err
		}
		if err := checkComponentEntry(entry); err != nil {
			return fmt.Errorf("entry %q: %w", name, err)
		}
		s.Entries[name] = entry
	}
	return s.checkDistinctLaunches()
}

// checkComponentVersion requires the set's key to be the release tag that
// built it without its v: semver in its canonical spelling, so one release
// has one key, and in the major version this reader judges. Build metadata is
// refused, since two keys differing in it name one version.
func checkComponentVersion(version string) error {
	tag := "v" + version
	if !semver.IsValid(tag) || semver.Canonical(tag) != tag {
		return fmt.Errorf("version %q is not MAJOR.MINOR.PATCH, optionally with a pre-release, and nothing else", version)
	}
	if major := fmt.Sprintf("v%d", SupportedComponentMajor); semver.Major(tag) != major {
		return fmt.Errorf("major version %s is not %s, the one this reader judges", semver.Major(tag), major)
	}
	return nil
}

// checkComponentEntry requires an entry to pin what the privilege it carries
// is granted to: a role the node image defines, the bytes' own command line
// and mount set, and no capability beyond the node's default set.
func checkComponentEntry(w Workload) error {
	for _, c := range w.containers() {
		switch {
		case c.Role != noRole && !slices.Contains(KnownRoles, c.Role):
			return fmt.Errorf("container %s names role %q, which no node image defines", c.Digest, c.Role)
		case c.Command.Policy != PolicyExact:
			return fmt.Errorf("container %s leaves its command to the pod: a component entry pins it (exact)", c.Digest)
		case c.Mounts.Policy != PolicyExact:
			return fmt.Errorf("container %s leaves its mounts to the pod: a component entry pins them (exact)", c.Digest)
		case len(c.Capabilities) > 0:
			return fmt.Errorf("container %s declares capabilities, which a component entry grants none of", c.Digest)
		}
	}
	return checkNodeService(w)
}

// checkNodeService requires a node service to be one container whose whole
// launch the entry fixes, so nothing about it is left to the control plane. A
// match environment names every variable the container may launch with and
// refuses the rest, which is the pin a pod whose name is a variable can hold.
func checkNodeService(w Workload) error {
	if !w.NodeService {
		return nil
	}
	if len(w.InitContainers) != 0 || len(w.Containers) != 1 {
		return fmt.Errorf("a node service is one container and no init container")
	}
	c := w.Containers[0]
	for _, policy := range []string{c.Command.Policy, c.Args.Policy, c.Mounts.Policy} {
		if policy != PolicyExact {
			return fmt.Errorf("a node service pins its launch exactly: command, args and mounts")
		}
	}
	if c.Env.Policy != PolicyExact && c.Env.Policy != PolicyMatch {
		return fmt.Errorf("a node service constrains its environment: an exact or match env policy")
	}
	return nil
}

// checkDistinctLaunches refuses a set that binds one launch twice: two
// declarations admitting the same container could grant it two roles, and the
// set would describe neither. The credential clients are separated by their
// mount sets alone, so the mount set is part of the launch.
func (s *ComponentSet) checkDistinctLaunches() error {
	bound := make(map[string]bool)
	for _, entry := range s.Entries {
		for _, c := range entry.containers() {
			key := launchKey(c)
			if bound[key] {
				return fmt.Errorf("container %s is bound twice under the same command line and mounts", c.Digest)
			}
			bound[key] = true
		}
	}
	return nil
}

// launchKey is the launch a declaration binds: the bytes, the argv and the
// mounts the set admits them under.
func launchKey(c Container) string {
	key, _ := json.Marshal([]any{c.Digest.String(), c.Command.Argv, c.Args.Policy, c.Args.Argv, c.Mounts.Rules})
	return string(key)
}
