package allowlist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SupportedComponentMajor is the major version of the component sets this
// reader judges. Within one major version every set works with every enforcer
// and Trust Authority; a set of another major version is refused or dropped
// unjudged.
const SupportedComponentMajor = 0

// ComponentSet is one release's entries for the c8s components: the injected
// sidecars, the router and the node services. A document keys it by its
// version, MAJOR.MINOR.PATCH.
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

// checkComponentVersion requires the set's key to be MAJOR.MINOR.PATCH in the
// major version this reader judges.
func checkComponentVersion(version string) error {
	numbers, err := parseComponentVersion(version)
	if err != nil {
		return err
	}
	if numbers[0] != SupportedComponentMajor {
		return fmt.Errorf("major version %d is not %d, the one this reader judges", numbers[0], SupportedComponentMajor)
	}
	return nil
}

// parseComponentVersion reads MAJOR.MINOR.PATCH, each a decimal number
// without a leading zero, as the numbers that order two sets.
func parseComponentVersion(version string) ([3]uint64, error) {
	var numbers [3]uint64
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return numbers, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
	}
	for i, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil || strconv.FormatUint(number, 10) != part {
			return numbers, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
		}
		numbers[i] = number
	}
	return numbers, nil
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
// launch the entry fixes: the enforcer excuses it from the privilege rules, so
// nothing about it is left to the control plane.
func checkNodeService(w Workload) error {
	if !w.NodeService {
		return nil
	}
	if len(w.InitContainers) != 0 || len(w.Containers) != 1 {
		return fmt.Errorf("a node service is one container and no init container")
	}
	c := w.Containers[0]
	for _, policy := range []string{c.Command.Policy, c.Args.Policy, c.Env.Policy, c.Mounts.Policy} {
		if policy != PolicyExact {
			return fmt.Errorf("a node service pins its launch exactly: command, args, env and mounts")
		}
	}
	return nil
}

// checkDistinctLaunches refuses a set that binds one launch twice: two
// declarations of the same bytes under the same command line could grant it
// two roles, and the set would describe neither.
func (s *ComponentSet) checkDistinctLaunches() error {
	bound := make(map[string]bool)
	for _, entry := range s.Entries {
		for _, c := range entry.containers() {
			key := launchKey(c)
			if bound[key] {
				return fmt.Errorf("container %s is bound twice under the same command line", c.Digest)
			}
			bound[key] = true
		}
	}
	return nil
}

// launchKey is the launch a declaration binds: the bytes and the argv the set
// admits them under.
func launchKey(c Container) string {
	key, _ := json.Marshal([]any{c.Digest.String(), c.Command.Argv, c.Args.Policy, c.Args.Argv})
	return string(key)
}
