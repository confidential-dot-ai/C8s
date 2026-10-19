package allowlist

import (
	"fmt"
	"strings"
)

type mountRuleBehavior interface {
	validate() error
	admits(ObservedMount) bool
	hostIndependent() bool
}

var (
	_ mountRuleBehavior = emptyDirRule{}
	_ mountRuleBehavior = dataRule{}
	_ mountRuleBehavior = hostRule{}
)

func (r MountRule) behavior() mountRuleBehavior {
	switch r.Kind {
	case MountEmptyDir:
		return emptyDirRule{r}
	case MountData:
		return dataRule{emptyDirRule{r}}
	case MountHost:
		return hostRule{r}
	default:
		return nil
	}
}

type emptyDirRule struct {
	MountRule
}

func (r emptyDirRule) validate() error {
	if r.Source != "" || r.ReadOnly || r.Provenance != "" || r.VerityDigest != "" {
		return fmt.Errorf("mount kind %q does not support source, readOnly or provenance", r.Kind)
	}
	return nil
}

func (emptyDirRule) admits(m ObservedMount) bool {
	return m.Storage == MountMemory || m.Storage == MountEncrypted
}

func (emptyDirRule) hostIndependent() bool {
	return true
}

type dataRule struct {
	emptyDirRule
}

func (r dataRule) validate() error {
	if err := r.emptyDirRule.validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(r.Destination, DataMountPrefix) {
		return fmt.Errorf("data destination %q must be below %s", r.Destination, DataMountPrefix)
	}
	return nil
}

type hostRule struct {
	MountRule
}

func (r hostRule) validate() error {
	if r.VerityDigest != "" {
		return fmt.Errorf("verityDigest is not supported")
	}
	switch r.Provenance {
	case "":
	case ProvenanceNodeRoot:
		if !r.ReadOnly {
			return fmt.Errorf("mount provenance requires readOnly: true")
		}
	default:
		return fmt.Errorf("mount provenance %q is not supported", r.Provenance)
	}
	_, err := HostSourceDigest(r.Source)
	return err
}

func (r hostRule) admits(m ObservedMount) bool {
	digest, err := HostSourceDigest(r.Source)
	return err == nil && m.HostSourceDigest == digest && m.ReadOnly == r.ReadOnly && (r.Provenance == "" || m.Provenance == r.Provenance)
}

// hostIndependent is false even with provenance: the rule still names a host
// path, so secrets grants (PinnedForGrant) reject it.
func (hostRule) hostIndependent() bool {
	return false
}
