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

// bindsVolume reports whether this rule's source names a pod volume rather
// than a host path: the kinds the kubelet stages from the pod's own volumes.
func (r MountRule) bindsVolume() bool {
	return r.Kind == MountEmptyDir || r.Kind == MountData
}

type emptyDirRule struct {
	MountRule
}

func (r emptyDirRule) validate() error {
	if r.ReadOnly {
		return fmt.Errorf("mount kind %q does not support readOnly", r.Kind)
	}
	if r.Source != "" && (strings.Contains(r.Source, "/") || r.Source == "." || r.Source == "..") {
		return fmt.Errorf("mount kind %q source %q must be a volume name, not a path", r.Kind, r.Source)
	}
	return nil
}

// admits also binds the pod volume behind the mount when the rule names one,
// so two destinations of one container cannot be fed from each other's
// volume. The node names that volume (internal/cmds/nri-image-policy); a
// mount it read out of no pod volume names none and is refused.
func (r emptyDirRule) admits(m ObservedMount) bool {
	if m.Storage != MountMemory && m.Storage != MountEncrypted {
		return false
	}
	return r.Source == "" || m.Volume == r.Source
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
	_, err := HostSourceDigest(r.Source)
	return err
}

func (r hostRule) admits(m ObservedMount) bool {
	digest, err := HostSourceDigest(r.Source)
	return err == nil && m.HostSourceDigest == digest && m.ReadOnly == r.ReadOnly
}

func (hostRule) hostIndependent() bool {
	return false
}
