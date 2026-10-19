package allowlist

import (
	"fmt"
	"strings"
)

type mountRuleBehavior interface {
	validate() error
	admits(ObservedMount) bool
	hostIndependent() bool
	// grantPinned reports whether a secrets grant accepts the rule: the host
	// chooses neither what the container reads through it nor where it
	// writes. fsVerityFile (#938) qualifies when readOnly with a verityDigest.
	grantPinned() bool
}

var (
	_ mountRuleBehavior = emptyDirRule{}
	_ mountRuleBehavior = dataRule{}
	_ mountRuleBehavior = hostRule{}
	_ mountRuleBehavior = nodeRootFileRule{}
)

func (r MountRule) behavior() mountRuleBehavior {
	switch r.Kind {
	case MountEmptyDir:
		return emptyDirRule{r}
	case MountData:
		return dataRule{emptyDirRule{r}}
	case MountHost:
		return hostRule{r}
	case MountNodeRootFile:
		return nodeRootFileRule{hostRule{r}}
	default:
		return nil
	}
}

type emptyDirRule struct {
	MountRule
}

func (r emptyDirRule) validate() error {
	if r.Source != "" || r.ReadOnly || r.VerityDigest != "" {
		return fmt.Errorf("mount kind %q does not support source, readOnly or verityDigest", r.Kind)
	}
	return nil
}

func (emptyDirRule) admits(m ObservedMount) bool {
	return m.Storage == MountMemory || m.Storage == MountEncrypted
}

func (emptyDirRule) hostIndependent() bool {
	return true
}

func (emptyDirRule) grantPinned() bool {
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
	_, err := HostSourceDigest(r.Source)
	return err
}

func (r hostRule) admits(m ObservedMount) bool {
	digest, err := HostSourceDigest(r.Source)
	return err == nil && m.Class == MountHost && m.HostSourceDigest == digest && m.ReadOnly == r.ReadOnly
}

func (hostRule) hostIndependent() bool {
	return false
}

// grantPinned is false: read-only or not, the host chooses the file's content,
// and a writable path is a channel to whatever the host runs behind it.
func (hostRule) grantPinned() bool {
	return false
}

// nodeRootFileRule is a read-only host rule that also requires node-root
// evidence. It still names a host path, so it is not host-independent, but a
// secrets grant accepts it (grantPinned).
type nodeRootFileRule struct {
	hostRule
}

func (r nodeRootFileRule) validate() error {
	if !r.ReadOnly {
		return fmt.Errorf("mount kind %q requires readOnly: true", r.Kind)
	}
	return r.hostRule.validate()
}

func (r nodeRootFileRule) admits(m ObservedMount) bool {
	return m.Provenance == ProvenanceNodeRoot && r.hostRule.admits(m)
}

// grantPinned is true when read-only: the node proves the bytes are on the
// measured root, and read-only removes the write channel.
func (r nodeRootFileRule) grantPinned() bool {
	return r.ReadOnly
}

// observedClass is the ObservedMount class a rule of r's kind matches.
func (r MountRule) observedClass() MountClass {
	if r.Kind == MountNodeRootFile {
		return MountHost
	}
	return r.Kind
}
