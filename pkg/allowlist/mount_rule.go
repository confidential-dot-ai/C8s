package allowlist

import (
	"encoding/hex"
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
	if r.Source != "" || r.ReadOnly || r.ContentSHA256 != "" {
		return fmt.Errorf("mount kind %q does not support source, readOnly or contentSHA256", r.Kind)
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
	if r.ContentSHA256 != "" {
		decoded, err := hex.DecodeString(r.ContentSHA256)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != r.ContentSHA256 {
			return fmt.Errorf("contentSHA256 must be 64 lowercase hexadecimal digits")
		}
		if !r.ReadOnly {
			return fmt.Errorf("contentSHA256 requires readOnly: true")
		}
	}
	_, err := HostSourceDigest(r.Source)
	return err
}

func (r hostRule) admits(m ObservedMount) bool {
	digest, err := HostSourceDigest(r.Source)
	return err == nil && m.HostSourceDigest == digest && m.ReadOnly == r.ReadOnly && (r.ContentSHA256 == "" || m.ContentSHA256 == r.ContentSHA256)
}

func (hostRule) hostIndependent() bool {
	return false
}
