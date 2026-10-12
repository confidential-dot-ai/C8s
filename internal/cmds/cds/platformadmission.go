package cds

import (
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// platformAdmission decides which platforms' evidence can carry a guest
// identity. It is a property of the deployment and not of a request: it is
// chosen once, when the handler is built.
type platformAdmission interface {
	admit(platform teetypes.PlatformType) error
}

// guestMeasuredOnly admits a platform only when its launch measurement names
// the guest image.
type guestMeasuredOnly struct{}

// On Azure SEV-SNP the launch measurement covers Azure's firmware layer and the
// paravisor owns HOSTDATA, so no claim a pin can reach names the guest image.
func (guestMeasuredOnly) admit(platform teetypes.PlatformType) error {
	if platform == teetypes.PlatformAzSNP {
		return fmt.Errorf("platform %q identifies no guest image, so this deployment admits no evidence from it", platform)
	}
	return nil
}

// alsoAzureSNP admits every platform, Azure SEV-SNP included.
type alsoAzureSNP struct{}

func (alsoAzureSNP) admit(teetypes.PlatformType) error {
	return nil
}

// verifiedPlatform is the platform evidence verification reported. A verdict
// that names none establishes no platform, and the requester's own tag is not a
// substitute for one.
func verifiedPlatform(resp remote.VerifyResponse) (teetypes.PlatformType, error) {
	if resp.Result.Platform == "" {
		return "", errors.New("evidence verification named no platform, so its claims answer no known one")
	}
	return teetypes.NormalizePlatform(string(resp.Result.Platform)), nil
}
