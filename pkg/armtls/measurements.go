package armtls

import (
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Pins carries the shared evidence policy to C8s peer verifiers.
type Pins remote.Policy

// VerifyPolicy adds the local attestation service to the shared policy.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy(p),
		AttestationApiURL: url,
	}
}

// EnforceImages is [remote.EnforceImagesWithRuntimeLog] with every anchored
// pin accepting any runtime extension that replays: a c8s peer accepts a node
// whose measured policy history replays against RTMR[3], and judging that
// history is an external verifier's job. claimed is the peer's list, nil for none, and is refused
// beyond [MaxRuntimeExtensions] entries since each costs a hash.
func EnforceImages(resp remote.VerifyResponse, images []remote.ImagePin, platform teetypes.PlatformType, claimed []string) error {
	if len(claimed) > MaxRuntimeExtensions {
		return fmt.Errorf("%w: %d runtime extensions, at most %d allowed", remote.ErrAnchorNotAllowed, len(claimed), MaxRuntimeExtensions)
	}
	return remote.EnforceImagesWithRuntimeLog(resp, acceptReplayed(images), platform, claimed)
}

// acceptReplayed returns a copy of images whose anchored pins without an
// AcceptExtension hook accept every extension.
func acceptReplayed(images []remote.ImagePin) []remote.ImagePin {
	out := slices.Clone(images)
	for i := range out {
		if out[i].Anchor != nil && out[i].AcceptExtension == nil {
			out[i].AcceptExtension = func(string) error { return nil }
		}
	}
	return out
}
