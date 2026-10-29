package armtls

import (
	"fmt"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Pins carries the shared evidence policy to C8s peer verifiers.
type Pins remote.Policy

// requirePins refuses a policy that names no guest. An empty set proves only
// that the peer is some TEE; registers and a TCB floor narrow a guest that a
// launch measurement or image pin already names.
func requirePins(p remote.Policy) error {
	if len(p.Measurements) == 0 && len(p.Images) == 0 {
		return ErrUnpinned
	}
	return nil
}

// VerifyPolicy adds the local attestation service to the shared policy.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy(p),
		AttestationApiURL: url,
	}
}

// EnforceImages is [remote.EnforceImagesWithRuntimeLog] with every anchored
// pin accepting any runtime extension that replays. It does not judge which
// digests the peer measured: that is an external verifier's job (c8s verify
// --pin-policy, --trust-operator), and docs/armtls.md says why it is a
// non-goal here. claimed is the peer's list, nil for none, and is refused
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
