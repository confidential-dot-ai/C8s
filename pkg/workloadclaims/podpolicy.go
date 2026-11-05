package workloadclaims

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// ParsePodImagePolicy parses the canonical reference-values schema, requiring
// complete TDX guest identities bound to launch public keys. These pins confer
// Pod mesh membership only; callers must never merge them into node policy.
// Empty input is invalid. A service may represent disabled Pod issuance with
// an absent/zero-byte file, but that is a distinct configuration decision.
func ParsePodImagePolicy(data []byte) (refvalues.ReferenceValues, error) {
	values, err := refvalues.Parse(data)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("invalid Pod image policy: %w", err)
	}
	if values.Family != teetypes.FamilyTDX || values.Empty() {
		return refvalues.ReferenceValues{}, fmt.Errorf("pod image policy requires nonempty TDX image pins")
	}
	for _, pin := range values.Images {
		if len(pin.Digest) != refvalues.DigestSize || len(pin.Registers[1]) != refvalues.DigestSize || len(pin.Registers[2]) != refvalues.DigestSize || len(pin.Anchor) == 0 {
			return refvalues.ReferenceValues{}, fmt.Errorf("pod image policy requires MRTD, RTMR1, RTMR2 and launch key")
		}
		if _, err := runtimemeasure.ParsePublicKeyPEM(pin.Anchor); err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("pod image policy requires a launch public key")
		}
	}
	return values, nil
}
