package armtls

import "github.com/confidential-dot-ai/attestation-go/remote"

// Pins carries the shared evidence policy to C8s peer verifiers.
type Pins remote.Policy

// ConstrainsGuestIdentity reports whether these pins name a guest. Registers,
// vTPM PCRs and a TCB floor only narrow a guest an image or launch digest
// already names.
func (p Pins) ConstrainsGuestIdentity() bool {
	return len(p.Images) > 0 || len(p.Measurements) > 0
}

// VerifyPolicy adds the local attestation service to the shared policy.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy(p),
		AttestationApiURL: url,
	}
}
