package ratls

import "github.com/confidential-dot-ai/attestation-go/remote"

// Pins carries the shared evidence policy to C8s peer verifiers.
type Pins remote.Policy

// VerifyPolicy adds the local attestation service to the shared policy.
func (p Pins) VerifyPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{
		Policy:            remote.Policy(p),
		AttestationApiURL: url,
	}
}
