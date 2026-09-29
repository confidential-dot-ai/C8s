// Package join releases an RKE2 agent token only after mutually attested TLS
// authenticates the exact launch-authorized image and operator key. The shared
// refvalues and ratls packages own evidence parsing and verification; this
// package adds role-specific policy requirements and token staging.
package join

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	joinClientCertTTL    = 10 * time.Minute
	releaseServerCertTTL = time.Hour
)

// peerPolicy is constructed only after every image entry pins its operator.
// The client requires one designated server; the server permits explicit
// agent entries. A missing policy never falls back to same-image trust.
type peerPolicy struct {
	family ratls.TEEType
	verify *ratls.VerifyPolicy
}

func loadPeerPolicy(path, platform, apiURL string, timeout time.Duration, server bool) (peerPolicy, error) {
	if path == "" {
		return peerPolicy{}, fmt.Errorf("--measurements-config is required")
	}
	if platform == "" {
		return peerPolicy{}, fmt.Errorf("--platform is required")
	}
	refs, err := cmdsutil.LoadImagePolicyValues(cmdsutil.ImagePolicyValuesConfig{
		Source: cmdsutil.ImagePolicySource{File: path}, Platform: platform})
	if err != nil {
		return peerPolicy{}, err
	}
	family := refs.Family
	if len(refs.Images) == 0 {
		return peerPolicy{}, fmt.Errorf("join: policy must contain authorized %s identities", family)
	}
	if server && len(refs.Images) != 1 {
		return peerPolicy{}, fmt.Errorf("join: policy must designate exactly one server")
	}
	for _, entry := range refs.Images {
		if len(entry.Anchor) == 0 {
			return peerPolicy{}, fmt.Errorf("join: policy entry %q requires approver_key", entry.Name)
		}
		if family == ratls.TEETypeTDX && (len(entry.Registers[1]) != refvalues.DigestSize || len(entry.Registers[2]) != refvalues.DigestSize) {
			return peerPolicy{}, fmt.Errorf("join: TDX policy entry %q requires RTMR[1] and RTMR[2]", entry.Name)
		}
	}
	policy := (ratls.Pins{Images: refs.Images}).VerifyPolicy(apiURL)
	policy.AttestationVerifyTimeout = timeout
	return peerPolicy{family: family, verify: policy}, nil
}

// verifyPeer delegates signature, certificate validity, TLS key binding, image
// registers and measured operator identity to the shared verifier. The bounded
// request budget also limits its online /verify call. TLS 1.3 proves possession
// of the attested leaf key; guest clocks bound the certificate replay window.
func verifyPeer(ctx context.Context, leaf *x509.Certificate, policy peerPolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if policy.verify == nil || len(policy.verify.Policy.Images) == 0 {
		return fmt.Errorf("join: peer policy is required")
	}
	att, err := ratls.ExtractAttestation(leaf)
	if err != nil {
		return err
	}
	if att.Family != policy.family {
		return fmt.Errorf("%w: expected %s peer", ratls.ErrPolicyViolation, policy.family)
	}
	bounded := *policy.verify
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		bounded.AttestationVerifyTimeout = min(bounded.AttestationVerifyTimeout, remaining)
	}
	if _, err := ratls.VerifyCert(leaf, &bounded, nil); err != nil {
		return fmt.Errorf("join: verify peer: %w", err)
	}
	return ctx.Err()
}
