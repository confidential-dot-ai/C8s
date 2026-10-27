package cds

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// loadPodImages keeps disabled issuance distinct from an invalid policy. The
// baked server always publishes this file; zero bytes explicitly disables it.
func loadPodImages(path string) ([]remote.ImagePin, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --pod-image-policy-file: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	values, err := workloadclaims.ParsePodImagePolicy(raw)
	if err != nil {
		return nil, fmt.Errorf("--pod-image-policy-file: %w", err)
	}
	return values.Images, nil
}

// validatePodAuthorities keeps Pod launch keys distinct from every explicitly
// configured node anchor and operator-write key. Compare parsed keys, not PEM
// bytes: whitespace changes the launch binding without changing who can sign.
// An unanchored development policy supplies no additional authority here.
func validatePodAuthorities(pods, nodes []remote.ImagePin, operators []*ecdsa.PublicKey) error {
	if len(pods) == 0 {
		return nil
	}
	authorities := append([]*ecdsa.PublicKey(nil), operators...)
	for _, node := range nodes {
		if len(node.Anchor) == 0 {
			continue
		}
		key, err := runtimemeasure.ParsePublicKeyPEM(node.Anchor)
		if err != nil {
			return fmt.Errorf("invalid configured node launch authority")
		}
		authorities = append(authorities, key)
	}
	for _, pod := range pods {
		key, err := runtimemeasure.ParsePublicKeyPEM(pod.Anchor)
		if err != nil {
			return fmt.Errorf("invalid configured Pod launch authority")
		}
		for _, authority := range authorities {
			if authority != nil && key.Equal(authority) {
				return fmt.Errorf("pod launch keys must differ from configured node and operator authorities")
			}
		}
	}
	return nil
}

// enforcePodImages requires one whole image/key tuple AND exact replay of the
// complete journal. Prefix acceptance alone cannot authenticate a complete
// observation history: unextended records must never earn a workload stamp.
func enforcePodImages(resp remote.VerifyResponse, pins []remote.ImagePin, platform teetypes.PlatformType, log []string) error {
	if !platform.IsTDX() || !resp.Result.Platform.IsTDX() || len(pins) == 0 {
		return fmt.Errorf("pod image policy unavailable")
	}
	for _, pin := range pins {
		if len(pin.Anchor) == 0 || len(pin.Registers[1]) != 48 || len(pin.Registers[2]) != 48 {
			continue
		}
		if armtls.EnforceImages(resp, []remote.ImagePin{pin}, platform, log) != nil {
			continue
		}
		if runtimemeasure.VerifyBinding(&resp.Result, pin.Anchor, log) == nil {
			return nil
		}
	}
	return fmt.Errorf("pod image, launch key or complete runtime journal not allowed")
}

func (h AttestHandler) resolvePodWorkload(ctx context.Context, pod workloadclaims.PodClaims) (*armtls.MatchedWorkload, error) {
	if h.AllowlistStore == nil {
		return nil, fmt.Errorf("pod issuance requires an allowlist")
	}
	snapshot, err := h.policySnapshot()
	if err != nil {
		return nil, err
	}
	membership := make(map[string]struct{}, len(pod.RuntimeExtensions))
	for _, d := range pod.RuntimeExtensions {
		if !snapshot.Contains(d) {
			return nil, fmt.Errorf("pod image membership not authorized")
		}
		membership[d] = struct{}{}
	}
	// Pod observations are authenticated by the guest quote, so membership
	// can and must check the full launch against this same policy snapshot.
	// A former admission under looser policy cannot regain an unnamed leaf
	// merely because its image still appears somewhere in the current policy.
	// Only platform roles bound by the measured guest base are excluded; the
	// requester cannot assert roles with the exported TLS key.
	for _, observed := range secrets.WorkloadContainers(pod.Containers) {
		if !snapshot.admissions.AdmitsContainer(observed) {
			return nil, fmt.Errorf("pod container observation not authorized")
		}
	}
	resp := workloadclaims.SandboxDigestsResponse{Digests: pod.RuntimeExtensions, Containers: pod.Containers}
	return h.matchWorkload(ctx, snapshot, resp, membership, workloadclaims.VerifiedSandbox{SandboxID: pod.InstanceID()}), nil
}
