package cdsconfig

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// ValidatePodAuthorities keeps Pod launch keys distinct from every explicitly
// configured node anchor and operator-write key. Compare parsed keys, not PEM
// bytes: whitespace changes the launch binding without changing who can sign.
// An unanchored development policy supplies no additional authority here.
func (c *Config) ValidatePodAuthorities() error {
	if err := ValidatePodNodeAuthorities(c.PodImages, c.Nodes.Images); err != nil {
		return err
	}
	return distinctPodAuthorities(c.PodImages, c.OperatorKeys.Keys())
}

// ValidatePodNodeAuthorities applies the measured Pod authority boundary to a
// current node set, including replacements accepted by an HA decree. Reject
// the whole set on an overlap; never merge it with the bootstrap identities.
func ValidatePodNodeAuthorities(pods, nodes []remote.ImagePin) error {
	if len(pods) == 0 {
		return nil
	}
	var authorities []*ecdsa.PublicKey
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
	return distinctPodAuthorities(pods, authorities)
}

func distinctPodAuthorities(pods []remote.ImagePin, authorities []*ecdsa.PublicKey) error {
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
