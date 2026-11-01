package cds

import (
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Every node consumer shares this source: issuance, inventory callbacks and
// /measurements. A signed node-image decree cannot turn a measured Pod launch
// authority into a node authority after the startup check has passed.
func separatePodAuthorities(source armtls.PinSource, pods []remote.ImagePin) armtls.PinSource {
	if len(pods) == 0 {
		return source
	}
	return podSeparatedNodeImages{PinSource: source, pods: pods}
}

type podSeparatedNodeImages struct {
	armtls.PinSource
	pods []remote.ImagePin
}

func (s podSeparatedNodeImages) Current() refvalues.ReferenceValues {
	current := s.PinSource.Current()
	if err := cdsconfig.ValidatePodNodeAuthorities(s.pods, current.Images); err != nil {
		// Both /attest and armTLS refuse a set with no images. Retaining only
		// its family lets /measurements truthfully publish that refusal, with
		// no filtered subset or fallback to previously accepted images.
		return refvalues.ReferenceValues{Family: current.Family}
	}
	return current
}
