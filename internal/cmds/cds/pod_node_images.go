package cds

import (
	"log/slog"
	"reflect"
	"sync"

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
	return &podSeparatedNodeImages{PinSource: source, pods: pods}
}

type podSeparatedNodeImages struct {
	armtls.PinSource
	pods []remote.ImagePin

	// refused is the node set Current last emptied, so one refusal is logged
	// per decree rather than per request.
	mu      sync.Mutex
	refused []remote.ImagePin
}

func (s *podSeparatedNodeImages) Current() refvalues.ReferenceValues {
	current := s.PinSource.Current()
	err := cdsconfig.ValidatePodNodeAuthorities(s.pods, current.Images)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		if s.refused != nil {
			slog.Info("node image set accepted again", "node_images", len(current.Images))
		}
		s.refused = nil
		return current
	}
	if !reflect.DeepEqual(s.refused, current.Images) {
		slog.Error("node image set refused: every node request is denied until a decree without a Pod launch authority arrives", "error", err, "node_images", len(current.Images))
	}
	s.refused = current.Images
	// Both /attest and armTLS refuse a set with no images. Retaining only
	// its family lets /measurements truthfully publish that refusal, with
	// no filtered subset or fallback to previously accepted images.
	return refvalues.ReferenceValues{Family: current.Family}
}
