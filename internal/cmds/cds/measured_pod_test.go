package cds

import (
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// A Pod launch key equal to an operator key is refused at serve time.
func TestServerRefusesMeasuredPodAuthorityOverlap(t *testing.T) {
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.measured.PodImages = []remote.ImagePin{{Anchor: cfg.measured.OperatorKeys.PEM()}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("server accepted a Pod launch authority that can write policy")
	}
}
