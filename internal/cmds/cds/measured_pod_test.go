package cds

import (
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

func TestServerRefusesMeasuredPodAuthorityOverlap(t *testing.T) {
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.measured.PodImages = []remote.ImagePin{{Anchor: cfg.measured.OperatorKeys.PEM()}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("server accepted a Pod launch authority that can write policy")
	}
}

func TestCDSServeHasNoUnmeasuredPodPolicyOverride(t *testing.T) {
	if NewCmd().Flags().Lookup("pod-image-policy-file") != nil {
		t.Fatal("CDS serving accepts Pod policy outside the measured configuration")
	}
}
