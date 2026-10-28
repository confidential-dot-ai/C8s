package cds

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

// excludedByConfig are the flags --config excludes: the measured configuration
// decides each of these settings, or, for the platform and the measured-policy
// journal, the launch and the VM itself do.
var excludedByConfig = []string{
	"armtls-platform",
	"operator-keys",
	"allowlist-seed",
	"follow-seed",
	"image-policy-file",
	"measurements",
	"rtmrs",
	"dns-san-file",
	"dns-san-pattern",
	"sandbox-inventory-cidr",
	"measured-policies-file",
}

// runMeasuredConfig runs CDS on the configuration document its VM was launched
// with. The host can write that file, so the bytes are settings only once a
// verified self-report binds them; the platform CDS attests on comes from the
// same report rather than from an operator's claim about it.
func runMeasuredConfig(ctx context.Context, cfg config) error {
	document, err := os.ReadFile(cfg.configPath)
	if err != nil {
		return fmt.Errorf("read --config: %w", err)
	}
	measured, err := cdsconfig.Parse(document)
	if err != nil {
		return fmt.Errorf("--config %s: %w", cfg.configPath, err)
	}
	if err := requireLoopbackAttestationAPI(cfg.attestationApiURL); err != nil {
		return err
	}
	platform, err := credrelease.VerifyMeasuredLaunchFile(ctx, cfg.attestationApiURL, document)
	if err != nil {
		return fmt.Errorf("--config %s is not the document this VM was launched with: %w", cfg.configPath, err)
	}
	if err := validateARMTLSPlatform("the platform this VM's launch proved", platform.String()); err != nil {
		return err
	}
	slog.Info("serving a measured CDS configuration", "cluster_id", measured.ClusterID, "platform", platform)
	return run(withMeasuredConfig(cfg, measured, platform))
}

// withMeasuredConfig returns cfg serving measured on the platform its launch
// proved. Nothing in such a VM extends a register, so it journals no measured
// policy.
func withMeasuredConfig(cfg config, measured *cdsconfig.Config, platform teetypes.Family) config {
	cfg.measured = measured
	cfg.armtlsPlatform = platform.String()
	cfg.measuredPolicies = ""
	return cfg
}

// requireLoopbackAttestationAPI holds the self-report to the attester inside
// this VM: a report fetched over the network is another guest's, and the
// attestation-api a CDS VM runs listens on loopback.
func requireLoopbackAttestationAPI(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--attestation-api-url %q: %w", raw, err)
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.IsLoopback() {
		return fmt.Errorf("--attestation-api-url %q must name a loopback address: with --config, CDS attests through its own attestation-api", raw)
	}
	return nil
}
