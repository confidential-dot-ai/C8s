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
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

// runMeasuredConfig runs CDS on the configuration document its VM was launched
// with. The host can write that file, so the bytes are settings only once a
// verified self-report binds them; the platform CDS attests on comes from the
// same report rather than from an operator's claim about it.
func runMeasuredConfig(ctx context.Context, cfg config) error {
	document, err := os.ReadFile(cfg.configPath)
	if err != nil {
		return fmt.Errorf("read --config: %w", err)
	}
	if err := requireLoopbackAttestationAPI(cfg.attestationApiURL); err != nil {
		return err
	}
	platform, err := credrelease.VerifyMeasuredLaunchFile(ctx, cfg.attestationApiURL, document)
	if err != nil {
		return fmt.Errorf("--config %s is not the document this VM was launched with: %w", cfg.configPath, err)
	}
	served, err := withMeasuredConfig(cfg, document, platform)
	if err != nil {
		return fmt.Errorf("--config %s: %w", cfg.configPath, err)
	}
	slog.Info("serving a measured CDS configuration", "cluster_id", served.measured.ClusterID, "platform", platform)
	return run(served)
}

// withMeasuredConfig returns cfg serving the document this VM was launched
// with, on the platform its launch proved. The settings and the bytes they
// were read from are one verified read: a replica's peers and its cluster's
// decrees are bound to those bytes.
func withMeasuredConfig(cfg config, document []byte, platform teetypes.Family) (config, error) {
	measured, err := cdsconfig.Parse(document)
	if err != nil {
		return config{}, err
	}
	cfg.measuredFile = document
	cfg.measured = measured
	cfg.armtlsPlatform = platform
	return cfg, nil
}

// requireLoopbackAttestationAPI holds the self-report to the attester inside
// this VM: a report fetched over the network is another guest's, and the
// attestation-api a CDS VM runs listens on loopback.
func requireLoopbackAttestationAPI(raw string) error {
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", raw); err != nil {
		return err
	}
	endpoint, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--attestation-api-url %q: %w", raw, err)
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.IsLoopback() {
		return fmt.Errorf("--attestation-api-url %q must name a loopback address: CDS attests through the attestation-api inside its own VM", raw)
	}
	return nil
}
