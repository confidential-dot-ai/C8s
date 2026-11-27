package ta

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/launchbinding"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
)

// runMeasuredConfig runs Trust Authority on the configuration document its VM was launched
// with. The host can write that file, so the bytes are settings only once a
// verified self-report binds them; the platform Trust Authority attests on comes from the
// same report rather than from an operator's claim about it.
func runMeasuredConfig(ctx context.Context, cfg config) error {
	document, err := os.ReadFile(cfg.configPath)
	if err != nil {
		return fmt.Errorf("read --config: %w", err)
	}
	if err := requireLoopbackAttestationAPI(cfg.attestationApiURL); err != nil {
		return err
	}
	platform, err := launchbinding.VerifyMeasuredLaunchFile(ctx, cfg.attestationApiURL, document)
	if err != nil {
		return fmt.Errorf("--config %s is not the document this VM was launched with: %w", cfg.configPath, err)
	}
	measured, err := taconfig.ParseForFamily(document, platform)
	if err != nil {
		return fmt.Errorf("--config %s: %w", cfg.configPath, err)
	}
	slog.Info("serving a measured Trust Authority configuration", "cluster_id", measured.ClusterID, "platform", platform)
	return run(ctx, withMeasuredConfig(cfg, measured, platform))
}

// withMeasuredConfig returns cfg serving measured on the platform its launch
// proved.
func withMeasuredConfig(cfg config, measured *taconfig.Config, platform teetypes.Family) config {
	cfg.measured = measured
	cfg.armtlsPlatform = platform
	return cfg
}

// requireLoopbackAttestationAPI holds the self-report to the attester inside
// this VM: a report fetched over the network is another guest's, and the
// attestation-api a Trust Authority VM runs listens on loopback.
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
		return fmt.Errorf("--attestation-api-url %q must name a loopback address: Trust Authority attests through the attestation-api inside its own VM", raw)
	}
	return nil
}
