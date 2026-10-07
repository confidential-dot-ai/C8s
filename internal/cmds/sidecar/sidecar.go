// Package sidecar holds the CDS-release plumbing shared by the get-secret and
// get-volume sidecars: the config they render from the webhook, the mTLS
// client bound to the pod's leaf, the challenge/sandbox-token dance around
// each store request, and the retry loop that turns "not released yet" into
// bounded patience. The two commands differ only in what they do with the
// released bytes.
package sidecar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Config is the release plumbing every sidecar needs. The webhook renders all
// of it; each command adds its own fields for what it fetches and where it
// puts the result.
type Config struct {
	CDSURL                 string
	AttestationApiURL      string
	Measurements           []string
	RTMRs                  []string
	MeasurementsConfig     string
	MeasurementsConfigJSON string

	CertPath string
	KeyPath  string

	Attempts         int
	RetryInterval    time.Duration
	RequestTimeout   time.Duration
	InventoryTimeout time.Duration
}

// Endpoint is the compiled inventory endpoint: where the sandbox token is
// redeemed. The flag selects between two baked values, never an address, so a
// control-plane value cannot redirect the redemption to a rogue inventory
// (docs/getcert-workload-binding.md, Corner 5).
func (c Config) Endpoint() string {
	return workloadclaims.InventoryEndpoint()
}

// BindFlags registers the flags shared by every sidecar, with get-secret's
// usage texts as the default prose. A command whose semantics differ (e.g.
// get-volume's request timeout also covers the node agent, and its guest
// shape also moves the volume daemon onto guest loopback) overrides the
// affected flag's Usage via f.Lookup after this call.
func BindFlags(f *pflag.FlagSet, cfg *Config) {
	cmdsutil.BindImagePolicyFlags(f, &cfg.MeasurementsConfig, &cfg.MeasurementsConfigJSON, "", "pins the CDS endpoint; excludes --measurements and --rtmrs")
	f.StringVar(&cfg.CDSURL, "cds-url", "", "https base URL of CDS")
	f.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "local attestation-api used to verify CDS's armTLS certificate")
	f.StringSliceVar(&cfg.Measurements, "measurements", nil, "SHA-384 hex launch measurement(s) CDS must present (repeatable; empty pins none, UNSAFE)")
	f.StringSliceVar(&cfg.RTMRs, "rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> CDS must additionally satisfy (repeatable; ignored when CDS presents SNP evidence, empty pins no registers)")
	f.StringVar(&cfg.CertPath, "cert", "/run/c8s/certs/tls.crt", "the pod's CDS-issued certificate, presented to CDS")
	f.StringVar(&cfg.KeyPath, "key", "/run/c8s/certs/tls.key", "private key for --cert")
	f.IntVar(&cfg.Attempts, "attempts", 60, "how many times to try before failing; release is refused until every main container is running, so retries are expected")
	f.DurationVar(&cfg.RetryInterval, "retry-interval", 5*time.Second, "wait between attempts")
	f.DurationVar(&cfg.RequestTimeout, "request-timeout", 10*time.Second, "per-request timeout against CDS")
	f.DurationVar(&cfg.InventoryTimeout, "inventory-timeout", 5*time.Second, "timeout for redeeming a sandbox token from the node's admission inventory")
}

// Validate checks the shared half of a config and canonicalises the CDS URL.
// Each command's own validate covers the fields only it knows about.
func (c *Config) Validate() error {
	if c.CDSURL == "" {
		return fmt.Errorf("--cds-url is required")
	}
	c.CDSURL = strings.TrimRight(c.CDSURL, "/")
	if !strings.HasPrefix(c.CDSURL, "https://") {
		return fmt.Errorf("--cds-url must be https (armTLS)")
	}
	if c.AttestationApiURL == "" {
		return fmt.Errorf("--attestation-api-url is required to verify CDS")
	}
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", c.AttestationApiURL); err != nil {
		return err
	}
	if c.Attempts <= 0 {
		return fmt.Errorf("--attempts must be positive")
	}
	if c.RetryInterval <= 0 || c.RequestTimeout <= 0 || c.InventoryTimeout <= 0 {
		return fmt.Errorf("--retry-interval, --request-timeout and --inventory-timeout must be positive")
	}
	return nil
}

// ParsePins resolves the pins this sidecar holds its CDS to: the node's policy
// where the enforcer mounts it, otherwise --measurements and --rtmrs.
func (c *Config) ParsePins() (armtls.Pins, error) {
	policy, source, err := cmdsutil.ResolveCDSPins(workloadclaims.CDSPinsPath,
		cmdsutil.ImagePolicySource{File: c.MeasurementsConfig, JSON: c.MeasurementsConfigJSON},
		cmdsutil.MeasurementPins{Measurements: c.Measurements, Registers: c.RTMRs})
	if err != nil {
		return armtls.Pins{}, err
	}
	slog.Info("CDS pins resolved", "source", source)
	cmdsutil.WarnIfCDSUnpinned(len(policy.Measurements)+len(policy.Images),
		"--measurements empty: the CDS this sidecar hands its sandbox token to is not pinned to a launch measurement. UNSAFE outside development.")
	return armtls.Pins(policy), nil
}

// Terminal marks a non-nil error no later attempt can clear, so Retry stops on
// it.
func Terminal(err error) error { return terminal{err} }

type terminal struct{ err error }

func (t terminal) Error() string { return t.err.Error() }
func (t terminal) Unwrap() error { return t.err }

// Retry runs one whole release pass at a time, retrying the set until an
// attempt succeeds, one returns a Terminal error, or the budget runs out.
//
// Retrying is expected, not exceptional: until every main container is running
// the sandbox does not match its workload entry, so early attempts are denied
// by design. The bound turns a genuinely stuck release into a visible failure
// instead of an idle sidecar in a Running pod. The what argument names the
// thing being released ("secret", "volume") in the log lines.
func Retry(ctx context.Context, cfg Config, what string, attempt func(context.Context) error) error {
	var lastErr error
	for n := 1; n <= cfg.Attempts; n++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if _, ok := errors.AsType[terminal](err); ok {
			slog.Error(what+" release cannot succeed", "attempt", n, "of", cfg.Attempts, "error", err)
			return err
		}
		if n == cfg.Attempts {
			// The last attempt's error is the one that matters: log it at
			// ERROR so a stuck release shows its real cause in the sidecar's
			// own log, not just the generic per-attempt INFO line.
			slog.Error(what+" release failed on the final attempt",
				"attempt", n, "of", cfg.Attempts, "error", err)
			break
		}
		slog.Info(what+" not released yet; retrying",
			"attempt", n, "of", cfg.Attempts, "retry_in", cfg.RetryInterval, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.RetryInterval):
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", cfg.Attempts, lastErr)
}
