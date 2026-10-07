// Package cdsconn builds what an operator CLI needs to reach CDS: an HTTP
// client that has verified the endpoint's attestation, and the operator
// credential that signs a write.
//
// It is shared by `c8s allowlist` and `c8s secrets`, which authorize against the
// same pinned operator keys and reach CDS the same way. The attestation
// decisions — that plaintext http needs --insecure, that a router front door is
// trusted through its discovery document, that a direct URL is verified by
// armTLS — belong in one place, since each is a way to talk to an unattested
// endpoint by mistake.
package cdsconn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/routerdiscovery"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// EnvOperatorKey supplies the operator private key when the flag is unset.
const EnvOperatorKey = "C8S_OPERATOR_KEY"

// Options are the connection and credential flags an operator CLI carries.
// Embed it in a command's option struct and bind Flags to its persistent flags.
type Options struct {
	URL                string
	Measurements       []string
	MeasurementsFile   string
	MeasurementsConfig string
	Timeout            time.Duration
	OperatorKey        string
	Insecure           bool

	// Verifier verifies endpoint evidence. Nil defaults to LocalVerifier.
	Verifier PinVerifier
}

// BindFlags registers the connection and credential flags on a command's
// persistent flag set, so every operator CLI spells them the same way.
func BindFlags(pf *pflag.FlagSet, o *Options) {
	pf.StringVar(&o.URL, "url", "", "CDS-issued-TLS router or direct CDS base URL (required); WebPKI router URLs are not attestation-bound")
	pf.StringSliceVar(&o.Measurements, "measurements", nil, "trusted endpoint build ID(s) (repeatable/comma-separated); use the router value for CDS-issued public TLS or the CDS value for a direct URL; empty trusts any attested build (UNSAFE)")
	pf.StringVar(&o.MeasurementsFile, "measurements-file", "", "text file of trusted endpoint SHA-384 hex digests, one per line; use --image-policy-file for complete JSON policies")
	cmdsutil.BindImagePolicyFlags(pf, &o.MeasurementsConfig, nil, "", "pins the endpoint; excludes --measurements and --measurements-file")
	pf.DurationVar(&o.Timeout, "timeout", 15*time.Second, "per-request timeout")
	pf.StringVar(&o.OperatorKey, "operator-key", "", "operator EC private key PEM file, whose public key is pinned on CDS via --operator-keys (env "+EnvOperatorKey+"); required for writes")
	pf.BoolVar(&o.Insecure, "insecure", false, "dev/test only: allow a plaintext http:// CDS URL, skipping armTLS attestation of CDS")
}

// Validate checks the flags every subcommand needs.
func (o *Options) Validate() error {
	if strings.TrimSpace(o.URL) == "" {
		return fmt.Errorf("--url is required")
	}
	return nil
}

// HTTPClient builds a client for CDS. An https URL is verified via armTLS (CDS
// proves its TEE attestation). Plaintext http is refused unless Insecure is
// set, so a typo'd or downgraded URL never silently writes to an
// unauthenticated endpoint.
func (o *Options) HTTPClient(ctx context.Context) (*http.Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid --url %q", o.URL)
	}

	switch u.Scheme {
	case "http":
		if o.MeasurementsConfig != "" {
			return nil, fmt.Errorf("--image-policy-file requires https; plaintext cannot enforce its endpoint identity")
		}
		if !o.Insecure {
			return nil, fmt.Errorf("refusing plaintext http:// for CDS (no attestation): use https:// (armTLS), or pass --insecure for a dev/test endpoint")
		}
		fmt.Fprintln(os.Stderr, "warning: --url is http:// with --insecure; CDS attestation is NOT verified (dev/test only)")
		return &http.Client{Timeout: o.Timeout}, nil
	case "https":
		pins, err := o.loadPins()
		if err != nil {
			return nil, err
		}
		if pins.Empty() {
			fmt.Fprintln(os.Stderr, "warning: no --measurements set; accepting any attested endpoint build (UNSAFE)")
		}
		hc, err := o.httpsClient(ctx, pins)
		if err != nil {
			return nil, err
		}
		hc.Timeout = o.Timeout
		return hc, nil
	default:
		return nil, fmt.Errorf("--url scheme must be http or https, got %q", u.Scheme)
	}
}

// httpsClient builds the attestation-verifying client. A router front door
// serves a CDS-issued cert with no armTLS extension; its trust path is the
// discovery document, so probe for that first and fall back to direct armTLS
// serving-cert verification (a port-forwarded CDS) when the target serves none
// — the same routing `c8s verify` uses in auto mode. A discovery document that
// fails verification is a hard error, never a fallback.
func (o *Options) httpsClient(ctx context.Context, pins refvalues.ReferenceValues) (*http.Client, error) {
	probeCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	verify := o.pinVerifier(pins)
	hc, err := routerdiscovery.NewVerifiedHTTPClient(probeCtx, o.URL, pins.Digests(), verify.Verify)
	switch {
	case err == nil:
		fmt.Fprintln(os.Stderr, "note: target is a router front door; verified its discovery attestation and bound this session to the attested connection")
		return hc, nil
	case errors.Is(err, routerdiscovery.ErrNoDiscovery):
		return localverify.NewARMTLSHTTPClient(pins.Digests(), verify.Verify, o.Timeout), nil
	default:
		return nil, err
	}
}

func (o *Options) loadPins() (refvalues.ReferenceValues, error) {
	source := cmdsutil.ImagePolicySource{File: o.MeasurementsConfig}
	if source.IsSet() {
		return source.LoadValues(cmdsutil.MeasurementPins{Measurements: o.Measurements, MeasurementsFile: o.MeasurementsFile})
	}
	digests, err := o.loadMeasurements()
	return refvalues.FromFlags(digests, nil), err
}

func (o *Options) pinVerifier(pins refvalues.ReferenceValues) PinVerifier {
	verify := o.Verifier
	if verify == nil {
		verify = LocalVerifier{}
	}
	if o.MeasurementsConfig == "" {
		return verify
	}
	return ImagePinVerifier{Verifier: verify, Images: pins.Images}
}

// loadMeasurements combines Measurements and MeasurementsFile into the raw
// digest byte form armTLS verification expects.
func (o *Options) loadMeasurements() ([][]byte, error) {
	return cmdsutil.LoadMeasurements(o.Measurements, o.MeasurementsFile)
}

// Signer builds the operator credential from the flag or the environment. The
// private key never leaves the CLI: it signs a short-lived token bound to the
// exact method, path, and body of one write. It refuses an unpinned endpoint —
// see requirePinnedEndpoint.
func (o *Options) Signer() (*operatorauth.Signer, error) {
	keyPath := o.OperatorKey
	if keyPath == "" {
		keyPath = os.Getenv(EnvOperatorKey)
	}
	if keyPath == "" {
		return nil, fmt.Errorf("operator key required: set --operator-key or %s", EnvOperatorKey)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read operator key: %w", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load operator key: %w", err)
	}
	if err := o.requirePinnedEndpoint(); err != nil {
		return nil, err
	}
	return signer, nil
}

// requirePinnedEndpoint refuses to mint an operator token for an endpoint whose
// build is not pinned. armTLS proves the peer is *a* TEE, not that it is the CDS
// this operator meant; with no --measurements, `c8s secrets put` hands a secret,
// and `c8s allowlist` a policy change, to whatever attested thing answered the
// URL. Reads stay a warning (HTTPClient): they carry no credential and no
// payload, and refusing them would break discovery against a fresh cluster.
//
// A plaintext endpoint is left to HTTPClient, which refuses it outright without
// --insecure and announces it with; adding a pinning complaint on top would only
// bury the specific error under a general one.
func (o *Options) requirePinnedEndpoint() error {
	if u, err := url.Parse(o.URL); err == nil && u.Scheme == "http" {
		return nil
	}
	pinned, err := o.Pinned()
	if err != nil {
		return err
	}
	if !pinned {
		return fmt.Errorf("refusing to authorize against an unpinned CDS: --measurements is empty, so any attested build would be accepted and this operator credential would be presented to it. Pass --image-policy-file <policy.json>, --measurements <endpoint build ID>, or --measurements-file; use the router value for a CDS-issued public TLS front door, the CDS value for a direct URL")
	}
	return nil
}

// Pinned reports whether the image policy or measurement flags name at least
// one trusted endpoint image.
func (o *Options) Pinned() (bool, error) {
	pins, err := o.loadPins()
	if err != nil {
		return false, err
	}
	return !pins.Empty(), nil
}
