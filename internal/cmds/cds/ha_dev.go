//go:build c8s_dev

package cds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// haTimingOverride runs the replicas fast enough for a test to watch an
// election, a lease lapse and a seat change. Every timer it leaves unset is
// the release's own.
var haTimingOverride = cdsha.Timing{
	Heartbeat:  200 * time.Millisecond,
	Election:   200 * time.Millisecond,
	Lease:      time.Second,
	Tick:       100 * time.Millisecond,
	DeadAfter:  5 * time.Second,
	Checkpoint: time.Second,
}

// bindAttestationAPIFlag lets a test verify mock-attested replicas, whose
// evidence no hardware root signs. Setting the flag replaces *verifier.
func bindAttestationAPIFlag(
	cmd *cobra.Command,
	verifier *cdsconn.PinVerifier,
) {
	cmd.Flags().Var(&attestationAPIFlag{verifier: verifier}, "attestation-api-url",
		"c8s_dev builds only: verify every replica through this attestation-api's /verify instead of in-process, against the same --cds-pin")
}

type attestationAPIFlag struct {
	url      string
	verifier *cdsconn.PinVerifier
}

func (f *attestationAPIFlag) String() string { return f.url }

func (f *attestationAPIFlag) Type() string { return "url" }

func (f *attestationAPIFlag) Set(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("want http(s)://<host>:<port> of an attestation-api, got %q", value)
	}
	f.url = value
	*f.verifier = attestationAPIVerifier{api: armtls.NewAttestationClient(value)}
	return nil
}

// attestationAPIVerifier takes the attestation-api's verdict on the evidence
// and enforces the binding and launch digests the armTLS client asks for.
// cdsconn wraps it in the image pins of --cds-pin, as it does LocalVerifier.
type attestationAPIVerifier struct {
	api remote.Client
}

func (v attestationAPIVerifier) Verify(
	ctx context.Context,
	platform string,
	evidence json.RawMessage,
	params localverify.Params,
) (*teetypes.VerificationResult, error) {
	// VerifyEvidence takes no single-digest pins, and dropping one would accept what it refuses.
	if len(params.ExpectedLaunchDigest) > 0 || len(params.ExpectedRTMRs) > 0 {
		return nil, errors.New("the attestation-api verifier enforces launch digests as a set, and was handed a single-digest pin")
	}
	envelope := teetypes.AttestationEvidence{
		Platform: teetypes.NormalizePlatform(platform),
		Evidence: evidence,
	}
	verified, err := v.api.VerifyEvidence(ctx, envelope, remote.Policy{
		ExpectedReportData:   params.ExpectedReportData,
		ExpectedInitDataHash: params.ExpectedInitDataHash,
		AllowDebug:           params.AllowDebug,
		MinTcb:               params.MinTCB,
		Measurements:         params.Measurements,
	})
	if err != nil {
		return nil, err
	}
	return &verified.Result, nil
}
