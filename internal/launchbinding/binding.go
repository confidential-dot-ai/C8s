// Package launchbinding reads what a guest's launch committed to: the operator
// public key the initrd staged and the launch file the launcher bound, each
// compared against the binding the guest's verified self-report carries.
package launchbinding

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into the launch binding). The
// service reads this file rather than mounting the ISO itself — mounting fails
// under the unit's systemd hardening, and the initrd is the single, measured
// reader of the disk anyway.
// Var (not const) so tests can point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// ErrNoOperatorKey is returned (wrapped) by the Load* functions when no
// operator pubkey is staged at all: the VM was launched without an opkeydata
// disk. It is deliberately distinct from fs.ErrNotExist so that no other
// ENOENT on the way to a binding check is ever mistaken for a non-operator
// boot.
var ErrNoOperatorKey = errors.New("no operator pubkey staged")

// ReadOperatorPubkey reads the operator public key the initrd staged off the
// opkeydata disk. The bytes are exactly what the initrd hashed into the launch
// binding, so runtimemeasure can re-derive the same digest. Absence is
// reported as ErrNoOperatorKey; every other read failure is a hard error.
func ReadOperatorPubkey() ([]byte, error) {
	pub, err := os.ReadFile(operatorPubkeyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s — was the VM launched with an operator key?", ErrNoOperatorKey, operatorPubkeyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", operatorPubkeyPath, err)
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("%s is empty", operatorPubkeyPath)
	}
	return pub, nil
}

// selfReportTimeout bounds the self-attestation round trip against the local
// attestation-api; on expiry the service fails start and systemd retries.
const selfReportTimeout = 15 * time.Second

// attestationReadyTimeout bounds remote.Client.WaitHealthy. attestation-api is a
// Type=simple unit that fetches its certificate collateral over the network
// before it binds its port, so an After= ordering alone lets a caller start
// while the socket is still refusing connections. Package vars so tests can
// shorten them.
var (
	attestationReadyTimeout  = 90 * time.Second
	attestationReadyInterval = 2 * time.Second
)

// verifiedSelfReport returns this guest's own attestation as the local
// attestation-api verified it.
//
// Reading the launch binding off an UNVERIFIED report would take the anchor
// from an unauthenticated field, so the report goes through /verify even though
// the guest produced it. The anchor is a fresh nonce, which makes the report
// non-replayable for free.
//
// One report answers every question this package asks about the guest: the
// operator-key binding (LoadMeasuredOperatorKey) and its own launch
// image identity. LoadMeasuredIdentity answers both
// from one report so the guest attests once.
func verifiedSelfReport(ctx context.Context, attestationAPIURL string) (*teetypes.VerificationResult, error) {
	return readSelfReport(ctx, attestationAPIURL, nil)
}

func readSelfReport(
	ctx context.Context,
	attestationAPIURL string,
	native *armtls.NativeVerifier,
) (*teetypes.VerificationResult, error) {
	client := armtls.NewAttestationClient(attestationAPIURL)
	readyCtx, cancelReady := context.WithTimeout(ctx, attestationReadyTimeout)
	err := client.WaitHealthy(readyCtx, attestationReadyInterval)
	cancelReady()
	if err != nil {
		return nil, fmt.Errorf("attestation-api at %s not ready after %s: %w", attestationAPIURL, attestationReadyTimeout, err)
	}
	ctx, cancel := context.WithTimeout(ctx, selfReportTimeout)
	defer cancel()

	// The attester is asked for the 48-byte prefix and zero-extends it into the
	// 64-byte report data the verifier must find.
	var reportData [64]byte
	if _, err := rand.Read(reportData[:sha512.Size384]); err != nil {
		return nil, fmt.Errorf("self-report nonce: %w", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationAPIURL, reportData[:sha512.Size384])
	if err != nil {
		return nil, fmt.Errorf("attest self: %w", err)
	}
	policy := remote.Policy{ExpectedReportData: reportData[:sha512.Size384]}
	var verified remote.VerifyResponse
	if native != nil {
		verified, err = native.VerifyEvidence(ctx, resp.Envelope(), policy)
	} else {
		verified, err = client.VerifyEvidence(ctx, resp.Envelope(), policy)
	}
	if err != nil {
		return nil, fmt.Errorf("verify self-report: %w", err)
	}
	return &verified.Result, nil
}

// VerifyNativeMeasuredLaunchFile authenticates generated evidence locally,
// retaining the fresh nonce and exact launch binding before trusting settings.
func VerifyNativeMeasuredLaunchFile(
	ctx context.Context,
	attestationAPIURL string,
	launchFile []byte,
	native *armtls.NativeVerifier,
) (teetypes.Family, error) {
	if native == nil {
		return teetypes.FamilyUnknown, errors.New("native launch verifier required")
	}
	report, err := readSelfReport(ctx, attestationAPIURL, native)
	if err != nil {
		return teetypes.FamilyUnknown, err
	}
	if err := runtimemeasure.VerifyBinding(report, launchFile, nil); err != nil {
		return teetypes.FamilyUnknown, err
	}
	return report.Platform.Family(), nil
}

// VerifyMeasuredLaunchFile confirms this guest's launch bound launchFile byte
// for byte, and returns the TEE family the verified report proves. The file is
// NOT itself measured, only its digest, so a host that swapped it post-boot
// produces a mismatch.
//
// A guest whose launch file is its whole configuration runs no workload
// measurer, so the binding must equal the bare anchor: an extension beyond it
// means an unexpected measurer ran.
func VerifyMeasuredLaunchFile(ctx context.Context, attestationAPIURL string, launchFile []byte) (teetypes.Family, error) {
	var noWorkloadDigests []string
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return teetypes.FamilyUnknown, err
	}
	if err := runtimemeasure.VerifyBinding(report, launchFile, noWorkloadDigests); err != nil {
		return teetypes.FamilyUnknown, err
	}
	family := report.Platform.Family()
	if family == teetypes.FamilyUnknown {
		return teetypes.FamilyUnknown, fmt.Errorf("the verified report names platform %q, which routes to no TEE family", report.Platform)
	}
	return family, nil
}

// VerifyLaunchBinding confirms this guest's verified self-report binds
// launchFile's digest under the reported TEE family's launch-file hash,
// followed by a prefix of the allowlist policies in the measured-policy
// journal. A binding it compares and finds different is ErrLaunchFileNotBound;
// a report that carries no binding is not.
func VerifyLaunchBinding(ctx context.Context, attestationAPIURL, journal string, launchFile []byte) error {
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return err
	}
	if _, err := runtimemeasure.Binding(report); err != nil {
		return fmt.Errorf("this guest's self-report: %w", err)
	}
	digest, err := runtimemeasure.LaunchFileDigest(report.Platform.Family(), launchFile)
	if err != nil {
		return err
	}
	// INVARIANT: the journal is read after the report, so it covers every
	// extend the report reflects.
	policies, err := measuredPolicies(journal)
	if err != nil {
		return err
	}
	if _, err := runtimemeasure.MatchLaunchFileDigestPrefix(report, digest, policies); err != nil {
		err = fmt.Errorf("%w: %w", ErrLaunchFileNotBound, err)
		if len(policies) > 0 {
			return fmt.Errorf("binding replays no prefix of the %d measured policies in %s: %w", len(policies), journal, err)
		}
		return err
	}
	return nil
}

// ErrLaunchFileNotBound marks a launch binding that does not commit the
// launch file.
var ErrLaunchFileNotBound = errors.New("the launch binding does not commit the launch file")

// measuredPolicies are the allowlist policies in the measured-policy journal;
// an empty path lists none.
func measuredPolicies(journal string) ([]string, error) {
	if journal == "" {
		return nil, nil
	}
	policies, err := armtls.ReadRuntimeExtensions(journal)
	if err != nil {
		return nil, fmt.Errorf("read measured policies: %w", err)
	}
	slog.Info("measured-policy journal", "path", journal, "policies", len(policies))
	return policies, nil
}
