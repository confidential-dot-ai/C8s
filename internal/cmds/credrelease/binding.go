// Package credrelease implements the in-guest credential-release service (B4
// of the operator-key design). It issues an operator a short-lived kube client
// certificate, but only to a caller who proves possession of the operator
// private key whose public half was bound into the CVM's launch identity at
// launch — giving an external operator
// console-free, non-TOFU admin access with no pre-shared cluster secret and
// no trust in the untrusted host.
package credrelease

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/policymeasure"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into the launch binding). The
// service reads this file rather than mounting the ISO itself — mounting fails
// under the unit's systemd hardening, and the initrd is the single, measured
// reader of the disk anyway.
// Var (not const) so tests can point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// measuredPoliciesPath is the NRI plugin's journal of the allowlist policies
// it extended into RTMR[3] (internal/policymeasure).
var measuredPoliciesPath = "/var/run/nri-image-policy/" + policymeasure.JournalName

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
	client := remote.NewClient(attestationAPIURL)
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
	verified, err := client.VerifyEvidence(ctx,
		resp.Envelope(), remote.Policy{ExpectedReportData: reportData[:sha512.Size384]})
	if err != nil {
		return nil, fmt.Errorf("verify self-report: %w", err)
	}
	return &verified.Result, nil
}

// LoadMeasuredOperatorKey reads the operator pubkey the initrd staged off the
// opkeydata disk and confirms the guest was launched to trust it. The returned
// bytes are safe to treat as the authorized operator key.
//
// This is the load-bearing anchor check: the pubkey file is NOT itself
// measured, only its digest, so before trusting the on-disk key the service
// confirms it is the key the launch bound. A host that swapped the file
// post-boot produces a mismatch — it can forge neither the register the
// measured initrd extended nor the field the launcher committed at launch.
//
// Which field carries the binding, and how wide it is, is runtimemeasure's
// problem: this reads the verified report and asks whether it names this key.
// The node image runs no workload measurer, so the binding must equal the seed
// followed by the allowlist policies the NRI plugin journaled; any other
// extension means an unexpected measurer ran, and the comparison fails closed.
//
// Called once at service start; the binding is fixed for the life of the guest.
func LoadMeasuredOperatorKey(ctx context.Context, attestationAPIURL string) ([]byte, error) {
	pub, err := ReadOperatorPubkey()
	if err != nil {
		return nil, err
	}
	// The platform comes from the verified report, not from configuration: a
	// config string says which platform an operator EXPECTED, and the anchor
	// check must key off what the hardware actually proved.
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return nil, err
	}
	if err := verifyNodeBinding(report, pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// MeasuredIdentity separates the verified guest image from the operator-key
// binding result. Non-operator boots still need Image to pin peer nodes, so
// a missing key must not discard a verified image. OperatorKeyErr distinguishes
// that absence (ErrNoOperatorKey) from a read or binding failure; callers must
// reject other key errors. OperatorKey is authorized only when OperatorKeyErr
// is nil.
type MeasuredIdentity struct {
	OperatorKey    []byte
	OperatorKeyErr error
	Image          runtimemeasure.ImageIdentity
}

// LoadMeasuredIdentity checks the operator key and reads the guest image
// identity from one verified self-report. Image is always resolved, even if the
// key is missing or its binding fails; OperatorKeyErr records that failure.
// The returned error is reserved for self-report, image, or platform failures.
func LoadMeasuredIdentity(ctx context.Context, platform, attestationAPIURL string) (MeasuredIdentity, error) {
	pub, pubErr := ReadOperatorPubkey()
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return MeasuredIdentity{}, err
	}
	if pubErr == nil {
		pubErr = verifyNodeBinding(report, pub)
	}
	if pubErr != nil {
		pub = nil
	}
	identity, err := runtimemeasure.IdentityFromResult(report)
	if err != nil {
		return MeasuredIdentity{}, err
	}
	if string(identity.Family()) != platform {
		return MeasuredIdentity{}, fmt.Errorf("this image was built for platform %q but the verified self-report is from %q", platform, report.Platform)
	}
	return MeasuredIdentity{OperatorKey: pub, OperatorKeyErr: pubErr, Image: identity}, nil
}

// verifyNodeBinding checks that report binds anchor, followed by a prefix of
// the measured allowlist policies: the journal is read after the report, so
// it may hold extends the report does not.
func verifyNodeBinding(report *teetypes.VerificationResult, anchor []byte) error {
	policies, err := policymeasure.Read(measuredPoliciesPath)
	if err != nil {
		return fmt.Errorf("read measured policies: %w", err)
	}
	_, err = policymeasure.Prefix(report, anchor, policies)
	return err
}
