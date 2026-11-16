package launchbinding

// The pod launch key path: a pod CVM's launch binding seeds RTMR[3] with the
// pod launch public key the initrd staged, and the pod's image journal then
// extends it. Ported from the credential-release package main deleted.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// ErrRegisterDoesNotReplay marks a register that is not the staged key's seed
// extended with a prefix of the measured list: the key is not the one the
// launch bound, or the register took an extend the list does not record.
// Neither mends before a reboot, so a caller that keeps running may treat it
// as final. So are ErrNoOperatorKey and a journal over
// armtls.MaxRuntimeExtensions; a failed attestation round trip or file read
// is what a retry can clear.
var ErrRegisterDoesNotReplay = errors.New("the register is not the staged key's seed extended with a prefix of the measured list")

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
// followed by a prefix of the allowlist policies in this node's own journal; an
// extension the journal does not list fails closed. Remote verifiers cannot
// read the journal and accept whatever list the node sends (docs/armtls.md).
//
// Called once at service start: it accepts the policies the node had measured
// by then, and does not see later extends.
func LoadMeasuredOperatorKey(ctx context.Context, attestationAPIURL, journal string) ([]byte, error) {
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
	if err := verifyNodeBinding(report, pub, journal); err != nil {
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
func LoadMeasuredIdentity(ctx context.Context, platform, attestationAPIURL, journal string) (MeasuredIdentity, error) {
	pub, pubErr := ReadOperatorPubkey()
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return MeasuredIdentity{}, err
	}
	if pubErr == nil {
		pubErr = verifyNodeBinding(report, pub, journal)
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

// verifyNodeBinding checks that report binds anchor followed by a prefix of
// the allowlist policies in the measured-policy journal; an empty journal path
// lists none. The journal is read after the report, so it may hold extends
// the report does not. A journal over armtls.MaxRuntimeExtensions fails, as it
// does at every verifier. Only a register that was compared and found
// different is ErrRegisterDoesNotReplay; a report that carries no binding is
// not.
func verifyNodeBinding(report *teetypes.VerificationResult, anchor []byte, journal string) error {
	if _, err := runtimemeasure.Binding(report); err != nil {
		return fmt.Errorf("this guest's self-report: %w", err)
	}
	return matchJournalPrefix(journal, func(policies []string) error {
		if _, err := runtimemeasure.MatchBindingPrefix(report, anchor, policies); err != nil {
			return fmt.Errorf("%w: %w", ErrRegisterDoesNotReplay, err)
		}
		return nil
	})
}

// matchJournalPrefix runs match, a binding check replaying a prefix of the
// given policies, on the allowlist policies in the measured-policy journal.
func matchJournalPrefix(journal string, match func(policies []string) error) error {
	// INVARIANT: the journal is read after the caller fetched the report, so it
	// covers every extend the report reflects.
	var policies []string
	if journal != "" {
		var err error
		if policies, err = armtls.ReadRuntimeExtensions(journal); err != nil {
			return fmt.Errorf("read measured policies: %w", err)
		}
		slog.Info("measured-policy journal", "path", journal, "policies", len(policies))
	}
	err := match(policies)
	if err != nil && len(policies) > 0 {
		return fmt.Errorf("binding replays no prefix of the %d measured policies in %s: %w", len(policies), journal, err)
	}
	return err
}
