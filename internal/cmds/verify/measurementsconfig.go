package verify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// maxServedMeasurements bounds the served document. Reference values for a
// realistic fleet are kilobytes; a larger body is a wrong endpoint, not a
// bigger policy.
const maxServedMeasurements = 1 << 20

// measurementsReport is the cross-check section of the verdict: what the
// attested target says it is enforcing, beside what the operator pinned.
type measurementsReport struct {
	served   refvalues.ReferenceValues
	fetched  bool
	fetchErr error
	note     string
}

func validateTargetInServedPolicy(target, served refvalues.ReferenceValues) error {
	if target.Family != served.Family {
		return fmt.Errorf("--image-policy-file is for %q but --served-policy-file is for %q: both policies must use the same TEE family", target.Family, served.Family)
	}
	missing, _ := refvalues.Diff(target, served)
	if len(missing) > 0 {
		return fmt.Errorf("--served-policy-file is missing the complete target pin %q from --image-policy-file: every target image, register set and launch anchor must appear in the served policy", missing[0].Name)
	}
	return nil
}

func applyCDSIdentityWarning(oc *Outcome, cfg config, target refvalues.ReferenceValues) {
	if cfg.kind != "cds" || (!oc.Verified && !oc.Partial) {
		return
	}
	if hasMultipleLaunchAnchors(target) {
		oc.Warnings = append(oc.Warnings, "--image-policy-file accepts multiple launch-key anchors as the CDS server; agent identities included in this file can pass as CDS. Use a server-only --image-policy-file and --served-policy-file for the full served set")
	}
}

func hasMultipleLaunchAnchors(values refvalues.ReferenceValues) bool {
	anchors := make(map[string]struct{})
	for _, image := range values.Images {
		if len(image.Anchor) > 0 {
			anchors[string(image.Anchor)] = struct{}{}
		}
	}
	return len(anchors) > 1
}

// fetchServedMeasurements parses /measurements from the attested endpoint.
func fetchServedMeasurements(ctx context.Context, base, serverName, wantCertSHA256 string, timeout time.Duration) (refvalues.ReferenceValues, error) {
	resp, err := fetchAttested(ctx, base+"/measurements", serverName, wantCertSHA256, timeout)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("fetch /measurements: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return refvalues.ReferenceValues{}, fmt.Errorf("/measurements not served: this target predates the endpoint, so its enforced set cannot be checked")
	}
	if resp.StatusCode != http.StatusOK {
		return refvalues.ReferenceValues{}, fmt.Errorf("/measurements returned %d", resp.StatusCode)
	}
	body, err := readutil.ReadAll(resp.Body, maxServedMeasurements)
	if errors.Is(err, readutil.ErrTooLarge) {
		return refvalues.ReferenceValues{}, fmt.Errorf("/measurements body exceeds %d bytes", maxServedMeasurements)
	}
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("read /measurements: %w", err)
	}
	return refvalues.ParseRendered(body)
}

// checkServedMeasurements compares the served set against the operator's file,
// naming flagName (the flag that supplied the file) in every failure.
// Equality is exact in both directions: an entry the target pins and the file
// does not is the substitution this check exists to catch, and one the file
// pins and the target does not means the cluster is enforcing less than the
// operator believes.
func checkServedMeasurements(flagName string, want refvalues.ReferenceValues, report measurementsReport, fail func(string, ...any)) {
	if report.fetchErr != nil {
		fail("could not fetch /measurements to check it against %s: %v", flagName, report.fetchErr)
		return
	}
	if !report.fetched {
		fail("%s cannot be checked: %s", flagName, report.note)
		return
	}
	if len(report.served.Images) == 0 {
		fail("the target serves an empty measurement set: it admits any TEE attestation, while %s pins %d image(s)", flagName, len(want.Images))
		return
	}
	if want.Family != report.served.Family {
		fail("%s is for %q but the target enforces %q", flagName, want.Family, report.served.Family)
		return
	}
	missing, extra := refvalues.Diff(want, report.served)
	var hint string
	if flagName == "--image-policy-file" {
		hint = "; if the target serves agent identities too, name the served set with --served-policy-file"
	}
	for _, e := range extra {
		fail("the target admits an image %s does not pin: %s (%x)%s", flagName, e.Name, e.Digest, hint)
	}
	for _, e := range missing {
		fail("%s pins an image the target does not admit: %s (%x)", flagName, e.Name, e.Digest)
	}
}

// gatherMeasurements fetches the set the target reports enforcing. Like the
// operator-key fetch it never fails the run here; a fetch error is recorded so
// checkServedPolicy can fail the verdict when a policy flag asked for
// the check, rather than letting an erroring endpoint dodge it.
func gatherMeasurements(ctx context.Context, cfg config, plan *verifyPlan, ev *evidence) measurementsReport {
	if plan.served == nil {
		return measurementsReport{}
	}
	if cfg.kind != "cds" {
		return measurementsReport{note: "target kind is not cds (use --kind cds to enable)"}
	}
	if cfg.url == "" {
		return measurementsReport{note: "not fetched (no target URL)"}
	}
	if ev.certSHA256 == "" {
		return measurementsReport{note: "not fetched (no serving cert to bind to)"}
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return measurementsReport{note: "not fetched: " + err.Error()}
	}
	served, err := fetchServedMeasurements(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout)
	if err != nil {
		return measurementsReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return measurementsReport{served: served, fetched: true}
}
