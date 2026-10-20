package nriimagepolicy

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// workloadMeasurer is the subset of runtimemeasure.Journal the plugin uses.
type workloadMeasurer interface {
	MeasureOnce(ref string) (bool, error)
}

// openRegister is a package var so tests can inject a fake register.
var openRegister = runtimemeasure.Open

// openMeasurer opens RTMR[3] and its journal seeded with the operator key the
// initrd staged, as the policy measurer does.
// Any journal problem (divergence, unreadable register, skipped lines) is
// fatal: the plugin must not start measuring on a register it cannot explain.
func openMeasurer(cfg measureConfig, platform string) (workloadMeasurer, error) {
	if !cfg.RTMR3 {
		return nil, nil
	}
	if cfg.JournalPath == "" {
		return nil, fmt.Errorf("measure.rtmr3 requires journal_path")
	}
	pub, err := readOperatorKey()
	if err != nil {
		return nil, fmt.Errorf("measure: read launch key: %w", err)
	}
	reg, err := openRegister(teetypes.NormalizePlatform(platform))
	if err != nil {
		return nil, fmt.Errorf("measure: open register: %w", err)
	}
	j, err := runtimemeasure.OpenJournalSeeded(cfg.JournalPath, reg, runtimemeasure.Seed(pub))
	if err != nil {
		return nil, fmt.Errorf("measure: journal does not reconcile with RTMR[3]: %w", err)
	}
	return j, nil
}

// measureStarted extends the started container's image digest. A failure
// denies the container: an unmeasured workload must not run.
func (p *plugin) measureStarted(ctx context.Context, imageRef string) error {
	if p.measurer == nil {
		return nil
	}
	digest, err := p.imageDigest(ctx, imageRef)
	if err != nil {
		return fmt.Errorf("measure: resolve image digest of %q: %w", imageRef, err)
	}
	if digest == "" {
		return fmt.Errorf("measure: no digest for %q", imageRef)
	}
	if _, err := p.measurer.MeasureOnce(digest); err != nil {
		return fmt.Errorf("measure %s into RTMR[3]: %w", digest, err)
	}
	return nil
}
