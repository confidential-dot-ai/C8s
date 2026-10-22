package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// workloadMeasurer is the subset of the RTMR[3] journal the plugin uses.
type workloadMeasurer interface {
	MeasureOnce(ref string) (bool, error)
}

// openRegister is a package var so tests can inject a fake register.
var openRegister = runtimemeasure.Open

// openMeasurer opens the pod role's RTMR[3] writer: the measured-policy
// journal under the plugin's runtime directory, seeded with the launch key
// the initrd staged. Guest readers such as pod-status use the shared
// armtls.NodeJournal path; measuring does not mount the journal into a Pod.
// Config refuses allowlist.pull.measure_policies beside measure.rtmr3, so a
// boot has one writer. Nil when measure.rtmr3 is off or the platform has no
// runtime register. Any journal problem (divergence, unreadable register,
// skipped lines) is fatal: the plugin must not start measuring on a register
// it cannot explain.
func openMeasurer(cfg *config, logger *slog.Logger) (workloadMeasurer, error) {
	if !cfg.Measure.RTMR3 {
		return nil, nil
	}
	platform := teetypes.PlatformType(cfg.NormalizedPlatform())
	if !platform.HasRegisters() {
		logger.Info("workloads are not measured: no runtime register", "platform", platform)
		return nil, nil
	}
	anchor, err := readOperatorKey()
	if err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}
	journal, err := openPolicyJournal(cfg.WorkloadClaims.SocketDir, platform, anchor)
	if err != nil {
		return nil, fmt.Errorf("measure: journal does not reconcile with RTMR[3]: %w", err)
	}
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal)
	// Created readable up front: the journal's first append would create it
	// 0600, and pod-status would serve an empty list until the chmod.
	if err := createReadable(path); err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}
	return &journalMeasurer{journal: journal, path: path}, nil
}

// journalMeasurer extends the journal within the list a certificate can
// carry and keeps the file readable by the non-root readers of the list.
type journalMeasurer struct {
	journal *runtimemeasure.Journal
	path    string
}

func (m *journalMeasurer) MeasureOnce(ref string) (bool, error) {
	digest, err := runtimemeasure.CanonicalDigest(ref)
	if err != nil {
		return false, err
	}
	if measured := m.journal.Digests(); len(measured) >= armtls.MaxRuntimeExtensions && !slices.Contains(measured, digest) {
		return false, fmt.Errorf("the guest measured %d workloads since boot, the most its certificates can carry", len(measured))
	}
	extended, err := m.journal.MeasureOnce(digest)
	// Also after a failed extend, which rewrites the file.
	if cerr := os.Chmod(m.path, 0o644); cerr != nil && !errors.Is(cerr, fs.ErrNotExist) && err == nil {
		err = cerr
	}
	return extended, err
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
