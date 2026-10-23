package nriimagepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// followedPins is the node's CDS pin set when it follows the operator's
// signed pin decrees: a cdspins.Source whose changes are also written to the
// policy the plugin mounts into credential clients, so every CDS client of
// the node moves to a new CDS image together.
type followedPins struct {
	*cdspins.Source
	onChange func(refvalues.ReferenceValues) error
	logger   *slog.Logger
}

func (f *followedPins) Refresh(ctx context.Context) (bool, error) {
	changed, err := f.Source.Refresh(ctx)
	if changed && f.onChange != nil {
		epoch, _ := f.Epoch()
		f.logger.Info("following a new CDS pin decree", "base_epoch", epoch, "images", len(f.Current().Images))
		if werr := f.onChange(f.Current()); werr != nil {
			f.logger.Error("could not hand the new CDS pins to credential clients", "error", werr)
		}
	}
	return changed, err
}

var _ armtls.PinSource = (*followedPins)(nil)

// mirrorTo makes every decree the node follows rewrite the policy mounted at
// path in place, for the credential clients that read it.
func (f *followedPins) mirrorTo(path string) {
	f.onChange = func(set refvalues.ReferenceValues) error {
		doc, err := refvalues.Format(set)
		if err != nil {
			return err
		}
		return rewriteInPlace(path, doc)
	}
}

// cdsDecrees builds the node's decree-following pin source, or nil when the
// node publishes no decree info (a cluster without HA CDS).
func (c pullConfig) cdsDecrees(platform string, logger *slog.Logger) (*followedPins, error) {
	if c.CDSDecreesFile == "" {
		return nil, nil
	}
	info, ok, err := cmdsutil.LoadCDSDecreesInfo(c.CDSDecreesFile)
	if err != nil || !ok {
		return nil, err
	}
	if c.CDSMeasurementsConfig == "" {
		return nil, fmt.Errorf("allowlist.pull.cds_decrees_file needs cds_measurements_config")
	}
	bootstrap, err := c.policySet(platform)
	if err != nil {
		return nil, err
	}
	src, err := cmdsutil.CDSDecreeSource(info, bootstrap, c.URL, c.CDSDecreesState)
	if err != nil {
		return nil, fmt.Errorf("CDS pin decrees: %w", err)
	}
	return &followedPins{Source: src, logger: logger}, nil
}

// pinsSet is the CDS set the plugin holds CDS to now: the followed decree's
// when there is one, else the launch document's.
func (c pullConfig) pinsSet(platform string) (refvalues.ReferenceValues, error) {
	if c.decrees != nil {
		return c.decrees.Current(), nil
	}
	return c.policySet(platform)
}

// followDecrees polls for a newer pin decree until ctx ends. Clients also
// refresh on a pin miss; the poll moves a node that is not talking to CDS.
func followDecrees(ctx context.Context, src armtls.PinSource, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = src.Refresh(ctx)
		}
	}
}

// rewriteInPlace replaces the content of a file the plugin bind-mounts into
// running containers. A rename would leave every existing mount on the old
// inode, so the bytes are rewritten in the same file; a client reading it
// halfway finds a document that does not parse, keeps its set, and reads it
// again on its next pin miss.
func rewriteInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
