package nriimagepolicy

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// followedPins is the node's CDS pin set when it follows the operator's
// signed pin decrees: a cdspins.Source whose changes are also written to the
// policy the plugin mounts into credential clients (mounted, when set), so
// every CDS client of the node moves to a new CDS image together.
type followedPins struct {
	*cdspins.Source
	mu        sync.Mutex // orders refresh, formatting and in-place publication
	dirty     bool       // retry failed publication even without a newer decree
	mounted   string
	logger    *slog.Logger
	writeFile func(string, []byte, os.FileMode) error // nil uses os.WriteFile
}

func (f *followedPins) Refresh(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed, err := f.Source.Refresh(ctx)
	f.dirty = f.dirty || changed
	if changed {
		epoch, _ := f.Epoch()
		f.logger.Info("following a new CDS pin decree", "base_epoch", epoch, "images", len(f.Current().Images))
	}
	if f.dirty && f.mounted != "" {
		// Rewrite the bytes in place (os.WriteFile truncates, it does not
		// rename): running pods' bind mounts pin the file's inode. A client
		// reading it halfway finds a document that does not parse, keeps its
		// set, and reads it again on its next pin miss.
		doc, werr := refvalues.Format(f.Current())
		if werr == nil {
			write := f.writeFile
			if write == nil {
				write = os.WriteFile
			}
			werr = write(f.mounted, doc, 0o644)
		}
		if werr == nil {
			f.dirty = false
		}
		if werr != nil {
			f.logger.Error("could not hand the new CDS pins to credential clients", "error", werr)
		}
	}
	return changed, err
}

var _ armtls.PinSource = (*followedPins)(nil)

// cdsDecreesInfo is the cluster, decree key and pin floor of the node's
// launch document, which nodeservices writes into the plugin's config.
type cdsDecreesInfo struct {
	ClusterID string `yaml:"cluster_id"`
	DecreeKey string `yaml:"decree_key"` // PEM P-256 public key
	// PinFloor is the lowest decree base epoch the node accepts: an older
	// decree the operator also signed is refused.
	PinFloor uint64 `yaml:"pin_floor"`
}

// cdsDecrees builds the node's decree-following pin source, or nil when the
// config names no decrees (a cluster without HA CDS). It fetches decrees from
// the CDS (GET /ha/pins), starting from the launch document's CDS policy.
func (c pullConfig) cdsDecrees(platform string, logger *slog.Logger) (*followedPins, error) {
	info := c.CDSDecrees
	if info == nil {
		return nil, nil
	}
	if c.CDSMeasurementsConfig == "" {
		return nil, fmt.Errorf("allowlist.pull.cds_decrees needs cds_measurements_config")
	}
	bootstrap, err := c.policySet(platform)
	if err != nil {
		return nil, err
	}
	key, err := runtimemeasure.ParsePublicKeyPEM([]byte(info.DecreeKey))
	if err != nil {
		return nil, fmt.Errorf("CDS pin decrees: decree key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	src, err := cdspins.New(cdspins.Config{ClusterID: info.ClusterID, DecreeKey: der, Bootstrap: bootstrap,
		Fetch: cdspins.HTTPFetch(strings.TrimRight(c.URL, "/")), StateFile: c.CDSDecreesState, MinEpoch: info.PinFloor})
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
