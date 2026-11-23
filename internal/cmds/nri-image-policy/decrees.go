package nriimagepolicy

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/tapins"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
)

// decreeStateName carries the decree across a restart of the plugin; a reboot
// starts from the launch document again.
const decreeStateName = "cds-decree.json"

// followedPins is the node's Trust Authority pin set as the cluster's pin decrees move
// it. Each change is written into the policy the plugin mounts into its
// credential clients, so every Trust Authority client of the node moves together.
type followedPins struct {
	*tapins.Source
	logger *slog.Logger

	mu sync.Mutex
	// mounted is the policy the plugin hands its credential clients, and
	// handedOut the decree generation last written there.
	mounted   string
	handedOut uint64
}

var _ armtls.PinSource = (*followedPins)(nil)

// Refresh hands the set the newest decree leaves to the credential clients.
func (f *followedPins) Refresh() error {
	err := f.Source.Refresh()
	f.handToClients()
	return err
}

// mountInto writes the set it already holds to path.
func (f *followedPins) mountInto(path string) {
	f.mu.Lock()
	f.mounted = path
	f.mu.Unlock()
	f.handToClients()
}

// handToClients rewrites the mounted policy where the set moved since the
// last write, and again after a write that failed. The bytes go in place: a
// running pod's bind mount holds the file's inode.
func (f *followedPins) handToClients() {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := f.Generation()
	if f.mounted == "" || held == f.handedOut {
		return
	}
	document, err := refvalues.Format(f.Current())
	if err != nil {
		f.logger.Error("could not render the node's new Trust Authority pins", "error", err)
		return
	}
	if err := os.WriteFile(f.mounted, document, 0o644); err != nil {
		f.logger.Error("could not hand the node's new Trust Authority pins to its credential clients", "path", f.mounted, "error", err)
		return
	}
	f.handedOut = held
	version, _ := f.Version()
	f.logger.Info("following a new Trust Authority pin decree", "version", version, "images", len(f.Current().Images))
}

// taDecrees asks a replica the node already pins first, and falls back to an
// unverified fetch only where none answers. It answers [cdspins.ErrSingleCDS]
// where the launch file this node pins names one Trust Authority.
func (c pullConfig) taDecrees(bootstrap refvalues.ReferenceValues, logger *slog.Logger) (*followedPins, error) {
	url := strings.TrimRight(c.URL, "/")
	source, err := tapins.New(tapins.Config{
		Bootstrap: bootstrap,
		Attested:  tapins.AttestedHTTPFetch(url, c.AttestationApiURL),
		Fetch:     tapins.HTTPFetch(url),
		StateFile: filepath.Join(enforcerRuntimeDir, decreeStateName),
		Floor:     c.CDSPinFloor,
	})
	if err != nil {
		return nil, err
	}
	return &followedPins{
		Source: source,
		logger: logger,
	}, nil
}

// taPinSource is chosen once at start-up: the cluster's decrees where this
// node's Trust Authority is one replica of several, the launch document's own set where
// that Trust Authority runs alone.
func (c pullConfig) taPinSource(logger *slog.Logger) (armtls.PinSource, *followedPins, error) {
	set, err := c.policySet()
	if err != nil {
		return nil, nil, err
	}
	decrees, err := c.taDecrees(set, logger)
	switch {
	case errors.Is(err, tapins.ErrSingleCDS):
		return armtls.FixedPins(set), nil, nil
	case err != nil:
		return nil, nil, fmt.Errorf("follow the cluster's Trust Authority pin decrees: %w", err)
	}
	return decrees, decrees, nil
}
