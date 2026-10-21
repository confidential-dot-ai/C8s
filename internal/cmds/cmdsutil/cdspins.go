package cmdsutil

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
)

// CDSPinsInfo is what a client needs to follow the operator's signed CDS pin
// decrees: the cluster and the decree key, from the launch document. Nodes
// publish it as /run/c8s-node/cds-pins.json; it is public.
type CDSPinsInfo struct {
	ClusterID string `json:"cluster_id"`
	DecreeKey string `json:"decree_key"` // PEM public key
}

// CDSPinsFlags select pin-decree following for a CDS client. Unset, the
// client keeps its static pins.
type CDSPinsFlags struct {
	File      string
	ClusterID string
	DecreeKey string
	// StateFile keeps the newest decree across restarts (node agents).
	StateFile string
}

// BindCDSPinsFlags adds --cds-pins-file, --cds-cluster-id, --cds-decree-key.
func BindCDSPinsFlags(f *pflag.FlagSet, c *CDSPinsFlags) {
	f.StringVar(&c.File, "cds-pins-file", "", "follow the operator's signed CDS pin decrees: JSON {cluster_id, decree_key} (a node's /run/c8s-node/cds-pins.json); excludes --cds-cluster-id/--cds-decree-key")
	f.StringVar(&c.ClusterID, "cds-cluster-id", "", "follow signed CDS pin decrees of this cluster (with --cds-decree-key)")
	f.StringVar(&c.DecreeKey, "cds-decree-key", "", "PEM public key that signs the cluster's CDS pin decrees")
}

// Info resolves the flags; ok is false when pin following is off.
func (c CDSPinsFlags) Info() (info CDSPinsInfo, ok bool, err error) {
	switch {
	case c.File != "" && (c.ClusterID != "" || c.DecreeKey != ""):
		return info, false, errors.New("--cds-pins-file excludes --cds-cluster-id and --cds-decree-key")
	case c.File != "":
		data, err := os.ReadFile(c.File)
		if errors.Is(err, os.ErrNotExist) {
			return info, false, nil // a cluster without HA CDS publishes none
		}
		if err != nil {
			return info, false, fmt.Errorf("--cds-pins-file: %w", err)
		}
		if err := json.Unmarshal(data, &info); err != nil {
			return info, false, fmt.Errorf("--cds-pins-file: %w", err)
		}
	case c.ClusterID == "" && c.DecreeKey == "":
		return info, false, nil
	case c.ClusterID == "" || c.DecreeKey == "":
		return info, false, errors.New("--cds-cluster-id and --cds-decree-key go together")
	default:
		info = CDSPinsInfo{ClusterID: c.ClusterID, DecreeKey: c.DecreeKey}
	}
	if info.ClusterID == "" || info.DecreeKey == "" {
		return info, false, errors.New("CDS pins info needs cluster_id and decree_key")
	}
	return info, true, nil
}

// Args renders info as flags for an injected container.
func (i CDSPinsInfo) Args() []string {
	return []string{"--cds-cluster-id=" + i.ClusterID, "--cds-decree-key=" + strings.TrimSpace(i.DecreeKey)}
}

// decreeKeyDER accepts PEM or base64 PEM, returns PKIX DER.
func decreeKeyDER(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "-----BEGIN") {
		return nil, errors.New("decree key must be a PEM PUBLIC KEY")
	}
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("decree key must be a PEM PUBLIC KEY")
	}
	return b.Bytes, nil
}

// Source builds the pin source over bootstrap, or nil when following is
// off. cdsURL is where pin decrees are fetched (GET /ha/pins).
func (c CDSPinsFlags) Source(bootstrap refvalues.ReferenceValues, cdsURL string) (*cdspins.Source, error) {
	info, ok, err := c.Info()
	if err != nil || !ok {
		return nil, err
	}
	der, err := decreeKeyDER(info.DecreeKey)
	if err != nil {
		return nil, err
	}
	return cdspins.New(cdspins.Config{ClusterID: info.ClusterID, DecreeKey: der, Bootstrap: bootstrap,
		Fetch: cdspins.HTTPFetch(strings.TrimRight(cdsURL, "/")), StateFile: c.StateFile})
}
