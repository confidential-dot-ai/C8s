package cdsha

import (
	"crypto/x509"
	"errors"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// CurrentCore is the direct-state pilot's encrypted identity/control record.
// It deliberately has no log index, log chain, secrets or token table. Only
// authenticated current-state storage may supply it; AEAD alone cannot prove
// freshness. The metadata service must supply a strictly current read.
type CurrentCore struct {
	Format    int            `json:"format"`
	Core      ClusterState   `json:"core"`
	MeshCAKey []byte         `json:"mesh_ca_key,omitempty"`
	Decrees   []DecreeRecord `json:"decrees,omitempty"`
}

func (f *FSM) CurrentCore() (CurrentCore, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	c := CurrentCore{Format: 1, Core: f.core.clone(), Decrees: append([]DecreeRecord(nil), f.decrees...)}
	if f.ca != nil {
		var err error
		c.MeshCAKey, err = x509.MarshalPKCS8PrivateKey(f.ca.Key)
		if err != nil {
			return CurrentCore{}, err
		}
	}
	return c, nil
}

// RestoreCurrentCore is used only on a fresh, private transition machine. It
// cannot overwrite an active FSM or bypass a Raft/WAL replica's installation
// rules. Its stores are restored separately from the same metadata read set.
func (f *FSM) RestoreCurrentCore(c CurrentCore) error {
	if f.AppliedIndex() != 0 || f.core.Joined() {
		return errors.New("cds direct state: transition machine is not fresh")
	}
	ca, err := c.Open(f.launch, f.LocalPolicy())
	if err != nil {
		return err
	}
	f.core, f.ca, f.decrees = c.Core.clone(), ca, append([]DecreeRecord(nil), c.Decrees...)
	return nil
}

func (c CurrentCore) Open(launch Launch, policy Policy) (*issuer.CA, error) {
	if c.Format != 1 || !c.Core.Joined() || c.Core.Version == 0 ||
		c.Core.ClusterID != launch.ClusterID || c.Core.ConfigSHA256 != launch.ConfigSHA256 || c.Core.Format > Format ||
		c.Core.PinsDecree == nil || len(c.Core.Doubts) != 0 || c.Core.Policy != policy {
		return nil, errors.New("cds direct state: invalid, fenced or incompatible current identity")
	}
	if err := cdsdecree.Verify(*c.Core.PinsDecree, launch.OperatorKeys, launch.ClusterID); err != nil {
		return nil, err
	}
	return meshCA(c.Core.MeshCACert, c.MeshCAKey)
}
