package nriimagepolicy

import (
	"fmt"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// renderedCDSPinsName is where the plugin keeps the policy document it hands
// its injected credential clients. It sits in the plugin's own runtime
// directory, which no pod can write.
const renderedCDSPinsName = "cds-pins.json"

// prepareCDSPins writes the CDS attestation policy this node hands its
// injected credential clients, before any container can be created. Whichever
// form the node's config names its CDS identities in, they reach every client
// as one rendered document, and a set no client could load fails here instead
// of in every pod.
func (p *plugin) prepareCDSPins() error {
	if p.cfg.WorkloadClaims.SocketDir == "" {
		// No inventory directory, so no pod of this node is injected and
		// nothing would read a policy.
		return nil
	}
	set, err := p.cfg.Allowlist.Pull.policySet(p.cfg.NormalizedPlatform())
	if err != nil {
		return err
	}
	if set.Empty() {
		// The node pins nothing, which leaves its clients to report
		// themselves unpinned.
		return nil
	}
	document, err := refvalues.Format(set)
	if err != nil {
		return fmt.Errorf("render the node's CDS pins: %w", err)
	}
	path := filepath.Join(p.cfg.WorkloadClaims.SocketDir, renderedCDSPinsName)
	if err := fileutil.WriteAtomic(path, document, 0o644); err != nil {
		return fmt.Errorf("write the rendered CDS pins: %w", err)
	}
	p.cdsPins = path
	return nil
}
