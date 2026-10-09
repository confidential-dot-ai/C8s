package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// renderedCDSPinsName is the policy document the plugin hands its injected
// credential clients (renderNodeDocument).
const renderedCDSPinsName = "cds-pins.json"

// enforcerRuntimeDir is the plugin's own directory on the node, holding the
// documents it hands its injected credential clients: no pod can write it, and
// it sits outside the inventory socket directory the plugin bind-mounts, so
// each document reaches a pod at the one compiled path its client reads. Tests
// override it to render in a temporary directory.
var enforcerRuntimeDir = "/run/c8s-enforcer"

// renderNodeDocument writes one document of that directory and returns the
// path the plugin bind-mounts from.
func renderNodeDocument(name string, document []byte) (string, error) {
	if err := os.MkdirAll(enforcerRuntimeDir, 0o700); err != nil {
		return "", fmt.Errorf("the plugin's runtime directory: %w", err)
	}
	path := filepath.Join(enforcerRuntimeDir, name)
	if err := fileutil.WriteAtomic(path, document, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	return path, nil
}

// prepareCDSPins writes the CDS attestation policy this node hands its
// injected credential clients, before any container can be created. Whichever
// form the node's config names its CDS identities in, they reach every client
// as one rendered document, and a set no client could load fails here instead
// of in every pod.
func (p *plugin) prepareCDSPins() error {
	if !p.cfg.injectsCredentialClients() {
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
	path, err := renderNodeDocument(renderedCDSPinsName, document)
	if err != nil {
		return err
	}
	p.cdsPins = path
	return nil
}
