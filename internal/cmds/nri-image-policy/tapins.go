package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/fileutil"
)

// renderedTAPinsName is the policy document the plugin hands its injected
// credential clients (renderNodeDocument).
const renderedTAPinsName = "cds-pins.json"

// EnforcerRuntimeDir is the plugin's own directory on the node, holding the
// documents it hands its injected credential clients: no pod can write it, and
// it sits outside the inventory socket directory the plugin bind-mounts, so
// each document reaches a pod at the one compiled path its client reads. The
// uninstall host sweep removes this path.
const EnforcerRuntimeDir = "/run/c8s-enforcer"

// enforcerRuntimeDir is where this process renders those documents. Tests
// override it to render in a temporary directory.
var enforcerRuntimeDir = EnforcerRuntimeDir

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

// prepareTAPins writes the Trust Authority attestation policy this node hands its
// injected credential clients, before any container can be created. Whichever
// form the node's config names its Trust Authority identities in, they reach every client
// as one rendered document, and a set no client could load fails here instead
// of in every pod.
func (p *plugin) prepareTAPins() error {
	if !p.cfg.injectsCredentialClients() {
		// This boot supplies no node credential clients.
		return nil
	}
	set, err := p.cfg.Allowlist.Pull.policySet()
	if err != nil {
		return err
	}
	document, err := refvalues.Format(set)
	if err != nil {
		return fmt.Errorf("render the node's Trust Authority pins: %w", err)
	}
	path, err := rewriteNodeDocument(renderedTAPinsName, document)
	if err != nil {
		return err
	}
	p.taPins = path
	return nil
}

// rewriteNodeDocument is renderNodeDocument for a document pods read on every
// handshake: one already rendered is rewritten in place, so the pods started
// before a plugin restart, which bind-mount its inode, read the new contents
// and the chain's later in-place updates too.
func rewriteNodeDocument(name string, document []byte) (string, error) {
	if err := os.MkdirAll(enforcerRuntimeDir, 0o700); err != nil {
		return "", fmt.Errorf("the plugin's runtime directory: %w", err)
	}
	path := filepath.Join(enforcerRuntimeDir, name)
	if err := writeInPlace(path, document, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	return path, nil
}
