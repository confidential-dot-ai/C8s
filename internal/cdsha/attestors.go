package cdsha

import (
	"errors"
	"fmt"
	"time"
)

// devAttestors is filled only by c8s_dev builds, so a production binary
// cannot select the mock.
var devAttestors = map[string]func(AttestorOptions) Attestor{}

// AttestorOptions configures the attestor chosen by name.
type AttestorOptions struct {
	MockMeasurement   string        // mock: the measurement to claim
	AttestationAPIURL string        // node: the node attestation-api (unix:// socket or http URL)
	Timeout           time.Duration // node: per-call timeout
}

// NewAttestor resolves an attestor by name ("node", or "mock" in dev builds).
func NewAttestor(name string, o AttestorOptions) (Attestor, error) {
	if name == "node" {
		if o.AttestationAPIURL == "" {
			return nil, errors.New("node attestor needs the attestation-api URL")
		}
		return NewNodeAttestor(o.AttestationAPIURL, o.Timeout), nil
	}
	if f, ok := devAttestors[name]; ok {
		return f(o), nil
	}
	return nil, fmt.Errorf("attestor %q not available in this build (node; mock needs -tags c8s_dev)", name)
}
