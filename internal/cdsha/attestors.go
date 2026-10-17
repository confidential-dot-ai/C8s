package cdsha

import (
	"fmt"
	"time"
)

// attestors holds the real attestors; devAttestors is filled only by
// c8s_dev builds, so a production binary cannot select the mock.
var (
	attestors    = map[string]func(AttestorOptions) (Attestor, error){}
	devAttestors = map[string]func(AttestorOptions) (Attestor, error){}
)

// AttestorOptions configures the attestor chosen by name.
type AttestorOptions struct {
	MockMeasurement   string        // mock: the measurement to claim
	TDXTCBStatuses    []string      // tdx: accepted Intel TCB statuses (PCS spelling)
	AttestationAPIURL string        // node: the node attestation-api (unix:// socket or http URL)
	Timeout           time.Duration // node: per-call timeout
}

// NewAttestor resolves an attestor by name ("node", "tdx", or "mock" in dev builds).
func NewAttestor(name string, o AttestorOptions) (Attestor, error) {
	if f, ok := attestors[name]; ok {
		return f(o)
	}
	if f, ok := devAttestors[name]; ok {
		return f(o)
	}
	return nil, fmt.Errorf("attestor %q not available in this build (node, tdx; mock needs -tags c8s_dev)", name)
}
