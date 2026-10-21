package armtls

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// PinSource is a peer pin set that can change while a client runs: CDS
// pins follow the operator's signed pin decrees during an image rollout
// (internal/cdspins).
type PinSource interface {
	// Current is the set to verify against now; Generation changes with it.
	Current() refvalues.ReferenceValues
	Generation() uint64
	// Refresh looks for a newer set and reports whether Current changed.
	Refresh(ctx context.Context) (bool, error)
}

// NewRefreshingHTTPClient is NewVerifyingHTTPClient over a PinSource. A
// request that fails asks the source for a newer set; if it changed, the
// request is retried once against it. A request whose body cannot be
// replayed is not retried, and nothing is retried when the set did not
// change, so a peer that fails the pins still fails.
func NewRefreshingHTTPClient(src PinSource, attestationApiURL string) (*http.Client, error) {
	if attestationApiURL == "" {
		return nil, fmt.Errorf("armtls client config: attestation-api URL is required")
	}
	t := &refreshingTransport{src: src, build: func(rv refvalues.ReferenceValues) (*http.Transport, error) {
		tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{Policy: Pins(rv.Policy()).VerifyPolicy(attestationApiURL)})
		if err != nil {
			return nil, fmt.Errorf("armtls client config: %w", err)
		}
		return HTTPClient(tlsCfg).Transport.(*http.Transport), nil
	}}
	if _, err := t.transport(); err != nil {
		return nil, err
	}
	hc := HTTPClient(nil)
	hc.Transport = t
	return hc, nil
}

type refreshingTransport struct {
	src   PinSource
	build func(refvalues.ReferenceValues) (*http.Transport, error)

	mu  sync.Mutex
	gen uint64
	cur *http.Transport
}

// transport is the TLS transport for the source's current set.
func (t *refreshingTransport) transport() (*http.Transport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	gen := t.src.Generation()
	if t.cur != nil && gen == t.gen {
		return t.cur, nil
	}
	base, err := t.build(t.src.Current())
	if err != nil {
		return nil, err
	}
	if t.cur != nil {
		t.cur.CloseIdleConnections()
	}
	t.cur, t.gen = base, gen
	return base, nil
}

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr, err := t.transport()
	if err != nil {
		return nil, err
	}
	resp, err := tr.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	changed, _ := t.src.Refresh(req.Context())
	if !changed || (req.Body != nil && req.Body != http.NoBody && req.GetBody == nil) {
		return nil, err
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		if retry.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	if tr, err = t.transport(); err != nil {
		return nil, err
	}
	return tr.RoundTrip(retry)
}
