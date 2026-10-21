package armtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"

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
	t, err := NewRefreshingTransport(src, func(p Pins) (*http.Transport, error) {
		tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{Policy: p.VerifyPolicy(attestationApiURL)})
		if err != nil {
			return nil, fmt.Errorf("armtls client config: %w", err)
		}
		return HTTPClient(tlsCfg).Transport.(*http.Transport), nil
	})
	if err != nil {
		return nil, err
	}
	hc := HTTPClient(nil)
	hc.Transport = t
	return hc, nil
}

// NewRefreshingTransport rebuilds the transport with build whenever src's
// pins change, and retries a failed request once when a refresh changed
// them. build makes the TLS client for one pin set (a client certificate,
// timeouts).
func NewRefreshingTransport(src PinSource, build func(Pins) (*http.Transport, error)) (http.RoundTripper, error) {
	t := &refreshingTransport{src: src, build: func(rv refvalues.ReferenceValues) (*http.Transport, error) { return build(Pins(rv.Policy())) }}
	if _, err := t.transport(); err != nil {
		return nil, err
	}
	return t, nil
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

// RefreshingPeerVerifier is a VerifyPeerCertificate for a server that pins
// its clients (verifyPeerCallback over src): a client that fails the pins
// makes it look for newer ones, and the same handshake is checked again
// against them. Install it on a config from NewServerTLSConfig with a
// ClientPolicy and no CA.
func RefreshingPeerVerifier(src PinSource, attestationApiURL string) func([][]byte, [][]*x509.Certificate) error {
	var (
		mu     sync.Mutex
		gen    uint64
		verify func([][]byte, [][]*x509.Certificate) error
	)
	current := func() func([][]byte, [][]*x509.Certificate) error {
		mu.Lock()
		defer mu.Unlock()
		if g := src.Generation(); verify == nil || g != gen {
			verify, gen = verifyPeerCallback(Pins(src.Current().Policy()).VerifyPolicy(attestationApiURL)), g
		}
		return verify
	}
	return func(raw [][]byte, chains [][]*x509.Certificate) error {
		err := current()(raw, chains)
		if err == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if changed, _ := src.Refresh(ctx); !changed {
			return err
		}
		return current()(raw, chains)
	}
}
