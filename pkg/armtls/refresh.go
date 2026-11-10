package armtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// PinSource is a peer pin set that changes while a process runs, so a client
// built once holds its peer to the set in force. A handshake reads it, so
// every implementation answers from any goroutine.
type PinSource interface {
	// Generation changes with the set.
	Current() refvalues.ReferenceValues
	Generation() uint64
	// Refresh looks for a newer set, and fails where it could not look.
	Refresh() error
}

// The source of a set no command replaces.
func FixedPins(images refvalues.ReferenceValues) PinSource {
	return fixedPins{images: images}
}

type fixedPins struct {
	images refvalues.ReferenceValues
}

func (f fixedPins) Current() refvalues.ReferenceValues {
	return f.images
}

func (f fixedPins) Generation() uint64 {
	return 0
}

func (f fixedPins) Refresh() error {
	return nil
}

// FollowServerPins holds the server of an armTLS client config to the set src
// holds at each handshake: a server outside the set makes the client look for
// a newer one, and the same handshake is then checked against that one.
// It replaces the entire peer VerifyPolicy installed by [NewClientTLSConfig];
// constructor options are not inherited. Pass true here to require
// non-migratable peers on every attempt, even if the constructor required it.
// Omitting the option leaves migration unchecked.
func FollowServerPins(
	tlsCfg *tls.Config,
	src PinSource,
	attestationApiURL string,
	requireNonMigratable ...bool,
) {
	tlsCfg.VerifyPeerCertificate = followPins(
		src,
		attestationApiURL,
		x509.ExtKeyUsageServerAuth,
		slices.Contains(
			requireNonMigratable,
			true,
		),
		nil,
	)
}

// FollowClientPins is FollowServerPins for a server pinning its callers: a
// client on a newly accepted image is admitted once the set has moved to it.
// Takes a config from [NewServerTLSConfig] with a ClientPolicy and no CA,
// replacing that entire policy. Constructor options are not inherited: pass
// true here to require non-migratable peers on every attempt. Omitting the
// option leaves migration unchecked, even if the constructor required it.
func FollowClientPins(
	tlsCfg *tls.Config,
	src PinSource,
	attestationApiURL string,
	requireNonMigratable ...bool,
) {
	tlsCfg.VerifyPeerCertificate = followPins(
		src,
		attestationApiURL,
		x509.ExtKeyUsageClientAuth,
		slices.Contains(
			requireNonMigratable,
			true,
		),
		nil,
	)
}

// FollowNativeServerPins preserves native verification across pin refreshes.
func FollowNativeServerPins(
	tlsCfg *tls.Config,
	src PinSource,
	native *NativeVerifier,
) {
	tlsCfg.VerifyPeerCertificate = followPins(src, "", x509.ExtKeyUsageServerAuth, true, native)
}

// FollowNativeClientPins is the native inventory listener's peer policy.
func FollowNativeClientPins(
	tlsCfg *tls.Config,
	src PinSource,
	native *NativeVerifier,
) {
	tlsCfg.VerifyPeerCertificate = followPins(src, "", x509.ExtKeyUsageClientAuth, true, native)
}

// followPins is the peer check of the set src holds now, retried against a
// newer set where the check failed and the set moved.
func followPins(
	src PinSource,
	attestationApiURL string,
	purpose x509.ExtKeyUsage,
	requireNonMigratable bool,
	native *NativeVerifier,
) func(
	[][]byte,
	[][]*x509.Certificate,
) error {
	verify := func(
		raw [][]byte,
		chains [][]*x509.Certificate,
	) error {
		policy := Pins(src.Current().Policy()).VerifyPolicy(attestationApiURL)
		policy.RequireNonMigratable = requireNonMigratable
		policy.Native = native
		return verifyPeerCallback(
			policy,
			purpose,
		)(raw, chains)
	}
	return func(
		raw [][]byte,
		chains [][]*x509.Certificate,
	) error {
		checked := src.Generation()
		err := verify(raw, chains)
		if err == nil {
			return nil
		}
		if refreshErr := src.Refresh(); refreshErr != nil || src.Generation() == checked {
			return err
		}
		return verify(raw, chains)
	}
}

// NewRefreshingHTTPClient is [NewVerifyingHTTPClient] over a pin source: a
// request that fails asks the source for a newer set and runs once more
// against it.
func NewRefreshingHTTPClient(src PinSource, attestationApiURL string) (*http.Client, error) {
	if attestationApiURL == "" {
		return nil, fmt.Errorf("armtls client config: attestation-api URL is required")
	}
	transport, err := NewRefreshingTransport(src, func(pins Pins) (*http.Transport, error) {
		return ClientTransport(pins, attestationApiURL)
	})
	if err != nil {
		return nil, err
	}
	client := HTTPClient(nil)
	client.Transport = transport
	return client, nil
}

// NewRefreshingTransport is the transport of the set src holds, rebuilt by
// build whenever the set changes. A failed request asks the source for a
// newer set and, where the set moved, runs once more against it. A request
// whose body cannot be replayed runs once.
func NewRefreshingTransport(src PinSource, build func(Pins) (*http.Transport, error)) (http.RoundTripper, error) {
	t := &refreshingTransport{
		src:   src,
		build: build,
	}
	if _, _, err := t.transport(); err != nil {
		return nil, err
	}
	return t, nil
}

// ClientTransport is [HTTPClient]'s transport holding its peer to pins.
func ClientTransport(pins Pins, attestationApiURL string) (*http.Transport, error) {
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{
		Policy: pins.VerifyPolicy(attestationApiURL),
	})
	if err != nil {
		return nil, fmt.Errorf("armtls client config: %w", err)
	}
	return standardTransport(tlsCfg)
}

// NativeClientTransport retains one verifier and its admission bound for every
// connection in this transport. Its policy never consults a remote verdict.
func NativeClientTransport(
	pins Pins,
	native *NativeVerifier,
) (*http.Transport, error) {
	if native == nil {
		return nil, fmt.Errorf("armtls client config: native verifier required")
	}
	policy := pins.VerifyPolicy("")
	policy.Native = native
	policy.RequireNonMigratable = true
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{Policy: policy})
	if err != nil {
		return nil, fmt.Errorf("armtls client config: %w", err)
	}
	return standardTransport(tlsCfg)
}

// standardTransport is [HTTPClient]'s transport over tlsCfg.
func standardTransport(tlsCfg *tls.Config) (*http.Transport, error) {
	transport, ok := HTTPClient(tlsCfg).Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("armtls client config: the standard client carries a %T", HTTPClient(tlsCfg).Transport)
	}
	return transport, nil
}

type refreshingTransport struct {
	src   PinSource
	build func(Pins) (*http.Transport, error)

	mu         sync.Mutex
	generation uint64
	current    *http.Transport
}

// transport closes the idle connections of a replaced set: one made under
// retired pins must not carry another request.
func (t *refreshingTransport) transport() (*http.Transport, uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	generation := t.src.Generation()
	if t.current != nil && generation == t.generation {
		return t.current, generation, nil
	}
	built, err := t.build(Pins(t.src.Current().Policy()))
	if err != nil {
		return nil, 0, err
	}
	if t.current != nil {
		t.current.CloseIdleConnections()
	}
	t.current = built
	t.generation = generation
	return built, generation, nil
}

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, generation, err := t.transport()
	if err != nil {
		return nil, err
	}
	resp, err := transport.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	if !t.pinsMovedSince(generation) || !replayable(req) {
		return nil, err
	}
	return t.runAgain(req)
}

// pinsMovedSince asks the source for a newer set first. A source that could
// not look reports no move, so a refused peer stays refused.
func (t *refreshingTransport) pinsMovedSince(generation uint64) bool {
	_ = t.src.Refresh()
	return t.src.Generation() != generation
}

func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func (t *refreshingTransport) runAgain(req *http.Request) (*http.Response, error) {
	again := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		again.Body = body
	}
	transport, _, err := t.transport()
	if err != nil {
		return nil, err
	}
	return transport.RoundTrip(again)
}
