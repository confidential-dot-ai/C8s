package taconn

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
)

// pinFirstPeer makes every connection hc dials present the leaf certificate its
// first connection presented. Attestation verification on each handshake proves
// only an attested build at a pinned measurement, which other Trust Authority instances
// share; without the pin, a redial after the connection the mesh CA was checked
// on drops (idle timeout, reset, Go's transparent retry) could hand the write to
// one of them. A matching leaf proves the same peer, since the handshake proves
// possession of its key.
func pinFirstPeer(hc *http.Client) (*http.Client, error) {
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		return nil, fmt.Errorf("taconn: armTLS client has no TLS transport to pin the peer on")
	}
	var (
		mu     sync.Mutex
		pinned []byte
	)
	// The client has not dialled yet, so setting the hook races nothing.
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("taconn: peer presented no certificate")
		}
		leaf := cs.PeerCertificates[0].Raw
		mu.Lock()
		defer mu.Unlock()
		if pinned == nil {
			pinned = bytes.Clone(leaf)
			return nil
		}
		if !bytes.Equal(pinned, leaf) {
			return fmt.Errorf("taconn: the connection to the Trust Authority was re-established and the peer presented a different serving certificate " +
				"than the one this command already verified; it may not be the same Trust Authority. Nothing was sent to it. Re-run the command")
		}
		return nil
	}
	return hc, nil
}
