package armtls

import (
	"crypto/tls"
	"crypto/x509"

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
// Takes a config from [NewClientTLSConfig], whose own peer check it replaces.
func FollowServerPins(tlsCfg *tls.Config, src PinSource, attestationApiURL string) {
	tlsCfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		checked := src.Generation()
		err := verifyServer(src, attestationApiURL)(raw, chains)
		if err == nil {
			return nil
		}
		if refreshErr := src.Refresh(); refreshErr != nil || src.Generation() == checked {
			return err
		}
		return verifyServer(src, attestationApiURL)(raw, chains)
	}
}

func verifyServer(src PinSource, attestationApiURL string) func([][]byte, [][]*x509.Certificate) error {
	return verifyPeerCallback(Pins(src.Current().Policy()).VerifyPolicy(attestationApiURL), x509.ExtKeyUsageServerAuth)
}
