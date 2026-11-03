package metadatapilot

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
)

// Transport trusts a pilot-specific CA from the measured launch configuration.
// Empty preserves ordinary system trust. It never disables hostname validation
// or changes the trust used for object storage, peers or other clients.
func Transport(rootPEM string) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if rootPEM == "" {
		return transport, nil
	}
	if len(rootPEM) > 8192 {
		return nil, errors.New("metadata root CA exceeds its size bound")
	}
	block, rest := pem.Decode([]byte(rootPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("metadata root CA must be one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("metadata root CA must authorize certificate signing")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	return transport, nil
}
