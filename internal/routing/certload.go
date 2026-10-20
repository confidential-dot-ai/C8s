package routing

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// clientCertRecheckInterval is how often the client credential is re-read
// while it is still valid. get-cert rotates at 50% of TTL, so this only needs
// to be small next to the rotation window.
const clientCertRecheckInterval = 30 * time.Second

// ClientCert supplies each backend handshake with a currently valid copy of
// the get-cert-managed mesh credential (B4). Unlike a pair loaded once into
// tls.Config.Certificates, it follows rotation, so the first leaf's expiry
// does not break backend connections until a restart. It is safe for
// concurrent use.
type ClientCert struct {
	certFile string
	keyFile  string

	mu        sync.Mutex
	cached    *tls.Certificate
	recheckAt time.Time
}

// NewClientCert reads the pair once, so an unreadable path or a mismatched key
// fails at startup. It does not enforce the validity window: a process
// restarting while CDS is down must still come up.
func NewClientCert(certFile, keyFile string) (*ClientCert, error) {
	c := &ClientCert{certFile: certFile, keyFile: keyFile}
	cert, err := c.read()
	if err != nil {
		return nil, err
	}
	c.cached = cert
	c.recheckAt = time.Now().Add(clientCertRecheckInterval)
	return c, nil
}

func (c *ClientCert) read() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("client certificate %q has no certificate", c.certFile)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client leaf: %w", err)
	}
	pair.Leaf = leaf
	return &pair, nil
}

// GetClientCertificate implements tls.Config.GetClientCertificate. It re-reads
// the files when the cached credential is due a recheck or outside its window,
// and never hands a handshake a credential outside its validity window.
func (c *ClientCert) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached != nil && now.Before(c.recheckAt) && certutil.CheckValidity(c.cached.Leaf, now) == nil {
		return c.cached, nil
	}
	cert, err := c.read()
	if err == nil {
		err = certutil.CheckValidity(cert.Leaf, now)
	}
	if err != nil {
		// get-cert writes the certificate and the key as separate files, so a
		// rotation can leave them momentarily out of step. Keep the cached
		// credential while it is still inside its own window.
		if c.cached != nil && certutil.CheckValidity(c.cached.Leaf, now) == nil {
			return c.cached, nil
		}
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	c.cached = cert
	c.recheckAt = now.Add(clientCertRecheckInterval)
	return cert, nil
}
