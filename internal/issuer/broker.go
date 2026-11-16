package issuer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// BrokerCommonName names every CDS broker certificate.
const BrokerCommonName = "c8s CDS broker"

// SignBroker issues the certificate of this CDS replica's broker key. Its one
// extended key usage is armtls.OIDCDSBroker, so it signs release statements
// and authenticates no TLS peer.
func (c *CA) SignBroker(pub *ecdsa.PublicKey, ttl time.Duration) ([]byte, error) {
	if c == nil || c.Cert == nil || c.Key == nil {
		return nil, fmt.Errorf("sign broker certificate: CA bundle not loaded")
	}
	template, err := certutil.NewLeafTemplate(BrokerCommonName, ttl)
	if err != nil {
		return nil, err
	}
	template.ExtKeyUsage = nil
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{armtls.OIDCDSBroker}
	der, err := x509.CreateCertificate(rand.Reader, template, c.Cert, pub, c.Key)
	if err != nil {
		return nil, fmt.Errorf("sign broker certificate: %w", err)
	}
	return der, nil
}
