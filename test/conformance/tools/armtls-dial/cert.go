package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// certOptions shapes a minted certificate. notBefore and notAfter are offsets
// from now; issuerDiffers makes the certificate not self-issued.
type certOptions struct {
	attestationURL string
	platform       string
	notBefore      time.Duration
	notAfter       time.Duration
	issuerDiffers  bool
	timeout        time.Duration
}

// selfSignedCert mints a P-256 key, binds it to TEE evidence from the
// attestation API the way the mesh does (armtls.SelfSignedProvider with
// attestclient.MakeSNPARMTLSAttestFunc, which is platform-agnostic) and
// wraps the evidence in a certificate shaped by o.
func selfSignedCert(ctx context.Context, o certOptions) (tls.Certificate, error) {
	family, err := teetypes.ParseFamily(o.platform)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, reportData, err := armtls.GenerateKeyPair()
	if err != nil {
		return tls.Certificate{}, err
	}
	client, url := attestClient(o.attestationURL, o.timeout)
	evidence, err := attestclient.MakeSNPARMTLSAttestFunc(client, url)(ctx, hex.EncodeToString(reportData[:]))
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := buildCert(key, &armtls.Attestation{Family: family, Report: []byte(evidence)}, o)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse minted certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// attestClient returns the attestation client and the URL to hand it. A
// unix:// URL becomes a transport that dials the socket for every request.
func attestClient(url string, timeout time.Duration) (attestclient.Client, string) {
	hc := &http.Client{Timeout: timeout}
	if socket, ok := strings.CutPrefix(url, "unix://"); ok {
		hc.Transport = &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socket)
			},
		}
		url = "http://unix"
	}
	return attestclient.NewClientWithHTTP("", hc), url
}

// buildCert is armtls.CreateAttestedCert with the validity window and the
// issuer under the caller's control: the same extension, key usages and
// subject, but NotBefore/NotAfter from o and, with issuerDiffers, a parent
// whose subject differs and whose key is unrelated, so the result is not
// self-issued yet still carries the evidence extension.
func buildCert(key *ecdsa.PrivateKey, att *armtls.Attestation, o certOptions) ([]byte, error) {
	ext, err := armtls.MarshalExtension(att)
	if err != nil {
		return nil, err
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "armTLS Workload", Organization: []string{"Confidential"}},
		NotBefore:             now.Add(o.notBefore),
		NotAfter:              now.Add(o.notAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	parent, signer := template, crypto.Signer(key)
	if o.issuerDiffers {
		unrelated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate issuer key: %w", err)
		}
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: "armtls-dial unrelated issuer"}}
		signer = unrelated
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return der, nil
}

// rewriteNotAfter returns a copy of der whose TBSCertificate carries notAfter
// in place of the original, keeping the signatureAlgorithm and signature, so
// the body no longer verifies under any key. The new time must take the
// original's encoding (UTCTime for 1950-2049, GeneralizedTime otherwise) so
// no length changes; a time outside the original's range is refused rather
// than re-encoded.
func rewriteNotAfter(der []byte, notAfter time.Time) ([]byte, error) {
	out := append([]byte(nil), der...)
	var tbs, validity, elem cryptobyte.String
	var tag cryptobyte_asn1.Tag
	s := cryptobyte.String(out)
	if !s.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) ||
		!s.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.SkipASN1(cryptobyte_asn1.INTEGER) || // serialNumber
		!tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) || // signature
		!tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) || // issuer
		!tbs.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) ||
		!validity.ReadAnyASN1Element(&elem, &tag) || // notBefore
		!validity.ReadAnyASN1Element(&elem, &tag) { // notAfter, a subslice of out
		return nil, errors.New("malformed certificate DER")
	}
	var encoded string
	switch tag {
	case cryptobyte_asn1.UTCTime:
		if y := notAfter.UTC().Year(); y < 1950 || y >= 2050 {
			return nil, fmt.Errorf("%s does not fit the certificate's UTCTime NotAfter", notAfter.UTC().Format(time.RFC3339))
		}
		encoded = notAfter.UTC().Format("060102150405Z")
	case cryptobyte_asn1.GeneralizedTime:
		encoded = notAfter.UTC().Format("20060102150405Z")
	default:
		return nil, fmt.Errorf("NotAfter has tag %v, not a time", tag)
	}
	// elem is tag, one-byte length, content: both time encodings are short.
	if len(elem) != 2+len(encoded) {
		return nil, fmt.Errorf("NotAfter encoding is %d bytes, cannot hold %d", len(elem)-2, len(encoded))
	}
	copy(elem[2:], encoded)
	return out, nil
}
