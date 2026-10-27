package cdsha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// OIDPeerEvidence carries a replica's attestation evidence in its peer TLS
// certificate. PROTOTYPE: not allocated in the c8s OID arc.
var OIDPeerEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 90}

const peerBindingDomain = "c8s-cds-ha-peer-v2\n"

// Claims are the verified contents of a peer's evidence.
type Claims struct {
	Measurement string   // the image: what the pin set lists
	Anchor      string   // the launch-key binding (TDX RTMR3, SNP HOST_DATA); "" if the platform has none
	ReportData  [48]byte // binds cluster_id, the TLS key and its NotAfter (SHA-384, the armTLS REPORT_DATA size)
}

// Attestor produces and verifies TEE evidence. Verify MUST check the
// hardware signature before returning any claim.
type Attestor interface {
	Evidence(reportData [48]byte) ([]byte, error)
	Verify(evidence []byte) (Claims, error)
}

// PeerBinding is the report data a replica must attest: it binds the TLS key,
// the certificate's NotAfter and the cluster_id (CI1). A peer in another
// cluster produces a different value, so CI2 holds whatever its measurement.
// Binding NotAfter makes the expiry attested: whoever holds a leaked key
// cannot re-sign its certificate with a later date. 48 bytes: the SNP
// REPORT_DATA size, which the attestation-api path sends as is; TDX
// zero-pads to 64.
func PeerBinding(clusterID string, spki []byte, notAfter time.Time) [48]byte {
	h := sha512.New384()
	h.Write([]byte(peerBindingDomain))
	h.Write([]byte(clusterID))
	h.Write([]byte{0})
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(notAfter.Unix())))
	h.Write(spki)
	var out [48]byte
	copy(out[:], h.Sum(nil))
	return out
}

// newPeerCert makes the replica's ephemeral self-signed peer certificate with
// its evidence embedded. x509 keeps whole seconds, so notAfter is truncated
// to them before it is bound.
func newPeerCert(clusterID string, att Attestor, notAfter time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	notAfter = notAfter.Truncate(time.Second)
	ev, err := att.Evidence(PeerBinding(clusterID, spki, notAfter))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("peer evidence: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "c8s-cds-ha-peer"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        notAfter,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: OIDPeerEvidence, Value: ev}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, err
}

// peerVerifier checks a peer certificate: evidence verifies, binds this
// cluster and the certificate key, carries our launch-key anchor, and the
// measurement is in the current pin set (L2). Before a replica joins, that
// set is its launch document's images (Node.peerPins): a replica on a new
// node image joins from replicas on the old one when its launch document
// lists the old image among its peer images.
type peerVerifier struct {
	clusterID string
	att       Attestor
	pins      func() []string // empty admits nobody
	anchor    string          // our own Anchor; a peer's must be equal (same role launch key)
}

func (v peerVerifier) claims(der []byte) (Claims, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Claims{}, err
	}
	var ev []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(OIDPeerEvidence) {
			ev = e.Value
		}
	}
	if ev == nil {
		return Claims{}, errors.New("peer certificate has no evidence")
	}
	// A replica renews its certificate every few hours: an expired one is
	// an old key, perhaps a leaked one. NotAfter is bound into the evidence
	// (PeerBinding). NotBefore is not checked: a peer clock a little ahead
	// would refuse fresh certificates.
	if time.Now().After(cert.NotAfter) {
		return Claims{}, fmt.Errorf("peer certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	c, err := v.att.Verify(ev)
	if err != nil {
		return Claims{}, fmt.Errorf("peer evidence: %w", err)
	}
	if c.ReportData != PeerBinding(v.clusterID, cert.RawSubjectPublicKeyInfo, cert.NotAfter) {
		return Claims{}, errors.New("peer evidence not bound to this cluster, TLS key and expiry")
	}
	if !slices.Contains(v.pins(), c.Measurement) {
		return Claims{}, fmt.Errorf("peer measurement %q not in the replica pin set", c.Measurement)
	}
	if c.Anchor != v.anchor {
		// Same image, other launch key: a workload node, or another
		// cluster's CDS. Never a replica of ours (review F2).
		return Claims{}, errors.New("peer launch-key binding differs from ours")
	}
	return c, nil
}

// errPeerIdentity marks a handshake refused because the peer's certificate
// failed claims.
var errPeerIdentity = errors.New("peer identity")

// tlsConfig returns a copy of cfg for one connection whose handshake fails
// unless the peer's certificate passes claims; *verified holds the peer's
// claims once the handshake succeeded. Peer certificates are self-signed by
// design: attestation, not PKI, authenticates a peer. *v is read when the
// peer is verified, during the handshake.
// INVARIANT: every attested connection is made with a config from here.
func (v *peerVerifier) tlsConfig(cfg *tls.Config) (_ *tls.Config, verified *Claims) {
	c := cfg.Clone()
	verified = new(Claims)
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: no peer certificate", errPeerIdentity)
		}
		claims, err := v.claims(cs.PeerCertificates[0].Raw)
		if err != nil {
			return fmt.Errorf("%w: %w", errPeerIdentity, err)
		}
		*verified = claims
		return nil
	}
	return c, verified
}
