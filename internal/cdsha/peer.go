// Package cdsha is the replicated half of CDS: the replicas of one cluster
// admit each other by what they run, and reach each other over one attested
// port.
//
// A peer is vouched for by no certificate authority. It presents an ephemeral
// self-signed certificate whose TEE evidence binds the cluster it serves, the
// member id the process minted at its start, the key the certificate speaks
// for and the second it expires. The replica it reaches authenticates the
// certificate body, has the loopback attestation-api verify the evidence, and
// holds the launch identity that verdict reports against the images it
// admits.
package cdsha

import (
	"crypto"
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
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// The peer certificate's extensions, from the c8s OID arc pkg/armtls records.
// Peer evidence binds more than the key, so it has an extension of its own.
var (
	oidPeerEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 6}
	oidPeerMember   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 7}
)

// peerContextDomain separates the peer binding from every other report data a
// c8s component attests.
const peerContextDomain = "c8s-cds-ha-peer-v1"

const peerCommonName = "c8s-cds-ha-peer"

// maxMemberID is what the Raft target frame carries: one length byte.
const maxMemberID = 255

// peer is an attested replica: the member id its certificate names, and the
// verdict it was admitted on, which a later admission set judges again.
type peer struct {
	member  string
	verdict verdict
}

// peerContext is what a replica's evidence binds besides its certificate key:
// the cluster, the member and the expiry, each length-prefixed so no two sets
// of fields read alike.
func peerContext(clusterID, member string, notAfter time.Time) []byte {
	context := appendBoundField(nil, []byte(peerContextDomain))
	context = appendBoundField(context, []byte(clusterID))
	context = appendBoundField(context, []byte(member))
	return appendBoundField(context, binary.BigEndian.AppendUint64(nil, uint64(notAfter.Unix())))
}

func appendBoundField(to, field []byte) []byte {
	to = binary.BigEndian.AppendUint64(to, uint64(len(field)))
	return append(to, field...)
}

// peerReportData binds pub ahead of context, the key as self-delimiting PKIX
// DER, and is the 48-byte REPORTDATA anchor every attestation path here
// sends.
func peerReportData(pub crypto.PublicKey, context []byte) ([48]byte, error) {
	reportData, err := armtls.ReportDataForKey(pub, context)
	if err != nil {
		return [48]byte{}, err
	}
	return [48]byte(reportData[:sha512.Size384]), nil
}

// peerIdentity is what a process shows its peers for one certificate
// lifetime, and the pin it admits replicas of its own image by.
type peerIdentity struct {
	certificate tls.Certificate
	self        remote.ImagePin
	// attested is the verdict an image set judges this replica by, as a peer.
	attested verdict
}

// newPeerIdentity mints a peer certificate for member. The one verdict on the
// evidence it carries is both the proof the certificate rests on and this
// replica's own launch identity, so a replica it refuses never serves.
func newPeerIdentity(
	a attestor,
	clusterID, member string,
	launchFile []byte,
	notAfter time.Time,
) (peerIdentity, error) {
	if err := checkMemberID(member); err != nil {
		return peerIdentity{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return peerIdentity{}, err
	}
	binding, err := peerReportData(&key.PublicKey, peerContext(clusterID, member, notAfter))
	if err != nil {
		return peerIdentity{}, err
	}
	evidence, err := a.attest(binding)
	if err != nil {
		return peerIdentity{}, err
	}
	own, err := a.ownVerdict(evidence, binding)
	if err != nil {
		return peerIdentity{}, fmt.Errorf("this replica's own evidence: %w", err)
	}
	self, err := own.imagePin(launchFile)
	if err != nil {
		return peerIdentity{}, err
	}
	certificate, err := newPeerCertificate(key, member, evidence, notAfter)
	if err != nil {
		return peerIdentity{}, err
	}
	return peerIdentity{certificate: certificate, self: self, attested: own}, nil
}

// newPeerCertificate self-signs the key and the expiry the evidence binds,
// and the member id that key therefore signs.
func newPeerCertificate(
	key *ecdsa.PrivateKey,
	member string,
	evidence *agarmtls.Attestation,
	notAfter time.Time,
) (tls.Certificate, error) {
	evidenceExtension, err := evidence.MarshalExtension(oidPeerEvidence)
	if err != nil {
		return tls.Certificate{}, err
	}
	memberExtension, err := newMemberExtension(member)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: peerCommonName},
		NotBefore:    time.Now(),
		NotAfter:     notAfter,
		ExtraExtensions: []pkix.Extension{
			evidenceExtension,
			memberExtension,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func newMemberExtension(member string) (pkix.Extension, error) {
	value, err := asn1.MarshalWithParams(member, memberIDEncoding)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("member id %q: %w", member, err)
	}
	return pkix.Extension{Id: oidPeerMember, Value: value}, nil
}

// memberIDEncoding carries a member id whatever bytes it is made of; ASN.1
// defaults to the PrintableString charset.
const memberIDEncoding = "utf8"

// certMember is the member id a certificate names; x509 parsing refuses a
// certificate that carries the extension twice.
func certMember(cert *x509.Certificate) (string, error) {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(oidPeerMember) {
			continue
		}
		var member string
		rest, err := asn1.UnmarshalWithParams(extension.Value, &member, memberIDEncoding)
		if err != nil {
			return "", fmt.Errorf("peer certificate member id: %w", err)
		}
		if len(rest) > 0 {
			return "", fmt.Errorf("peer certificate member id carries %d trailing bytes", len(rest))
		}
		if err := checkMemberID(member); err != nil {
			return "", err
		}
		return member, nil
	}
	return "", errors.New("peer certificate names no member")
}

// checkMemberID bounds a member id by the frame that carries it.
func checkMemberID(member string) error {
	if member == "" || len(member) > maxMemberID {
		return fmt.Errorf("member id is %d bytes, want 1 to %d", len(member), maxMemberID)
	}
	return nil
}

// admissionSet reports the images a replica admits: its own pin until it
// joins a cluster, and the cluster's pin set once it has. It is read on every
// handshake and while the transport holds its lock, so it is safe to call
// from several goroutines and makes no network call.
type admissionSet func() []remote.ImagePin

// peerVerifier admits the peers of one cluster against the images it holds
// them to.
type peerVerifier struct {
	clusterID string
	attestor  attestor
	admits    admissionSet
}

// errPeerIdentity marks a handshake refused for the peer's certificate.
var errPeerIdentity = errors.New("peer identity")

// admit authenticates one peer certificate, which armtls walks: the body
// under its own key, the evidence bound to the key and this cluster's
// context, and the launch identity the verdict reports against the pins.
func (v peerVerifier) admit(der []byte) (peer, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return peer{}, err
	}
	member, err := certMember(cert)
	if err != nil {
		return peer{}, err
	}
	result, err := armtls.VerifyCert(
		cert,
		v.policy(),
		peerContext(v.clusterID, member, cert.NotAfter),
	)
	if err != nil {
		return peer{}, err
	}
	judgement, err := newVerdict(result.Verified)
	if err != nil {
		return peer{}, err
	}
	return peer{member: member, verdict: judgement}, nil
}

// policy holds a peer to the images this replica admits, under the evidence
// extension a peer certificate carries.
func (v peerVerifier) policy() *armtls.VerifyPolicy {
	policy := armtls.Pins(remote.Policy{Images: v.admits()}).VerifyPolicy(v.attestor.serviceURL)
	policy.ExtensionOID = oidPeerEvidence
	policy.AttestationVerifyTimeout = v.attestor.timeout
	return policy
}

// peerHandshake is one connection's admission: config fails the handshake
// unless the peer's certificate is admitted, and admitted is that peer once
// the handshake has returned.
type peerHandshake struct {
	config   *tls.Config
	admitted peer
}

// handshake is how an attested connection is made in either direction: one
// peerHandshake per connection, since the admission it records is that
// connection's peer.
func (v peerVerifier) handshake(cfg *tls.Config) *peerHandshake {
	handshake := &peerHandshake{config: cfg.Clone()}
	handshake.config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("%w: no peer certificate", errPeerIdentity)
		}
		admitted, err := v.admit(state.PeerCertificates[0].Raw)
		if err != nil {
			return fmt.Errorf("%w: %w", errPeerIdentity, err)
		}
		handshake.admitted = admitted
		return nil
	}
	return handshake
}
