package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSignedLeaf is a leaf a verifier can be handed on the handshake path:
// no TEE evidence, so only the chain half of dual verification can accept it.
func selfSignedLeaf(t *testing.T, usages []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7001),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// An intermediate the peer offers is part of what the verifier chains on, so a
// garbled one must fail the handshake rather than be silently dropped: a peer
// could otherwise hide the CA link a verifier is about to reject.
func TestParsePeerChainRefusesUnparsableIntermediate(t *testing.T) {
	leaf := selfSignedLeaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	intermediate := selfSignedLeaf(t, nil)

	parsedLeaf, pool, err := parsePeerChain([][]byte{leaf.Raw, intermediate.Raw})
	if err != nil {
		t.Fatalf("parsePeerChain with a valid intermediate: %v", err)
	}
	if !parsedLeaf.Equal(leaf) {
		t.Fatal("parsePeerChain returned a leaf other than the one the peer presented")
	}
	if pool == nil {
		t.Fatal("parsePeerChain returned no intermediate pool")
	}

	_, _, err = parsePeerChain([][]byte{leaf.Raw, []byte("not a certificate")})
	if err == nil {
		t.Fatal("parsePeerChain accepted a garbled intermediate")
	}
	if !strings.Contains(err.Error(), "parse peer intermediate") {
		t.Fatalf("error = %v, want it to name the unparsable intermediate", err)
	}
}

// The refusal must name the purpose the peer's role required, since serverAuth
// and clientAuth failures are different misconfigurations.
func TestCheckPeerPurposeNamesTheRequiredPurpose(t *testing.T) {
	for _, tc := range []struct {
		name    string
		usages  []x509.ExtKeyUsage
		want    x509.ExtKeyUsage
		wantErr string
	}{
		{
			name:    "server cert in a client role",
			usages:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			want:    x509.ExtKeyUsageClientAuth,
			wantErr: "clientAuth",
		},
		{
			name:    "client cert in a server role",
			usages:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			want:    x509.ExtKeyUsageServerAuth,
			wantErr: "serverAuth",
		},
		{
			name:    "no purpose at all",
			usages:  nil,
			want:    x509.ExtKeyUsageServerAuth,
			wantErr: "serverAuth",
		},
		{
			name:    "both purposes",
			usages:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			want:    x509.ExtKeyUsageClientAuth,
			wantErr: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPeerPurpose(selfSignedLeaf(t, tc.usages), tc.want)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkPeerPurpose = %v, want accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkPeerPurpose accepted a certificate for the wrong role")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to name %s", err, tc.wantErr)
			}
		})
	}
}

// Dual verification must fail closed on input that never reaches either half:
// an absent peer certificate and one that does not parse.
func TestDualVerifyPeerCallbackRefusesMalformedPeer(t *testing.T) {
	verify := dualVerifyPeerCallback(nil, newSharedCACerts(nil))

	err := verify(nil, nil)
	if err == nil {
		t.Fatal("dual verification accepted a peer that presented nothing")
	}
	if !strings.Contains(err.Error(), "no peer certificate") {
		t.Fatalf("error = %v, want it to name the missing certificate", err)
	}

	err = verify([][]byte{[]byte("not a certificate")}, nil)
	if err == nil {
		t.Fatal("dual verification accepted an unparsable peer certificate")
	}
	if !strings.Contains(err.Error(), "parse peer cert") {
		t.Fatalf("error = %v, want it to name the unparsable certificate", err)
	}
}

// A client that will be handed its CA at runtime starts with an empty pool.
// Until then every peer must be refused: an empty pool is not "trust anyone",
// and with no evidence either the handshake has nothing to accept.
func TestNewClientTLSConfigDynamicCAStartsFailClosed(t *testing.T) {
	tlsCfg, mgr, err := NewClientTLSConfig(&ClientConfig{DynamicCACert: true})
	if err != nil {
		t.Fatalf("NewClientTLSConfig: %v", err)
	}
	if mgr != nil {
		t.Fatal("a client with no certificate source got a CertManager")
	}
	leaf := selfSignedLeaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := tlsCfg.VerifyPeerCertificate([][]byte{leaf.Raw}, nil); err == nil {
		t.Fatal("a client with an empty dynamic CA pool accepted an unattested peer")
	}
}

// The zero client configuration is a verifying client with no certificate of
// its own, not a client that skips verification.
func TestNewClientTLSConfigWithoutConfig(t *testing.T) {
	tlsCfg, mgr, err := NewClientTLSConfig(nil)
	if err != nil {
		t.Fatalf("NewClientTLSConfig(nil): %v", err)
	}
	if mgr != nil {
		t.Fatal("NewClientTLSConfig(nil) returned a CertManager")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsCfg.MinVersion)
	}
	if !tlsCfg.SessionTicketsDisabled {
		t.Fatal("session resumption is enabled on the default client config")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("the default client config verifies no peer")
	}
	if tlsCfg.GetClientCertificate != nil {
		t.Fatal("a client with no certificate source offers a client certificate")
	}
}

// Key-bound evidence is only meaningful for the two curves the verifier
// accepts, so a peer key of any other type is refused before verification.
func TestCheckPeerKeyTypeRefusesNonECDSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7002),
		Subject:      pkix.Name{CommonName: "rsa-peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	err = checkPeerKeyType(cert)
	if err == nil {
		t.Fatal("an RSA peer key was accepted")
	}
	if !strings.Contains(err.Error(), "want ECDSA") {
		t.Fatalf("error = %v, want it to name the accepted key types", err)
	}
}

// Evidence verification without a policy has no attestation-api to verify
// against, so it must refuse rather than fall back to trusting the report.
func TestVerifyAttestationWithoutPolicyRefuses(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &Attestation{
		Family: TEETypeSEVSNP,
		Report: []byte("report"),
	}
	_, err = VerifyAttestation(&key.PublicKey, att, nil, nil)
	if err == nil {
		t.Fatal("verification without a policy succeeded")
	}
	if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("error = %v, want ErrInvalidReport", err)
	}
}
