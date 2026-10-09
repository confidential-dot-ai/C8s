package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// A client carries a verification policy or it is not configured at all: the
// client verifies the server's evidence on every handshake, so neither the
// absent nor the zero configuration yields a usable one.
func TestNewClientTLSConfigWithoutPolicy(t *testing.T) {
	for _, cfg := range []*ClientConfig{nil, {}} {
		tlsCfg, mgr, err := NewClientTLSConfig(cfg)
		if err == nil {
			t.Fatal("a client with no verification policy was accepted")
		}
		if !strings.Contains(err.Error(), "Policy is required") {
			t.Fatalf("error = %v, want it to name the missing policy", err)
		}
		if tlsCfg != nil || mgr != nil {
			t.Fatal("a refused client configuration returned a TLS config")
		}
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
