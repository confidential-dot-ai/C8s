package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// mintAttestedLeaf builds a self-issued cert with a genuine (fake-SNP)
// attestation extension, an embedded public key from holder, a signature by
// signer, and the given validity. signer != holder models an altered body
// re-signed by an attacker who does not hold the attested key.
func mintAttestedLeaf(t *testing.T, holder *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	attExt, err := armtls.MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(11),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{attExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, holder, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// mintForgedIssuerLeaf reproduces the no-private-key exploit: the attested
// public key is holder's, but the Issuer DN differs from the Subject so the
// self-signature check is never reached, the signature is junk (x509 parsing
// checks none), and NotAfter is decades out. Everything REPORTDATA covers —
// the SubjectPublicKeyInfo — is untouched, so genuine hardware evidence still
// verifies against it.
func mintForgedIssuerLeaf(t *testing.T, holder *ecdsa.PublicKey, notAfter time.Time) *x509.Certificate {
	t.Helper()
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	attExt, err := armtls.MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "workload-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IsCA:         true,
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(11),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{attExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, holder, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert.Signature = make([]byte, len(cert.Signature)) // nothing checks it
	return cert
}

// The forged-issuer certificate must not become evidence on any source that
// cannot prove the presenter holds the attested key. Both sources that can't —
// a saved file and a discovery document fetched over a connection nothing
// binds it to — must fail closed, as a security verdict rather than an
// "evidence unavailable".
func TestUnauthenticatedCertBodyRejected(t *testing.T) {
	holder := testKey(t)
	forged := mintForgedIssuerLeaf(t, &holder.PublicKey, time.Now().Add(500000*time.Hour))

	t.Run("saved certificate file", func(t *testing.T) {
		_, err := gatherFromFile(certutil.EncodeCertPEM(forged.Raw), nil, "file", leafTrust{})
		if err == nil {
			t.Fatal("a CA-issued certificate whose chain is unchecked must not become evidence")
		}
		if !isSecurityError(err) {
			t.Fatalf("want a security verdict (no auto-mode fall-through, exit 2), got %T", err)
		}
		if !strings.Contains(err.Error(), "--mesh-ca") {
			t.Errorf("error = %q, want it to name the flag that fixes it", err)
		}
	})

	t.Run("discovery document", func(t *testing.T) {
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(forged.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		_, err := evidenceFromDiscovery(doc, "test", leafTrust{}, nil)
		if err == nil {
			t.Fatal("a replayed discovery document with a re-minted certificate must not verify")
		}
		if !isSecurityError(err) {
			t.Fatalf("want a security verdict, got %T", err)
		}
	})

	t.Run("--mesh-ca that does not cover the leaf", func(t *testing.T) {
		// A pinned CA that did not issue this leaf is a chain failure, not a
		// pass: the pin is the authentication, so it has to actually hold.
		_, err := gatherFromFile(certutil.EncodeCertPEM(forged.Raw), nil, "file",
			leafTrust{meshCA: x509.NewCertPool()})
		if err == nil || !strings.Contains(err.Error(), "does not chain") {
			t.Fatalf("want a chain failure against the pinned CA, got %v", err)
		}
	})

	// A live ARmTLS dial is different in kind: completing the handshake proves
	// the peer holds the attested private key, which a re-minted body around
	// someone else's SPKI cannot do. That path records the proof instead of
	// demanding a chain.
	t.Run("live handshake stands in for the chain", func(t *testing.T) {
		ev, err := evidenceFromCert(forged, "test", leafTrust{keyProven: true})
		if err != nil {
			t.Fatalf("a proof-of-possession source must not need --mesh-ca: %v", err)
		}
		if ev.leafChainVerified {
			t.Error("no chain was checked on this path; the verdict must not claim one")
		}
		if !strings.Contains(describeCertBody(config{}, ev), "holds the attested key") {
			t.Errorf("cert-body note must say what actually backs the body: %q", describeCertBody(config{}, ev))
		}
	})
}

// With --mesh-ca the CA-issued body IS authenticated, and the verdict records
// that a CA anchor stands behind the leaf — which is what downgrades the
// deployment-class measurement rule to a warning.
func TestMeshCAAuthenticatesCAIssuedCertBody(t *testing.T) {
	caKey := testKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	attExt, err := armtls.MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := testKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "cds"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{attExt},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(leaf.Raw)), []byte("challenge"),
		`{"attestation_report":"AAAA"}`)
	ev, err := evidenceFromDiscovery(doc, "test", leafTrust{meshCA: pool}, nil)
	if err != nil {
		t.Fatalf("a CA-issued discovery cert chaining to --mesh-ca must be accepted: %v", err)
	}
	if !ev.leafChainVerified {
		t.Fatal("leafChainVerified must record the CA anchor the verdict keys on")
	}
	if got := describeCertBody(config{}, ev); !strings.Contains(got, "verified issuing chain") {
		t.Errorf("cert-body note = %q", got)
	}
}

// An altered self-signed body under a real attestation extension must never
// produce evidence: the extension binds only the key, so the self-signature
// is the only thing authenticating subject/serial/validity.
func TestEvidenceFromCertRejectsResignedBody(t *testing.T) {
	now := time.Now()
	holder, signer := testKey(t), testKey(t)
	cert := mintAttestedLeaf(t, &holder.PublicKey, signer, now.Add(-time.Hour), now.Add(time.Hour))

	_, err := evidenceFromCert(cert, "test", leafTrust{})
	if err == nil || !strings.Contains(err.Error(), "does not verify with its own key") {
		t.Fatalf("want self-signature rejection, got %v", err)
	}
	if !isSecurityError(err) {
		t.Fatalf("an altered body is a security failure (no auto-mode fall-through), got %T", err)
	}
}

func TestEvidenceFromCertValidity(t *testing.T) {
	now := time.Now()
	key := testKey(t)

	t.Run("future NotBefore beyond skew rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key,
			now.Add(certutil.LeafValiditySkew+time.Minute), now.Add(2*time.Hour))
		_, err := evidenceFromCert(cert, "test", leafTrust{})
		if err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("want NotBefore rejection, got %v", err)
		}
		if !isSecurityError(err) {
			t.Fatalf("want a security error, got %T", err)
		}
	})

	t.Run("NotBefore within skew accepted", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key,
			now.Add(certutil.LeafValiditySkew-time.Minute), now.Add(2*time.Hour))
		if _, err := evidenceFromCert(cert, "test", leafTrust{}); err != nil {
			t.Fatalf("NotBefore within the documented skew must pass: %v", err)
		}
	})

	t.Run("expired NotAfter rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		_, err := evidenceFromCert(cert, "test", leafTrust{})
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want NotAfter rejection, got %v", err)
		}
	})

	// The binding note must say what bounds a replay: these certs carry no
	// nonce, so validity is the only freshness bound.
	t.Run("replay bounded only by validity is documented in the binding", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		ev, err := evidenceFromCert(cert, "test", leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.fresh {
			t.Error("cert evidence must not claim freshness")
		}
		if !strings.Contains(ev.bindingNote, "replayable within the authenticated certificate validity window") {
			t.Errorf("bindingNote = %q, want it to state the replay bound", ev.bindingNote)
		}
	})
}

// The discovery path parses the same class of certificate and must apply the
// same body rules, and its retained leaf unlocks the CA-vouched pins.
func TestEvidenceFromDiscoveryAuthenticatesCertBody(t *testing.T) {
	now := time.Now()
	key := testKey(t)

	t.Run("expired discovery cert rejected", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		_, err := evidenceFromDiscovery(doc, "test", leafTrust{}, nil)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want NotAfter rejection, got %v", err)
		}
	})

	t.Run("re-signed discovery cert rejected", func(t *testing.T) {
		signer := testKey(t)
		cert := mintAttestedLeaf(t, &key.PublicKey, signer, now.Add(-time.Hour), now.Add(time.Hour))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		if _, err := evidenceFromDiscovery(doc, "test", leafTrust{}, nil); err == nil {
			t.Fatal("want self-signature rejection on the discovery cert")
		}
	})

	t.Run("valid discovery cert is retained as the leaf", func(t *testing.T) {
		cert := mintAttestedLeaf(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		doc := discoveryDocWith(t, string(certutil.EncodeCertPEM(cert.Raw)), []byte("challenge"),
			`{"attestation_report":"AAAA"}`)
		ev, err := evidenceFromDiscovery(doc, "test", leafTrust{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ev.leaf == nil {
			t.Fatal("discovery evidence must retain the leaf so --mesh-ca/--sandbox-id/--workload can check it")
		}
		if ev.leafBody != certutil.BodySelfSigned {
			t.Errorf("leafBody = %v, want a self-issued discovery cert recorded as self-signed", ev.leafBody)
		}
	})
}

// The verdict says what authenticates the body fields, in each class — and
// only claims validity was enforced where the bytes carrying it are signed
// for by something.
func TestDescribeCertBody(t *testing.T) {
	self := &evidence{leafBody: certutil.BodySelfSigned}
	if got := describeCertBody(config{}, self); !strings.Contains(got, "own attested key") ||
		!strings.Contains(got, "validity enforced") {
		t.Errorf("self-signed note = %q", got)
	}
	chained := &evidence{leafChainVerified: true}
	if got := describeCertBody(config{}, chained); !strings.Contains(got, "verified issuing chain") ||
		!strings.Contains(got, "validity enforced") {
		t.Errorf("chain-verified note = %q", got)
	}
	// The attest-pq transcript binds the exact body bytes, so validity is
	// genuinely enforced — but the note must not claim a verified chain: the
	// anchor is responder-chosen, which the chain-anchor / not-proven lines
	// carry.
	derived := &evidence{leafChainDerived: true}
	dgot := describeCertBody(config{}, derived)
	if !strings.Contains(dgot, "identity transcript") || !strings.Contains(dgot, "validity enforced") {
		t.Errorf("derived-chain note = %q", dgot)
	}
	if strings.Contains(dgot, "verified issuing chain") {
		t.Errorf("derived-chain note = %q: a responder-chosen anchor is not a verified chain", dgot)
	}
	// A live handshake proves possession of the attested key, which is what
	// stands behind an un-chained body there — say that, not "validity
	// enforced": NotAfter inside an unsigned body bounds nothing on its own.
	proven := &evidence{leafKeyProven: true}
	got := describeCertBody(config{}, proven)
	if !strings.Contains(got, "holds the attested key") {
		t.Errorf("key-proven note = %q", got)
	}
	if strings.Contains(got, "validity enforced") {
		t.Errorf("key-proven note = %q, must not claim validity bounds an unauthenticated body", got)
	}
	// The residual class reaches no caller today (authorizeLeafBody rejects
	// it), but if it ever renders it must not dress itself up.
	unauth := describeCertBody(config{}, &evidence{})
	if !strings.Contains(unauth, "UNAUTHENTICATED") {
		t.Errorf("unauthenticated note = %q, must flag the unauthenticated body", unauth)
	}
	if strings.Contains(unauth, "validity enforced") {
		t.Errorf("unauthenticated note = %q: validity checked against unauthenticated bytes bounds nothing", unauth)
	}
}
