package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvidenceFromDiscovery_Malformed(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)

	if _, err := evidenceFromDiscovery([]byte("not json"), "t", leafTrust{}, nil); err == nil {
		t.Error("non-JSON must fail")
	}

	var obj map[string]any
	good := discoveryDocWith(t, certPEM, []byte("c"), `{"attestation_report":"AAAA"}`)
	if err := json.Unmarshal(good, &obj); err != nil {
		t.Fatal(err)
	}

	delete(obj["attestation"].(map[string]any), "evidence")
	noEvidence, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromDiscovery(noEvidence, "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "no attestation.evidence") {
		t.Errorf("missing evidence should fail, got %v", err)
	}
	if err := json.Unmarshal(good, &obj); err != nil {
		t.Fatal(err)
	}
	obj["attestation"].(map[string]any)["challenge"] = "%%%not-base64%%%"
	badChallenge, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromDiscovery(badChallenge, "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "decode challenge") {
		t.Errorf("bad challenge base64 should fail, got %v", err)
	}

	garbageCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	if _, err := evidenceFromDiscovery(discoveryDocWith(t, garbageCert, []byte("c"), `{"attestation_report":"AAAA"}`), "t", leafTrust{}, nil); err == nil || !strings.Contains(err.Error(), "parse cds cert") {
		t.Errorf("unparseable cert DER should fail, got %v", err)
	}
}

func TestEvidenceFromDiscovery_DefaultsPlatformToSNP(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	doc := map[string]any{
		"cds_tls": map[string]any{"certificate_pem": certPEM},
		"attestation": map[string]any{
			"challenge": base64.StdEncoding.EncodeToString([]byte("c")),
			"evidence":  json.RawMessage(`{"attestation_report":"AAAA"}`),
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceFromDiscovery(data, "t", leafTrust{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want the snp default for a platform-less doc", ev.platform)
	}
}

func TestGatherFromDiscoveryConnectErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("bad base URL", func(t *testing.T) {
		if _, err := gatherFromDiscovery(ctx, "https://\x7f", "", "", time.Second, leafTrust{}); err == nil {
			t.Error("unparseable base must fail")
		}
	})

	t.Run("https to a non-TLS service is a connectError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		t.Cleanup(srv.Close)
		_, err := gatherFromDiscovery(ctx, "https"+strings.TrimPrefix(srv.URL, "http"), "", "", time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("a TLS handshake failure must be a connectError, got %v", err)
		}
	})

	t.Run("connection refused is a connectError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		base := srv.URL
		srv.Close()
		_, err := gatherFromDiscovery(ctx, base, "", "", time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("expected connectError, got %v", err)
		}
	})
}

// A host that accepts TCP and then stalls must not hang the gather: the
// dial timeout bounds connect + TLS handshake as a whole (tls.Dialer applies
// the NetDialer timeout to HandshakeContext), and the gather ctx carries no
// deadline of its own. The select — not a sleep — is what fails if the knob
// goes missing.
func TestGatherFromDiscoveryBoundsStallingHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close() // accept and hold: never speak TLS
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := gatherFromDiscovery(context.Background(), "https://"+ln.Addr().String(), "", "", 300*time.Millisecond, leafTrust{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !isConnectError(err) {
			t.Fatalf("a stalled handshake must surface as a connectError, got %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the gather hung on a stalling host: the dial timeout must bound connect + handshake")
	}
}

// selfSignedServerCert mints a throwaway self-signed certificate and returns
// its PEM encoding plus a tls.Certificate a test server can present.
func selfSignedServerCert(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	key, der := mintSelfSigned(t, "lb", 1, nil)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// remintServerCert re-mints cert's body around the same key (new serial): the
// SPKI matches but the DER does not.
func remintServerCert(t *testing.T, cert tls.Certificate) tls.Certificate {
	t.Helper()
	key := cert.PrivateKey.(*ecdsa.PrivateKey)
	_, der := mintSelfSigned(t, "lb", 2, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// discoveryServer starts a TLS server presenting serverCert and serving doc.
func discoveryServer(t *testing.T, serverCert tls.Certificate, doc []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(doc)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The discovery gather probes the live handshake on https targets: the
// verdict about the front door's serving key keys on what the handshake
// presented, not on the document's declared public_tls.mode — the lying-host
// case (claims cds, serves another key) and the honest webpki case both
// record an unbound door, and only the attested cert on the wire records a
// bound one.
func TestGatherFromDiscoveryProbesFrontDoor(t *testing.T) {
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	attestedPEM, attestedCert := selfSignedServerCert(t) // the key the document attests
	_, otherCert := selfSignedServerCert(t)              // a WebPKI stand-in
	docClaims := func(mode string) []byte {
		return discoveryDocWithPublicTLS(t, mode, attestedPEM, challenge, stubEvidence)
	}

	t.Run("handshake presents the attested cert", func(t *testing.T) {
		srv := discoveryServer(t, attestedCert, docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested {
			t.Errorf("frontDoor = %v, want attested", ev.frontDoor)
		}
		// The passing verdict states the observed handshake as its basis,
		// scoped to the one observation made.
		oc := snpVerifiedOutcome(t, config{}, ev)
		if !oc.Verified {
			t.Fatalf("verified=%v error=%q, want a verified verdict", oc.Verified, oc.Error)
		}
		if !strings.Contains(oc.Binding, "live handshake presented the attested serving certificate") {
			t.Errorf("Binding = %q, want it to state the observed handshake as the verdict's basis", oc.Binding)
		}
		if len(oc.Warnings) != 1 || !strings.Contains(oc.Warnings[0], "single connection") {
			t.Errorf("Warnings = %v, want the one-connection/one-replica/one-instant scope caveat", oc.Warnings)
		}
	})

	t.Run("lying host: claims cds, serves another cert", func(t *testing.T) {
		srv := discoveryServer(t, otherCert, docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Fatalf("frontDoor = %v, want other", ev.frontDoor)
		}
		served := sha256.Sum256(otherCert.Certificate[0])
		if ev.frontDoorCertSHA256 != hex.EncodeToString(served[:]) {
			t.Errorf("frontDoorCertSHA256 = %q, want the served cert's digest %x", ev.frontDoorCertSHA256, served)
		}
		// The verdict is partial, never verified: the door clients reach is
		// not attestation-bound, however the document declares itself.
		oc := snpVerifiedOutcome(t, config{}, ev)
		if oc.Verified || !oc.Partial || verdictExitCode(oc) != exitPartial {
			t.Errorf("verified=%v partial=%v exit=%d, want a partial verdict", oc.Verified, oc.Partial, verdictExitCode(oc))
		}
	})

	t.Run("honest webpki: declared and served unbound", func(t *testing.T) {
		srv := discoveryServer(t, otherCert, docClaims("webpki"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Errorf("frontDoor = %v, want other", ev.frontDoor)
		}
	})

	t.Run("declared webpki but serves the attested cert", func(t *testing.T) {
		srv := discoveryServer(t, attestedCert, docClaims("webpki"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested {
			t.Errorf("frontDoor = %v, want attested: the observed handshake governs, not the declaration", ev.frontDoor)
		}
	})

	t.Run("lying host: no mode declared, serves another cert", func(t *testing.T) {
		srv := discoveryServer(t, otherCert, docClaims(""))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Errorf("frontDoor = %v, want other", ev.frontDoor)
		}
	})

	t.Run("a re-minted body around the attested key is still another cert", func(t *testing.T) {
		srv := discoveryServer(t, remintServerCert(t, attestedCert), docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorOther {
			t.Errorf("frontDoor = %v, want other: the comparison is byte-equality, not key-equality", ev.frontDoor)
		}
	})

	t.Run("a chain at the door is compared by its leaf", func(t *testing.T) {
		chained := tls.Certificate{
			Certificate: [][]byte{attestedCert.Certificate[0], otherCert.Certificate[0]},
			PrivateKey:  attestedCert.PrivateKey,
		}
		srv := discoveryServer(t, chained, docClaims("cds"))
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested {
			t.Errorf("frontDoor = %v, want attested: the presented leaf is what compares", ev.frontDoor)
		}
	})

	t.Run("non-TLS target leaves the door unobserved", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(docClaims("cds"))
		}))
		t.Cleanup(srv.Close)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorUnobserved {
			t.Errorf("frontDoor = %v, want unobserved", ev.frontDoor)
		}
	})

	t.Run("redirect on the discovery path is a fetch failure", func(t *testing.T) {
		// The redirect target answers 200, so only the no-redirect guard
		// stands between the fetch and a followed redirect.
		target := discoveryServer(t, attestedCert, docClaims("cds"))
		srv := discoveryServer(t, attestedCert, docClaims("cds"))
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+defaultDiscoveryPath, http.StatusFound)
		})
		_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err == nil || !isConnectError(err) {
			t.Fatalf("a redirect must fail as a fetch (connect) error, got %v", err)
		}
		if !strings.Contains(err.Error(), "302") {
			t.Errorf("error = %q, want it to name the 302: the redirect is refused, not followed", err)
		}
	})
}

// Evidence gathered off the discovery path observes no front door, so it
// presents none: every non-discovery constructor records frontDoorNone, and
// the verdict then says nothing about a front door — no attested-door note,
// no scope caveat, no demotion for an unobserved one. The ARmTLS dial is
// what auto mode falls back to when the discovery fetch fails, so this is
// the state that reaches the verdict on that path.
func TestNonDiscoveryEvidencePresentsNoFrontDoor(t *testing.T) {
	nonce := make([]byte, nonceSize)
	sess := fakeSession(0x02)
	endpointJSON := buildEndpointJSON(t, mintEndpointIdentity(t), nonce, make([]byte, 64), []byte("vcek"), sess)

	for _, tc := range []struct {
		name        string
		get         func(t *testing.T) (*evidence, error)
		wantVerdict string
	}{
		{"ARmTLS serving cert: auto mode's fallback", func(t *testing.T) (*evidence, error) {
			srv := attestedTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			return gatherFromARMTLSCert(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "", 5*time.Second, leafTrust{})
		}, "verified"},
		{"attest-pq endpoint", func(*testing.T) (*evidence, error) {
			return evidenceFromEndpointJSON(endpointJSON, nonce, sess.ek, "attestation endpoint")
		}, "partial"},
		{"saved bare evidence", func(*testing.T) (*evidence, error) {
			return evidenceFromBareJSON([]byte(`{"evidence":{"attestation_report":"AAAA"}}`), make([]byte, 48), "file")
		}, "verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := tc.get(t)
			if err != nil {
				t.Fatal(err)
			}
			if ev.frontDoor != frontDoorNone {
				t.Errorf("frontDoor = %v, want none: this evidence is not discovery-sourced", ev.frontDoor)
			}
			if ev.frontDoorCertSHA256 != "" {
				t.Errorf("frontDoorCertSHA256 = %q, want empty: no handshake leaf was compared", ev.frontDoorCertSHA256)
			}

			oc := snpVerifiedOutcome(t, config{}, ev)
			if got := verdictShape(oc); got != tc.wantVerdict {
				t.Errorf("verdict = %s (error=%q not_proven=%v), want %s", got, oc.Error, oc.NotProven, tc.wantVerdict)
			}
			if strings.Contains(oc.Binding, "live handshake presented the attested serving certificate") {
				t.Errorf("Binding = %q, want no attested-front-door claim on evidence that observed none", oc.Binding)
			}
			for _, w := range oc.Warnings {
				if strings.Contains(w, "attested front door") {
					t.Errorf("Warnings = %v, want no front-door scope caveat", oc.Warnings)
				}
			}
			for _, np := range oc.NotProven {
				if strings.Contains(np, "front door") {
					t.Errorf("NotProven = %v, want no front-door demotion", oc.NotProven)
				}
			}
		})
	}
}

// verdictShape names the verdict a test expects, so a mismatch prints the
// shape rather than a pair of bools.
func verdictShape(oc Outcome) string {
	switch {
	case oc.Verified:
		return "verified"
	case oc.Partial:
		return "partial"
	default:
		return "failed"
	}
}

// The document and the observed handshake leaf must ride ONE connection:
// serving certs are per replica, so a second dial can reach a different
// replica — or, for an adversarial host, a proxied attested router pod — and
// make a WebPKI door look attested. The server below is that host: the door
// clients reach (first connection) serves a WebPKI stand-in, every later
// connection gets the attested cert. The observation must be the dialed
// connection's leaf, and there must be exactly one dial — the count pins the
// invariant regardless of dial order.
func TestGatherFromDiscoverySingleConnection(t *testing.T) {
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`
	attestedPEM, attestedCert := selfSignedServerCert(t)
	_, otherCert := selfSignedServerCert(t) // a WebPKI stand-in
	doc := discoveryDocWithPublicTLS(t, "cds", attestedPEM, challenge, stubEvidence)

	// Hand-rolled TLS listener: httptest's StartTLS installs its own
	// certificate when Certificates is empty, which would shadow
	// GetCertificate for a client that sends no SNI.
	var handshakes atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(doc)
	})}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(tls.NewListener(ln, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if handshakes.Add(1) == 1 {
			return &otherCert, nil
		}
		return &attestedCert, nil
	}}))

	ev, err := gatherFromDiscovery(context.Background(), "https://"+ln.Addr().String(), "", "", 5*time.Second, leafTrust{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.frontDoor != frontDoorOther {
		t.Errorf("frontDoor = %v, want other: the observation must be the dialed connection's leaf (the door clients reach), not a later connection's", ev.frontDoor)
	}
	if got := handshakes.Load(); got != 1 {
		t.Errorf("handshakes = %d, want exactly 1: the document and the observation must ride one connection", got)
	}
}

// singleConnClient's second dial fails closed rather than re-reaching a
// possibly different replica.
func TestSingleConnClientNeverRedials(t *testing.T) {
	_, serverCert := selfSignedServerCert(t)
	srv := discoveryServer(t, serverCert, []byte("{}"))
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	transport := singleConnClient(conn, 5*time.Second).Transport.(*http.Transport)
	if _, err := transport.DialTLSContext(context.Background(), "tcp", "unused"); err != nil {
		t.Fatalf("the first dial hands out the attested connection: %v", err)
	}
	if _, err := transport.DialTLSContext(context.Background(), "tcp", "unused"); err == nil {
		t.Fatal("a second dial must fail closed")
	}
}

// A discovery document's CA-vouched serving cert (the chart's shape: issued
// by the CDS mesh CA) is authenticated by the live handshake when it presents
// byte-identically that cert — the same possession backstop as the ARmTLS
// path — so a live door needs no --mesh-ca. A door serving a different cert
// gets no such backstop and fails closed.
func TestDiscoveryHandshakeAuthenticatesCAVouchedBody(t *testing.T) {
	challenge := []byte("issuance-challenge")
	stubEvidence := `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`

	id := mintEndpointIdentity(t) // CA-signed leaf, the CDS-issued serving cert's shape
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.leaf.Raw}))
	leafTLSCert := tls.Certificate{Certificate: [][]byte{id.leaf.Raw}, PrivateKey: id.key}
	doc := discoveryDocWithPublicTLS(t, "cds", leafPEM, challenge, stubEvidence)

	t.Run("handshake presenting the attested CA-vouched leaf needs no --mesh-ca", func(t *testing.T) {
		srv := discoveryServer(t, leafTLSCert, doc)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err != nil {
			t.Fatalf("a live door presenting the attested leaf must authenticate its body: %v", err)
		}
		if ev.frontDoor != frontDoorAttested || !ev.leafKeyProven {
			t.Errorf("frontDoor = %v leafKeyProven = %v, want attested / proven", ev.frontDoor, ev.leafKeyProven)
		}
		if got := describeCertBody(config{}, ev); !strings.Contains(got, "live TLS handshake") {
			t.Errorf("cert-body note = %q, want the possession branch", got)
		}
	})

	t.Run("a pinned mesh CA stays the body authentication on a match", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(id.ca)
		srv := discoveryServer(t, leafTLSCert, doc)
		ev, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{meshCA: pool})
		if err != nil {
			t.Fatal(err)
		}
		if ev.frontDoor != frontDoorAttested || !ev.leafChainVerified {
			t.Errorf("frontDoor = %v leafChainVerified = %v, want attested / chain-verified", ev.frontDoor, ev.leafChainVerified)
		}
		if got := describeCertBody(config{}, ev); !strings.Contains(got, "verified issuing chain") {
			t.Errorf("cert-body note = %q, want the verified-chain branch", got)
		}
	})

	t.Run("a door serving another cert gets no possession backstop", func(t *testing.T) {
		_, otherCert := selfSignedServerCert(t)
		srv := discoveryServer(t, otherCert, doc)
		_, err := gatherFromDiscovery(context.Background(), srv.URL, "", "", 5*time.Second, leafTrust{})
		if err == nil || !isSecurityError(err) {
			t.Fatalf("an unauthenticated CA-vouched body must fail closed, got %v", err)
		}
		if !strings.Contains(err.Error(), "--mesh-ca") {
			t.Errorf("error = %q, want it to name the flag that fixes it", err)
		}
		// The door lie is the actionable signal: the served-vs-attested
		// digests must reach the operator, not be buried by the body failure.
		served := sha256.Sum256(otherCert.Certificate[0])
		attested := sha256.Sum256(id.leaf.Raw)
		if !strings.Contains(err.Error(), hex.EncodeToString(served[:])) ||
			!strings.Contains(err.Error(), hex.EncodeToString(attested[:])) {
			t.Errorf("error = %q, want it to name the served and attested serving-cert digests", err)
		}
	})
}
