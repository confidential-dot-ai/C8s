package cdsattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testManifest routes nothing; handshake tests need only its digest.
const testManifest = `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2020-01-01T00:00:00Z","maxAgeSeconds":3600,"hosts":{}}`

// testRouteDigest is the digest every testRoutes state binds.
var testRouteDigest = sha256.Sum256([]byte(testManifest))

// signManifest signs manifest with a fresh operator key.
func signManifest(t *testing.T, manifest string) (routes.Envelope, []*ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := signer.Authorization(http.MethodPut, routes.Path, []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return routes.Envelope{Manifest: []byte(manifest), Token: strings.TrimPrefix(auth, "Bearer ")}, []*ecdsa.PublicKey{&key.PublicKey}
}

// signedManifest signs manifest with a fresh operator key and verifies it.
func signedManifest(t *testing.T, manifest string) *routing.Applied {
	t.Helper()
	env, keys := signManifest(t, manifest)
	signed, err := routes.VerifySigned(env, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := signed.Manifest()
	return &routing.Applied{Signed: signed, Manifest: m, Table: routes.Compile(m, nil)}
}

// noMeshCAs is a CASource for manifests with no address backend.
func noMeshCAs() ([]*x509.Certificate, error) { return nil, nil }

// testRoutes is a route state with the test manifest applied, so the attested
// handshakes a server serves from it bind testRouteDigest.
// testRoutes is a router with testManifest applied that echoes tunnel
// requests.
func testRoutes(t *testing.T) testRouter {
	t.Helper()
	state := routing.NewState(routing.StateConfig{MeshCAs: noMeshCAs})
	if _, err := state.Accept(signManifest(t, testManifest)); err != nil {
		t.Fatal(err)
	}
	return testRouter{State: state, backendFunc: echoBackend}
}

// manifestAt is testManifest at another revision, so its digest differs.
func manifestAt(revision int) string {
	return strings.Replace(testManifest, `"revision":1`, `"revision":`+strconv.Itoa(revision), 1)
}

// swappingRoutes answers the first Session with first and every later load
// with second, standing in for a manifest applied mid-handshake.
type swappingRoutes struct {
	backendFunc
	mu            sync.Mutex
	first, second *routing.Applied
	loads         int
}

func (r *swappingRoutes) Session() (*routing.Applied, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loads++
	if r.loads == 1 {
		return r.first, nil
	}
	return r.second, nil
}

func (r *swappingRoutes) Current() *routing.Applied {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loads++
	return r.second
}

// digestServer serves both attested handshakes from source.
type digestServer struct {
	url        string
	prov       *capturingProvider
	identity   testMeshIdentity
	servingDER []byte
}

// newDigestServer serves both handshakes from router.
func newDigestServer(t *testing.T, router Router) *digestServer {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	certPath, servingDER := writeTestServingLeaf(t)
	prov := &capturingProvider{}
	srv := NewServer(Config{
		Evidence:             prov,
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Routes:               router,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &digestServer{url: ts.URL, prov: prov, identity: identity, servingDER: servingDER}
}

// pqDigestBound runs attest-pq and requires report_data and the bundle's
// informational field to carry digest.
func (d *digestServer) pqDigestBound(t *testing.T, digest [sha256.Size]byte) {
	t.Helper()
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x21}, 32)
	b := fetchBundle(t, d.url, ck, nonce)
	ct, err := base64.RawURLEncoding.DecodeString(b.XWingCT)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := base64.RawURLEncoding.DecodeString(b.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := overenc.IdentityTranscriptHash(b.FrontDoorMode, ck.EncapsulationKey(), ct, sessionID, nonce, d.identity.leaf.Raw, d.identity.ca.Raw, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.prov.lastReportData, want) {
		t.Fatalf("attest-pq report_data does not bind route digest %x", digest)
	}
	if b.RouteDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("attest-pq route_digest = %q, want %x", b.RouteDigest, digest)
	}
}

func (d *digestServer) lbDigestBound(t *testing.T, digest [sha256.Size]byte) {
	t.Helper()
	nonce := bytes.Repeat([]byte{0x31}, 32)
	resp, err := http.Get(d.url + "/.well-known/c8s/attest-lb?nonce=" + b64url(nonce))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attest-lb status %d", resp.StatusCode)
	}
	var b types.AttestationBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	want, err := overenc.LBTranscriptHash(b.FrontDoorMode, nonce, d.servingDER, d.identity.leaf.Raw, d.identity.ca.Raw, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.prov.lastReportData, want) {
		t.Fatalf("attest-lb report_data does not bind route digest %x", digest)
	}
	if b.RouteDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("attest-lb route_digest = %q, want %x", b.RouteDigest, digest)
	}
}

func TestE1HandshakesBindAppliedDigest(t *testing.T) {
	state := routing.NewState(routing.StateConfig{MeshCAs: noMeshCAs})
	d := newDigestServer(t, testRouter{State: state, backendFunc: echoBackend})
	for _, revision := range []int{1, 2} {
		manifest := manifestAt(revision)
		if _, err := state.Accept(signManifest(t, manifest)); err != nil {
			t.Fatalf("Accept(revision %d) = %v", revision, err)
		}
		digest := sha256.Sum256([]byte(manifest))
		d.pqDigestBound(t, digest)
		d.lbDigestBound(t, digest)
	}
}

func TestE2DigestComesFromTheAdmittedManifest(t *testing.T) {
	for _, handshake := range []string{"attest-pq", "attest-lb"} {
		t.Run(handshake, func(t *testing.T) {
			source := &swappingRoutes{backendFunc: echoBackend, first: signedManifest(t, manifestAt(1)), second: signedManifest(t, manifestAt(2))}
			d := newDigestServer(t, source)
			digest := sha256.Sum256([]byte(manifestAt(1)))
			if handshake == "attest-pq" {
				d.pqDigestBound(t, digest)
			} else {
				d.lbDigestBound(t, digest)
			}
			if source.loads != 1 {
				t.Fatalf("handshake loaded the route manifest %d times, want once (E2)", source.loads)
			}
		})
	}
}

func TestE1HandshakesRefusedBeforeFirstApply(t *testing.T) {
	d := newDigestServer(t, testRouter{State: routing.NewState(routing.StateConfig{MeshCAs: noMeshCAs}), backendFunc: echoBackend})
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(types.AttestPQRequest{Nonce: b64url(make([]byte, 32)), XWingEK: b64url(ck.EncapsulationKey())})
	pq := postAttestPQ(t, d.url, body)
	lb, err := http.Get(d.url + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if got := errorCode(t, pq); got != types.ErrorCodeRoutesUnavailable {
		t.Fatalf("attest-pq before the first apply = %q, want %q", got, types.ErrorCodeRoutesUnavailable)
	}
	if got := errorCode(t, lb); got != types.ErrorCodeRoutesUnavailable {
		t.Fatalf("attest-lb before the first apply = %q, want %q", got, types.ErrorCodeRoutesUnavailable)
	}
	if d.prov.lastReportData != nil {
		t.Fatal("a refused handshake requested evidence")
	}
}
