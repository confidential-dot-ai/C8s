//go:build linux

package armtlsmesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// testInstanceID is the workload instance a published leaf names.
const testInstanceID = "3f2c1b0a9e8d7c6b5a493827160514f3e2d1c0b9a8978685746352413f2e1d0c"

// meshCA mints the generations a test publishes.
type meshCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newMeshCA(t *testing.T, validFor time.Duration) meshCA {
	t.Helper()
	key := testKey(t)
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := certutil.NewCATemplate(serial, "c8s Mesh CA", time.Now().Add(validFor))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return meshCA{
		key:  key,
		cert: cert,
	}
}

// leafSpec shapes the leaf a test publishes. Its zero value is the leaf
// get-cert publishes: both TLS purposes, the instance-ID extension, and an
// hour of validity around now.
type leafSpec struct {
	key            *ecdsa.PrivateKey
	notBefore      time.Time
	notAfter       time.Time
	purposes       []x509.ExtKeyUsage
	omitInstanceID bool
}

// issue returns the published set of a generation issued by this CA.
func (ca meshCA) issue(t *testing.T, spec leafSpec) publishedSet {
	t.Helper()
	key := spec.key
	if key == nil {
		key = testKey(t)
	}
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(time.Hour)
	}
	if spec.purposes == nil {
		spec.purposes = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mesh-endpoint"},
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  spec.purposes,
	}
	if !spec.omitInstanceID {
		ext, err := armtls.MarshalSandboxIDExtension(testInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{ext}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return publishedSet{
		chainPEM: certutil.EncodeCertPEM(der),
		keyPEM:   testKeyPEM(t, key),
		caPEM:    certutil.EncodeCertPEM(ca.cert.Raw),
	}
}

// meshConfigs returns the two armTLS configurations of a peer holding a leaf
// from this CA: what a real mesh endpoint on the other side presents.
func (ca meshCA) meshConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	g, err := adoptPublishedSet(ca.issue(t, leafSpec{}), time.Now(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	return g.serverTLS, g.clientTLS
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	pem, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testVolume is a credential volume with the file names get-cert's callers use.
func testVolume(t *testing.T) credentialVolume {
	t.Helper()
	dir := t.TempDir()
	volume, err := credentialVolumeFor(
		filepath.Join(dir, "tls.crt"),
		filepath.Join(dir, "tls.key"),
		filepath.Join(dir, "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return volume
}

// publishSet writes a generation under a name no earlier publication used and
// flips the pointer onto it, as get-cert's publication does.
func publishSet(t *testing.T, volume credentialVolume, set publishedSet) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(volume.dir, "generations"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	name := filepath.Join("generations", strconv.Itoa(len(entries)+1))
	dir := filepath.Join(volume.dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		volume.chainName: set.chainPEM,
		volume.keyName:   set.keyPEM,
		volume.caName:    set.caPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// One rename, as the publication the watcher observes: a pointer that
	// briefly names nothing is a withdrawal.
	tmp := volume.pointerPath() + ".next"
	if err := os.Symlink(name, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, volume.pointerPath()); err != nil {
		t.Fatal(err)
	}
}

// withdrawSet removes the generation pointer, as get-cert's withdrawal does.
func withdrawSet(t *testing.T, volume credentialVolume) {
	t.Helper()
	if err := os.Remove(volume.pointerPath()); err != nil {
		t.Fatal(err)
	}
}

// A generation serves connections only when the leaf it presents matches the
// published key, names a workload instance, and chains to the CA its peers
// are verified against in both TLS roles.
func TestAdoptPublishedSetValidatesTheSet(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	foreign := newMeshCA(t, time.Hour)
	valid := ca.issue(t, leafSpec{})

	wrongKey := valid
	wrongKey.keyPEM = testKeyPEM(t, testKey(t))
	foreignCA := valid
	foreignCA.caPEM = foreign.issue(t, leafSpec{}).caPEM
	noCA := valid
	noCA.caPEM = nil
	twoCAs := valid
	twoCAs.caPEM = append(append([]byte{}, valid.caPEM...), foreign.issue(t, leafSpec{}).caPEM...)
	garbageLeaf := valid
	garbageLeaf.chainPEM = []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n")

	tests := []struct {
		name    string
		set     publishedSet
		wantErr bool
	}{
		{"published generation", valid, false},
		{"leaf and key from different generations", wrongKey, true},
		{"leaf without a workload instance ID", ca.issue(t, leafSpec{omitInstanceID: true}), true},
		{"leaf usable in one role only", ca.issue(t, leafSpec{purposes: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}), true},
		{"another mesh CA", foreignCA, true},
		{"no CA", noCA, true},
		{"two CA certificates", twoCAs, true},
		{"expired leaf", ca.issue(t, leafSpec{
			notBefore: time.Now().Add(-2 * time.Hour),
			notAfter:  time.Now().Add(-time.Hour),
		}), true},
		{"unparseable leaf", garbageLeaf, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := adoptPublishedSet(tc.set, time.Now(), discardLogger())
			if tc.wantErr {
				if err == nil {
					t.Fatal("the set was adopted; it must not serve a connection")
				}
				return
			}
			if err != nil {
				t.Fatalf("adoptPublishedSet: %v", err)
			}
			for role, cfg := range map[string]*tls.Config{"server": g.serverTLS, "client": g.clientTLS} {
				if !slices.Contains(cfg.NextProtos, armtls.MeshALPN) {
					t.Errorf("%s config offers %v, want the mesh ALPN %q", role, cfg.NextProtos, armtls.MeshALPN)
				}
				if !cfg.SessionTicketsDisabled {
					t.Errorf("%s config allows session resumption", role)
				}
			}
		})
	}
}

// The three files come from the generation the pointer names, so a flip
// part-way through a read cannot mix two generations.
func TestReadResolvesThePointerOnce(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	if _, err := volume.read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read without a pointer = %v, want a not-exist error", err)
	}
	first := ca.issue(t, leafSpec{})
	publishSet(t, volume, first)
	read, err := volume.read()
	if err != nil {
		t.Fatal(err)
	}
	if !read.sameAs(first) {
		t.Fatal("read returned a set other than the published one")
	}
	withdrawSet(t, volume)
	if _, err := volume.read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read after withdrawal = %v, want a not-exist error", err)
	}
}

// An adopted generation holds until a new one validates: a rejected
// publication leaves the endpoint serving what it already had, and a
// withdrawal leaves it serving nothing.
func TestCredentialsAdoptEachValidatedGeneration(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	foreign := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	creds := &credentials{
		volume: volume,
		logger: discardLogger(),
	}

	creds.reload(time.Now())
	if _, err := creds.usable(time.Now()); err == nil {
		t.Fatal("a connection was admitted before anything was published")
	}

	publishSet(t, volume, ca.issue(t, leafSpec{}))
	creds.reload(time.Now())
	first, err := creds.usable(time.Now())
	if err != nil {
		t.Fatalf("usable after the first publication: %v", err)
	}

	creds.reload(time.Now())
	if again, _ := creds.usable(time.Now()); again != first {
		t.Error("an unchanged publication was adopted again")
	}

	// A leaf published with another CA's set: nothing a reader could use.
	inconsistent := ca.issue(t, leafSpec{})
	inconsistent.caPEM = foreign.issue(t, leafSpec{}).caPEM
	publishSet(t, volume, inconsistent)
	creds.reload(time.Now())
	if kept, _ := creds.usable(time.Now()); kept != first {
		t.Error("a rejected publication replaced a usable generation")
	}

	publishSet(t, volume, ca.issue(t, leafSpec{}))
	creds.reload(time.Now())
	second, err := creds.usable(time.Now())
	if err != nil {
		t.Fatalf("usable after renewal: %v", err)
	}
	if second == first {
		t.Error("a renewed generation was not adopted")
	}

	withdrawSet(t, volume)
	creds.reload(time.Now())
	if _, err := creds.usable(time.Now()); err == nil {
		t.Fatal("a connection was admitted after the generation was withdrawn")
	}
}

// A generation stops serving when its leaf or any CA it trusts expires, so an
// endpoint whose credentials ran out refuses connections and reports unready.
func TestUsableRefusesAnExpiredGeneration(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	shortCA := newMeshCA(t, 30*time.Minute)

	tests := []struct {
		name   string
		set    publishedSet
		expiry time.Duration
	}{
		{"expired leaf", ca.issue(t, leafSpec{notAfter: time.Now().Add(10 * time.Minute)}), 10 * time.Minute},
		{"expired mesh CA", shortCA.issue(t, leafSpec{}), 30 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volume := testVolume(t)
			publishSet(t, volume, tc.set)
			creds := &credentials{
				volume: volume,
				logger: discardLogger(),
			}
			creds.reload(time.Now())
			g, err := creds.usable(time.Now())
			if err != nil {
				t.Fatalf("usable now: %v", err)
			}
			if got := time.Until(g.expiry()).Round(time.Minute); got != tc.expiry {
				t.Errorf("expiry in %s, want %s", got, tc.expiry)
			}
			past := time.Now().Add(tc.expiry + time.Minute)
			if _, err := creds.usable(past); err == nil {
				t.Fatal("the expired generation is still usable")
			}
			creds.reload(past)
			if _, err := creds.usable(time.Now()); err == nil {
				t.Fatal("the expired generation was not withdrawn")
			}
		})
	}
}
