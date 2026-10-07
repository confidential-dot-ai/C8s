package getcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testInstanceID = "b7f1c9e4a2d84f0b9c3e5a7d1f6b8c2e"

// testCA stands in for the CDS mesh CA: it issues leaves for a requester's key
// and stamps the workload instance the way CDS does from a verified token.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return (&testCA{key: key}).issueSelf(t, 24*time.Hour)
}

// issueSelf replaces the CA certificate under the same key, which is what a
// same-key CA renewal looks like to a pod.
func (ca *testCA) issueSelf(t *testing.T, ttl time.Duration) *testCA {
	t.Helper()
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := certutil.NewCATemplate(serial, "test-mesh-ca", time.Now().Add(ttl))
	template.NotBefore = time.Now().Add(-time.Minute)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: ca.key, cert: cert}
}

func (ca *testCA) pem(t *testing.T) string {
	t.Helper()
	return string(certutil.EncodeCertPEM(ca.cert.Raw))
}

// issue returns the chain CDS returns: the leaf first, its CA set trailing. It
// takes no *testing.T because the renewal-loop stub calls it off the test
// goroutine.
func (ca *testCA) issue(pub *ecdsa.PublicKey, instanceID string, ttl time.Duration, extra ...pkix.Extension) (string, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if instanceID != "" {
		ext, err := armtls.MarshalSandboxIDExtension(instanceID)
		if err != nil {
			return "", err
		}
		template.ExtraExtensions = []pkix.Extension{ext}
	}
	template.ExtraExtensions = append(template.ExtraExtensions, extra...)
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(certutil.EncodeCertPEM(ca.cert.Raw)), nil
}

func (ca *testCA) mustIssue(t *testing.T, pub *ecdsa.PublicKey, instanceID string, ttl time.Duration) string {
	t.Helper()
	chain, err := ca.issue(pub, instanceID, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// issueFor mints the generation CDS would return for a pod's own key.
func issueFor(ca *testCA, creds *credentials, ttl time.Duration) (*Generation, error) {
	chain, err := ca.issue(&creds.key.PublicKey, creds.instanceID, ttl)
	if err != nil {
		return nil, err
	}
	return issuedGeneration(chain, creds.key, creds.keyPEM)
}

// issueNamedFor mints the generation CDS returns once the pod's workload is
// matched: the leaf carries the matched-workload stamp too.
func issueNamedFor(ca *testCA, creds *credentials, ttl time.Duration) (*Generation, error) {
	stamp, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             "api",
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		return nil, err
	}
	chain, err := ca.issue(&creds.key.PublicKey, creds.instanceID, ttl, stamp)
	if err != nil {
		return nil, err
	}
	return issuedGeneration(chain, creds.key, creds.keyPEM)
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, keyPEM, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key, keyPEM
}

// testVolume is a credential volume on a fresh directory, under the file names
// the webhook injects.
func testVolume(t *testing.T) credentialVolume {
	t.Helper()
	dir := ramBackedDir(t)
	v, err := credentialVolumeFor(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ramBackedDir is a tmpfs directory, which is what a pod's credential volume
// is: get-cert refuses to publish a key onto persistent storage.
func ramBackedDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "credentials-")
	if err != nil {
		t.Skipf("no tmpfs to publish a credential volume on: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := fileutil.RequireRAMBacked(dir); err != nil {
		t.Skipf("%s is not RAM-backed: %v", dir, err)
	}
	return dir
}

func testGeneration(t *testing.T, ca *testCA, key *ecdsa.PrivateKey, keyPEM []byte, instanceID string, ttl time.Duration) *Generation {
	t.Helper()
	g, err := issuedGeneration(ca.mustIssue(t, &key.PublicKey, instanceID, ttl), key, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCredentialVolumeForRejects(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	for name, paths := range map[string][3]string{
		"a key in another directory": {path("tls.crt"), filepath.Join(t.TempDir(), "tls.key"), path("ca.crt")},
		"one name for two files":     {path("tls.crt"), path("tls.key"), path("tls.crt")},
		"the pointer name":           {path("current"), path("tls.key"), path("ca.crt")},
		"the issuer record name":     {path("tls.crt"), path("issuer"), path("ca.crt")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := credentialVolumeFor(paths[0], paths[1], paths[2]); err == nil {
				t.Fatalf("accepted %v", paths)
			}
		})
	}
}

// H4: get-cert does not get to trust its response. Each row is a generation a
// hostile or broken CDS could return.
func TestVerifyGenerationRejects(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	otherKey, otherKeyPEM := testKey(t)

	for name, g := range map[string]*Generation{
		"a leaf for another key": func() *Generation {
			g, err := issuedGeneration(ca.mustIssue(t, &otherKey.PublicKey, testInstanceID, time.Hour), key, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			return g
		}(),
		"a leaf from another CA": func() *Generation {
			g := testGeneration(t, newTestCA(t), key, keyPEM, testInstanceID, time.Hour)
			g.CASet = []*x509.Certificate{ca.cert}
			g.CAPEM = []byte(ca.pem(t))
			return g
		}(),
		"no instance ID":              testGeneration(t, ca, key, keyPEM, "", time.Hour),
		"another instance ID":         testGeneration(t, ca, key, keyPEM, "a7c2d41e8b96f035", time.Hour),
		"an expired leaf":             testGeneration(t, ca, key, keyPEM, testInstanceID, -time.Minute),
		"an expired CA":               testGeneration(t, ca.issueSelf(t, -time.Minute), key, keyPEM, testInstanceID, time.Hour),
		"a CA where the leaf belongs": {ChainPEM: []byte(ca.pem(t)), KeyPEM: otherKeyPEM, Leaf: ca.cert, Key: otherKey},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyGeneration(g, testInstanceID, time.Now()); err == nil {
				t.Fatal("accepted an unusable generation")
			}
		})
	}
}

// R3: the pod keeps the issuer of its first published leaf, which is the CA key
// and not the CA certificate, so a same-key renewal validates and a replacement
// key does not.
func TestValidateGenerationFollowsTheBoundKey(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	bound, err := issuerKeyIDOf(ca.cert)
	if err != nil {
		t.Fatal(err)
	}

	renewed := testGeneration(t, ca.issueSelf(t, 48*time.Hour), key, keyPEM, testInstanceID, time.Hour)
	if err := validateGeneration(renewed, testInstanceID, bound, time.Now()); err != nil {
		t.Fatalf("same-key CA renewal rejected: %v", err)
	}
	replaced := testGeneration(t, newTestCA(t), key, keyPEM, testInstanceID, time.Hour)
	if err := validateGeneration(replaced, testInstanceID, bound, time.Now()); !errors.Is(err, errUnboundIssuer) {
		t.Fatalf("replacement CA key: err = %v, want errUnboundIssuer", err)
	}
}

// R1: a reader following the stable paths sees one whole generation, both
// before and after a flip, and never a partial set.
func TestPublishGenerationFlipsOneWholeSet(t *testing.T) {
	v := testVolume(t)
	ca := newTestCA(t)
	key, keyPEM := testKey(t)

	first := testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour)
	if err := publishGeneration(v, first); err != nil {
		t.Fatal(err)
	}
	assertReaderPaths(t, v, first)

	second := testGeneration(t, ca, key, keyPEM, testInstanceID, 2*time.Hour)
	if err := publishGeneration(v, second); err != nil {
		t.Fatal(err)
	}
	assertReaderPaths(t, v, second)

	// The flip moved to the other slot, so the generation a reader may still be
	// resolving was never overwritten in place.
	target, err := os.Readlink(v.pointerPath())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != generationSlots[1] {
		t.Fatalf("pointer = %q, want slot %q", target, generationSlots[1])
	}
	info, err := os.Stat(filepath.Join(v.dir, v.keyName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("published key mode = %v, want 0600", info.Mode().Perm())
	}
}

func assertReaderPaths(t *testing.T, v credentialVolume, want *Generation) {
	t.Helper()
	for name, data := range map[string][]byte{v.leafName: want.ChainPEM, v.keyName: want.KeyPEM, v.caName: want.CAPEM} {
		got, err := os.ReadFile(filepath.Join(v.dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != string(data) {
			t.Fatalf("%s does not hold the published generation", name)
		}
	}
	stored, err := storedGeneration(v)
	if err != nil {
		t.Fatalf("storedGeneration: %v", err)
	}
	if !stored.Leaf.Equal(want.Leaf) {
		t.Fatal("the published generation is not the one that was written")
	}
}

// R4: withdrawal leaves no readable credential, and R3's binding outlives it.
func TestWithdrawGenerationKeepsTheIssuerRecord(t *testing.T) {
	v := testVolume(t)
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	creds := &credentials{volume: v, instanceID: testInstanceID, key: key, keyPEM: keyPEM}
	if err := creds.publish(testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := withdrawGeneration(v); err != nil {
		t.Fatal(err)
	}
	for _, name := range v.names() {
		if _, err := os.ReadFile(filepath.Join(v.dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still readable after withdrawal: %v", name, err)
		}
	}
	if _, err := storedGeneration(v); !errors.Is(err, errNoGeneration) {
		t.Fatalf("storedGeneration after withdrawal = %v, want errNoGeneration", err)
	}
	record, err := loadIssuerRecord(v)
	if err != nil || record != creds.issuer {
		t.Fatalf("issuer record = %q, %v; want the bound key %q", record, err, creds.issuer)
	}
}

// Rows 10, 11 and 13: what a restart may adopt. Only a volume holding a record
// and a generation that still validates under it carries a pod on; a volume
// holding neither is the pod's first start.
func TestLoadCredentialsFailsClosedOnIncompleteState(t *testing.T) {
	ca := newTestCA(t)

	t.Run("neither record nor generation bootstraps", func(t *testing.T) {
		creds, err := loadCredentials(testVolume(t), testInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if creds.key == nil || creds.issuer != "" || creds.current != nil {
			t.Fatal("a first start must hold a fresh key and no binding")
		}
	})

	t.Run("a record and a published generation resumes on its key", func(t *testing.T) {
		v, published, key := publishedVolume(t, ca)
		creds, err := loadCredentials(v, testInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if !creds.key.Equal(key) {
			t.Fatal("the pod's key was not taken from its generation")
		}
		if creds.current == nil || !creds.current.Leaf.Equal(published.Leaf) {
			t.Fatal("the published generation was not resumed")
		}
	})

	t.Run("a record with no generation fails closed", func(t *testing.T) {
		v, _, _ := publishedVolume(t, ca)
		if err := withdrawGeneration(v); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(v, testInstanceID); !errors.Is(err, errFailClosed) {
			t.Fatalf("err = %v, want errFailClosed", err)
		}
	})

	t.Run("a generation with no record fails closed", func(t *testing.T) {
		v, _, _ := publishedVolume(t, ca)
		if err := os.Remove(v.issuerPath()); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(v, testInstanceID); !errors.Is(err, errFailClosed) {
			t.Fatalf("err = %v, want errFailClosed", err)
		}
	})

	t.Run("a partial generation fails closed", func(t *testing.T) {
		v, _, _ := publishedVolume(t, ca)
		target, err := os.Readlink(v.pointerPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(v.dir, target, v.caName)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(v, testInstanceID); !errors.Is(err, errFailClosed) {
			t.Fatalf("err = %v, want errFailClosed", err)
		}
	})

	t.Run("a damaged issuer record fails closed", func(t *testing.T) {
		v, _, _ := publishedVolume(t, ca)
		if err := os.WriteFile(v.issuerPath(), []byte("not-a-fingerprint\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(v, testInstanceID); !errors.Is(err, errFailClosed) {
			t.Fatalf("err = %v, want errFailClosed", err)
		}
	})
}

// Row 10: a restart that cannot revalidate its generation withdraws it and
// stays fail-closed, so the pod cannot be moved onto another CA key.
func TestAdoptStoredGenerationWithdrawsAnInvalidOne(t *testing.T) {
	v, _, key := publishedVolume(t, newTestCA(t))
	creds, err := loadCredentials(v, "d4e9b1760c3a8f52")
	if err != nil {
		t.Fatal(err)
	}

	if err := creds.adoptStoredGeneration(time.Now()); !errors.Is(err, errFailClosed) {
		t.Fatalf("err = %v, want errFailClosed", err)
	}
	if _, err := storedGeneration(v); !errors.Is(err, errNoGeneration) {
		t.Fatal("the generation of another instance was left published")
	}
	if _, err := loadIssuerRecord(v); err != nil {
		t.Fatalf("the binding did not survive withdrawal: %v", err)
	}
	if !creds.key.Equal(key) {
		t.Fatal("the stored key changed")
	}
}

// Row 13: a generation stops being usable when its own leaf or CA set expires,
// and the pod withdraws it rather than leaving it readable.
func TestWithdrawUnusableAtExpiry(t *testing.T) {
	v := testVolume(t)
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	creds := &credentials{volume: v, instanceID: testInstanceID, key: key, keyPEM: keyPEM}
	generation := testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour)
	if err := creds.publish(generation, time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := creds.withdrawUnusable(time.Now()); err != nil || creds.current == nil {
		t.Fatalf("a valid generation was withdrawn: %v", err)
	}
	if err := creds.withdrawUnusable(generationExpiry(generation).Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if creds.current != nil {
		t.Fatal("an expired generation stayed published")
	}
	if _, err := os.Readlink(v.pointerPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the pointer survived withdrawal")
	}
}

// Row 8: a running pod publishes nothing under a replacement CA key, and keeps
// the generation it has.
func TestPublishRefusesAReplacementCAKey(t *testing.T) {
	v := testVolume(t)
	key, keyPEM := testKey(t)
	creds := &credentials{volume: v, instanceID: testInstanceID, key: key, keyPEM: keyPEM}
	bound := testGeneration(t, newTestCA(t), key, keyPEM, testInstanceID, time.Hour)
	if err := creds.publish(bound, time.Now()); err != nil {
		t.Fatal(err)
	}

	replacement := testGeneration(t, newTestCA(t), key, keyPEM, testInstanceID, time.Hour)
	if err := creds.publish(replacement, time.Now()); !errors.Is(err, errUnboundIssuer) {
		t.Fatalf("err = %v, want errUnboundIssuer", err)
	}
	if !creds.current.Leaf.Equal(bound.Leaf) {
		t.Fatal("the bound generation was replaced")
	}
	assertReaderPaths(t, v, bound)
}

func TestIssuerRecordRoundTrip(t *testing.T) {
	v := testVolume(t)
	if _, err := loadIssuerRecord(v); !errors.Is(err, errNoIssuerRecord) {
		t.Fatalf("err = %v, want errNoIssuerRecord", err)
	}
	id, err := issuerKeyIDOf(newTestCA(t).cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIssuerRecord(v, id); err != nil {
		t.Fatal(err)
	}
	got, err := loadIssuerRecord(v)
	if err != nil || got != id {
		t.Fatalf("record = %q, %v; want %q", got, err, id)
	}
	if len(strings.TrimSpace(string(got))) != 64 {
		t.Fatalf("issuer key id %q is not a SHA-256 fingerprint", got)
	}
}

// publishedVolume is a volume in the state a restart finds: one published
// generation and the issuer record it was bound under.
func publishedVolume(t *testing.T, ca *testCA) (credentialVolume, *Generation, *ecdsa.PrivateKey) {
	t.Helper()
	v := testVolume(t)
	key, keyPEM := testKey(t)
	creds := &credentials{volume: v, instanceID: testInstanceID, key: key, keyPEM: keyPEM}
	generation := testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour)
	if err := creds.publish(generation, time.Now()); err != nil {
		t.Fatal(err)
	}
	return v, generation, key
}

// stageInventory serves the node inventory's sandbox route over a temporary
// socket, asserting instanceID for whatever key asks.
func stageInventory(t *testing.T, instanceID string) {
	t.Helper()
	serveSandboxRoute(t, func(w http.ResponseWriter, r *http.Request) {
		signTokenFor(t, w, r, instanceID)
	})
	previous := nodeInventory.requireMount
	nodeInventory.requireMount = func() error { return nil }
	t.Cleanup(func() { nodeInventory.requireMount = previous })
}

// stagePodEnvironment gives cfg what an injected sidecar has: a private
// credential volume, the node inventory, and the measured CDS policy.
func stagePodEnvironment(t *testing.T, cfg config) config {
	t.Helper()
	dir := ramBackedDir(t)
	cfg.CertPath = filepath.Join(dir, "tls.crt")
	cfg.KeyPath = filepath.Join(dir, "tls.key")
	cfg.CAPath = filepath.Join(dir, "ca.crt")
	if cfg.WorkloadClaimsTimeout == 0 {
		cfg.WorkloadClaimsTimeout = 5 * time.Second
	}
	stageInventory(t, testInstanceID)
	return cfg
}

// publishedCredentials is a pod that has published one generation on a fresh
// volume, which is the state the renewal loop runs in.
func publishedCredentials(t *testing.T, ca *testCA, ttl time.Duration) *credentials {
	t.Helper()
	key, keyPEM := testKey(t)
	creds := &credentials{volume: testVolume(t), instanceID: testInstanceID, key: key, keyPEM: keyPEM}
	generation, err := issueFor(ca, creds, ttl)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(generation, time.Now()); err != nil {
		t.Fatal(err)
	}
	return creds
}

// signTokenFor answers a sandbox-token request the way the inventory does,
// naming instanceID for whatever key asks.
func signTokenFor(t *testing.T, w http.ResponseWriter, r *http.Request, instanceID string) {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var req workloadclaims.SandboxTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub, err := x509.ParsePKIXPublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	digest, err := workloadclaims.RequesterKeyDigest(pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, err := signer.Sign(instanceID, digest, req.Nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(token)
}

// An expired set is the ordinary end of a generation's life, and says so: a
// validation failure that is not expiry means the set does not hold together.
func TestExpiryIsItsOwnFailure(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	bound, err := issuerKeyIDOf(ca.cert)
	if err != nil {
		t.Fatal(err)
	}
	expired := testGeneration(t, ca, key, keyPEM, testInstanceID, -time.Minute)
	if err := validateGeneration(expired, testInstanceID, bound, time.Now()); !errors.Is(err, errGenerationExpired) {
		t.Fatalf("err = %v, want errGenerationExpired", err)
	}
	live := testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour)
	if err := validateGeneration(live, "a7c2d41e8b96f035", bound, time.Now()); errors.Is(err, errGenerationExpired) {
		t.Fatalf("a foreign instance reported as expiry: %v", err)
	}
}

// Row 12: a recreated pod starts on a fresh volume, so it binds to whichever CA
// key CDS holds now — including a replacement one — and publishes under it.
func TestRecreatedPodBindsToTheReplacementCAKey(t *testing.T) {
	retired := newTestCA(t)
	replacement := newTestCA(t)

	// The pod this one replaces, bound to the retired key.
	previous, _, _ := publishedVolume(t, retired)
	retiredKey, err := loadIssuerRecord(previous)
	if err != nil {
		t.Fatal(err)
	}

	creds, err := loadCredentials(testVolume(t), testInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := issueFor(replacement, creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(generation, time.Now()); err != nil {
		t.Fatalf("a recreated pod could not publish under the replacement key: %v", err)
	}
	record, err := loadIssuerRecord(creds.volume)
	if err != nil {
		t.Fatal(err)
	}
	want, err := issuerKeyIDOf(replacement.cert)
	if err != nil {
		t.Fatal(err)
	}
	if record != want || record == retiredKey {
		t.Fatalf("recreated pod bound to %q, want the replacement key %q", record, want)
	}
	assertReaderPaths(t, creds.volume, generation)
}
