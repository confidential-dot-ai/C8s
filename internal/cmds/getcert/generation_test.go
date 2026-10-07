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
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
	return &testCA{
		key:  ca.key,
		cert: cert,
	}
}

func (ca *testCA) pem(t *testing.T) string {
	t.Helper()
	return string(certutil.EncodeCertPEM(ca.cert.Raw))
}

// issue returns the chain CDS returns: the leaf first, its CA trailing. It
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
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})) + string(certutil.EncodeCertPEM(ca.cert.Raw)), nil
}

func (ca *testCA) mustIssue(t *testing.T, pub *ecdsa.PublicKey, instanceID string, ttl time.Duration) string {
	t.Helper()
	chain, err := ca.issue(pub, instanceID, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// issueFor mints the generation CDS would return for a request's own fresh key,
// which is what every renewal asks on.
func issueFor(ca *testCA, creds *credentials, ttl time.Duration) (*generation, error) {
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	chain, err := ca.issue(&key.PublicKey, creds.instanceID, ttl)
	if err != nil {
		return nil, err
	}
	return issuedGeneration(chain, key, keyPEM)
}

// issueNamedFor mints the generation CDS returns once the pod's workload is
// matched: the leaf carries the matched-workload stamp too.
func issueNamedFor(ca *testCA, creds *credentials, ttl time.Duration) (*generation, error) {
	stamp, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             "api",
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		return nil, err
	}
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	chain, err := ca.issue(&key.PublicKey, creds.instanceID, ttl, stamp)
	if err != nil {
		return nil, err
	}
	return issuedGeneration(chain, key, keyPEM)
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

func testGeneration(t *testing.T, ca *testCA, key *ecdsa.PrivateKey, keyPEM []byte, instanceID string, ttl time.Duration) *generation {
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
		"the generations directory":  {path("tls.crt"), path("generations"), path("ca.crt")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := credentialVolumeFor(paths[0], paths[1], paths[2]); err == nil {
				t.Fatalf("accepted %v", paths)
			}
		})
	}
}

// get-cert does not get to trust its response. Each row is a generation a
// hostile or broken CDS could return.
func TestVerifyGenerationRejects(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	otherKey, otherKeyPEM := testKey(t)

	for name, g := range map[string]*generation{
		"a leaf for another key": func() *generation {
			g, err := issuedGeneration(ca.mustIssue(t, &otherKey.PublicKey, testInstanceID, time.Hour), key, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			return g
		}(),
		"a leaf from another CA": func() *generation {
			g := testGeneration(t, newTestCA(t), key, keyPEM, testInstanceID, time.Hour)
			g.CA = ca.cert
			g.CAPEM = []byte(ca.pem(t))
			return g
		}(),
		"no instance ID":      testGeneration(t, ca, key, keyPEM, "", time.Hour),
		"another instance ID": testGeneration(t, ca, key, keyPEM, "a7c2d41e8b96f035", time.Hour),
		"an expired leaf":     testGeneration(t, ca, key, keyPEM, testInstanceID, -time.Minute),
		"an expired CA":       testGeneration(t, ca.issueSelf(t, -time.Minute), key, keyPEM, testInstanceID, time.Hour),
		"a CA where the leaf belongs": {
			ChainPEM: []byte(ca.pem(t)),
			KeyPEM:   otherKeyPEM,
			Leaf:     ca.cert,
			Key:      otherKey,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyGeneration(g, testInstanceID, time.Now()); err == nil {
				t.Fatal("accepted an unusable generation")
			}
		})
	}
}

// CDS holds one mesh CA, so a response trailing more than one CA certificate
// is refused instead of published.
func TestIssuedGenerationRefusesTwoCAs(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	chain := ca.mustIssue(t, &key.PublicKey, testInstanceID, time.Hour) + newTestCA(t).pem(t)
	if _, err := issuedGeneration(chain, key, keyPEM); err == nil {
		t.Fatal("accepted a response carrying two CA certificates")
	}
}

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

	// The flip named a new generation and kept the one it replaced, so a reader
	// resolving the previous set still has its files.
	target, err := os.Readlink(v.pointerPath())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(target) != "2" {
		t.Fatalf("pointer = %q, want the second generation", target)
	}
	assertGenerations(t, v, "1", "2")

	third := testGeneration(t, ca, key, keyPEM, testInstanceID, 3*time.Hour)
	if err := publishGeneration(v, third); err != nil {
		t.Fatal(err)
	}
	assertReaderPaths(t, v, third)
	assertGenerations(t, v, "2", "3")

	info, err := os.Stat(filepath.Join(v.dir, v.keyName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("published key mode = %v, want 0600", info.Mode().Perm())
	}
}

// assertGenerations names the generations the volume must hold, newest last.
func assertGenerations(t *testing.T, v credentialVolume, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(v.generationsPath())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("generations = %v, want %v", got, want)
	}
}

func assertReaderPaths(t *testing.T, v credentialVolume, want *generation) {
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

// A reader resolves the pointer, then reads the generation it named. However
// many generations publish in between, it reads that whole set or nothing: no
// later generation takes the name it resolved.
func TestStoredGenerationNeverMixesTwoGenerations(t *testing.T) {
	for _, flips := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d generations publish under the reader", flips), func(t *testing.T) {
			ca := newTestCA(t)
			creds := &credentials{
				volume:     testVolume(t),
				instanceID: testInstanceID,
			}
			first, err := issueFor(ca, creds, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := creds.publish(first, time.Now()); err != nil {
				t.Fatal(err)
			}
			resolved, err := os.Readlink(creds.volume.pointerPath())
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < flips; i++ {
				next, err := issueFor(ca, creds, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := creds.publish(next, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			// A read of a generation that has since been removed fails; what it
			// must never do is succeed on a mixed set.
			published, err := generationIn(creds.volume, resolved)
			if err != nil {
				return
			}
			if !leafMatchesKey(published) {
				t.Fatal("a reader paired a leaf with another generation's key")
			}
			if !published.Leaf.Equal(first.Leaf) {
				t.Fatal("another generation took the name the reader resolved")
			}
		})
	}
}

func publishedVolume(t *testing.T, ca *testCA) (credentialVolume, *generation, *ecdsa.PrivateKey) {
	t.Helper()
	v := testVolume(t)
	key, keyPEM := testKey(t)
	creds := &credentials{
		volume:     v,
		instanceID: testInstanceID,
	}
	g := testGeneration(t, ca, key, keyPEM, testInstanceID, time.Hour)
	if err := creds.publish(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	return v, g, key
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
	creds := &credentials{
		volume:     testVolume(t),
		instanceID: testInstanceID,
	}
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

// What a restart resumes: the generation on its volume, with the key that
// generation was published with, or nothing when the pod has published nothing
// yet.
func TestLoadCredentialsResumesWhatTheVolumeHolds(t *testing.T) {
	t.Run("a published generation resumes with its own key", func(t *testing.T) {
		v, published, key := publishedVolume(t, newTestCA(t))
		creds, err := loadCredentials(v, testInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if creds.current == nil || !creds.current.Leaf.Equal(published.Leaf) {
			t.Fatal("the published generation was not resumed")
		}
		if !creds.current.Key.Equal(key) {
			t.Fatal("the resumed generation does not carry the key it was published with")
		}
		if err := creds.adoptStoredGeneration(time.Now()); err != nil {
			t.Fatalf("a valid generation was not adopted: %v", err)
		}
	})

	t.Run("an empty volume bootstraps", func(t *testing.T) {
		creds, err := loadCredentials(testVolume(t), testInstanceID)
		if err != nil {
			t.Fatal(err)
		}
		if creds.current != nil {
			t.Fatal("a first start must hold no generation")
		}
	})

	t.Run("a partial generation is refused", func(t *testing.T) {
		v, _, _ := publishedVolume(t, newTestCA(t))
		target, err := os.Readlink(v.pointerPath())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(v.dir, target, v.caName)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCredentials(v, testInstanceID); err == nil {
			t.Fatal("a partial generation was resumed")
		}
	})
}

// A generation naming another workload instance is never resumed, however
// intact it is.
func TestAdoptStoredGenerationRefusesAnotherInstance(t *testing.T) {
	v, _, _ := publishedVolume(t, newTestCA(t))
	creds, err := loadCredentials(v, "d4e9b1760c3a8f52")
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.adoptStoredGeneration(time.Now()); err == nil {
		t.Fatal("adopted the generation of another workload instance")
	}
}
