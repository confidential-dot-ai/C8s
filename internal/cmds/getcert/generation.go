// Credential generations on the pod's private credential volume, under the
// directory the leaf, key and CA paths share:
//
//	generations/<n>/     one complete credential set, written before it is named
//	current              symlink to the published generation
//	<leaf> <key> <ca>    hard links into it: the paths readers keep
//
// One rename of current publishes a set, and <n> only counts up, so a reader
// that resolved the pointer reads that whole generation or nothing, never two
// generations mixed. That pointer is the notification consumers watch. The
// three reader paths are relinked behind it, one rename each.

package getcert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	generationsSubdir = "generations"
	pointerName       = "current"
)

var errNoGeneration = errors.New("no generation is published")

// generation is one credential set: a key, the leaf CDS issued for it, and the
// mesh CA that leaf chains to.
type generation struct {
	ChainPEM []byte
	KeyPEM   []byte
	CAPEM    []byte
	Leaf     *x509.Certificate
	Key      *ecdsa.PrivateKey
	CA       *x509.Certificate
}

// credentialVolume is the private volume a pod publishes on, named by the file
// names its readers use.
type credentialVolume struct {
	dir      string
	leafName string
	keyName  string
	caName   string
}

// credentialVolumeFor requires the three published files in one directory under
// distinct names: one pointer covers a generation only if it covers all three.
func credentialVolumeFor(certPath, keyPath, caPath string) (credentialVolume, error) {
	var dir string
	for _, path := range []string{certPath, keyPath, caPath} {
		// Resolved, not compared as written: two spellings of one directory
		// are one directory.
		resolved, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return credentialVolume{}, err
		}
		if dir == "" {
			dir = resolved
		}
		if resolved != dir {
			return credentialVolume{}, fmt.Errorf("--cert-path, --key-path and --ca-path must name files in one directory; %q is not in %q", path, dir)
		}
	}
	v := credentialVolume{
		dir:      dir,
		leafName: filepath.Base(certPath),
		keyName:  filepath.Base(keyPath),
		caName:   filepath.Base(caPath),
	}
	if err := requireDistinctNames(v.names()); err != nil {
		return credentialVolume{}, err
	}
	return v, nil
}

// requireDistinctNames rejects a reader name that collides with another reader
// path or with the volume's own entries.
func requireDistinctNames(names []string) error {
	taken := map[string]bool{generationsSubdir: true, pointerName: true}
	for _, name := range names {
		if taken[name] {
			return fmt.Errorf("%q is reserved by the credential volume or names two of --cert-path, --key-path and --ca-path", name)
		}
		taken[name] = true
	}
	return nil
}

func (v credentialVolume) names() []string {
	return []string{v.leafName, v.keyName, v.caName}
}

func (v credentialVolume) pointerPath() string {
	return filepath.Join(v.dir, pointerName)
}

func (v credentialVolume) generationsPath() string {
	return filepath.Join(v.dir, generationsSubdir)
}

// publishedName is the generation the pointer names, empty on a volume that has
// published nothing.
func (v credentialVolume) publishedName() (string, error) {
	target, err := os.Readlink(v.pointerPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read generation pointer: %w", err)
	}
	return filepath.Base(target), nil
}

// nextName is one past the highest generation the volume holds. A name is never
// handed out twice, so the directory a reader resolved through the pointer holds
// that generation for as long as it exists.
func (v credentialVolume) nextName() (string, error) {
	entries, err := os.ReadDir(v.generationsPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read generations directory: %w", err)
	}
	var highest uint64
	for _, entry := range entries {
		n, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			return "", fmt.Errorf("generations directory holds %q, which is not a generation", entry.Name())
		}
		if n > highest {
			highest = n
		}
	}
	return strconv.FormatUint(highest+1, 10), nil
}

// pruneGenerations removes every generation but the ones named: the published
// one and the one it replaced, which a reader that resolved the pointer just
// before the flip is still entitled to read.
func (v credentialVolume) pruneGenerations(published, previous string) error {
	entries, err := os.ReadDir(v.generationsPath())
	if err != nil {
		return fmt.Errorf("read generations directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == published || entry.Name() == previous {
			continue
		}
		if err := os.RemoveAll(filepath.Join(v.generationsPath(), entry.Name())); err != nil {
			return fmt.Errorf("remove generation %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// issuedGeneration is the set CDS just returned: the chain is leaf first with
// its CA trailing.
func issuedGeneration(chainPEM string, key *ecdsa.PrivateKey, keyPEM []byte) (*generation, error) {
	caPEM, err := caBundleFromChain([]byte(chainPEM))
	if err != nil {
		return nil, err
	}
	return newGeneration([]byte(chainPEM), keyPEM, caPEM, key)
}

// storedGeneration is the published set, read from the directory the pointer
// names so a flip part-way through cannot mix two generations.
func storedGeneration(v credentialVolume) (*generation, error) {
	target, err := os.Readlink(v.pointerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoGeneration
	}
	if err != nil {
		return nil, fmt.Errorf("read generation pointer: %w", err)
	}
	return generationIn(v, target)
}

// generationIn reads the set in one generation directory, which is what a reader
// holds once it has resolved the pointer.
func generationIn(v credentialVolume, target string) (*generation, error) {
	dir := filepath.Join(v.dir, target)
	chainPEM, err := os.ReadFile(filepath.Join(dir, v.leafName))
	if err != nil {
		return nil, fmt.Errorf("read published generation: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, v.keyName))
	if err != nil {
		return nil, fmt.Errorf("read published generation: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, v.caName))
	if err != nil {
		return nil, fmt.Errorf("read published generation: %w", err)
	}
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("published generation key: %w", err)
	}
	return newGeneration(chainPEM, keyPEM, caPEM, key)
}

func newGeneration(chainPEM, keyPEM, caPEM []byte, key *ecdsa.PrivateKey) (*generation, error) {
	leaf, err := certutil.ParseCertificatePEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("generation leaf: %w", err)
	}
	ca, err := soleCA(caPEM)
	if err != nil {
		return nil, fmt.Errorf("generation CA: %w", err)
	}
	return &generation{
		ChainPEM: chainPEM,
		KeyPEM:   keyPEM,
		CAPEM:    caPEM,
		Leaf:     leaf,
		Key:      key,
		CA:       ca,
	}, nil
}

// soleCA is the one mesh CA a generation's CA file holds. CDS holds one mesh
// CA, so any other count is a response or a file this pod does not accept.
func soleCA(caPEM []byte) (*x509.Certificate, error) {
	cas, err := certutil.ParsePEMCertificates(caPEM)
	if err != nil {
		return nil, err
	}
	if len(cas) != 1 {
		return nil, fmt.Errorf("holds %d certificates, want the one mesh CA", len(cas))
	}
	return cas[0], nil
}

// generationExpiry is when the set stops being usable. A set without a leaf has
// no expiry.
func generationExpiry(g *generation) time.Time {
	if g == nil || g.Leaf == nil {
		return time.Time{}
	}
	return g.Leaf.NotAfter
}

// verifyGeneration is the check CDS's response does not get to skip: the leaf
// matches the key it was issued for, names the pod's workload instance, and
// chains to the generation's own CA at now.
func verifyGeneration(g *generation, instanceID string, now time.Time) error {
	if !leafMatchesKey(g) {
		return errors.New("leaf public key does not match the private key it was requested for")
	}
	if err := requireInstanceID(g.Leaf, instanceID); err != nil {
		return err
	}
	return chainIssuer(g, now)
}

func leafMatchesKey(g *generation) bool {
	pub, ok := g.Leaf.PublicKey.(*ecdsa.PublicKey)
	return ok && g.Key.PublicKey.Equal(pub)
}

// requireInstanceID compares the leaf's instance-ID extension byte-exactly with
// the instance the node inventory asserted for this pod.
func requireInstanceID(leaf *x509.Certificate, instanceID string) error {
	id, err := armtls.SandboxIDFromCert(leaf)
	if err != nil {
		return fmt.Errorf("leaf instance ID: %w", err)
	}
	if id != instanceID {
		return fmt.Errorf("leaf names workload instance %q, the inventory asserted %q", id, instanceID)
	}
	return nil
}

// chainIssuer checks the leaf against the generation's own CA at now. That CA
// is the only anchor a consumer of this generation has.
func chainIssuer(g *generation, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(g.CA)
	if _, err := g.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("leaf does not chain to the generation's CA: %w", err)
	}
	return nil
}

// publishGeneration writes one generation and renames the pointer onto it, so
// readers move from the whole previous set to the whole new one.
func publishGeneration(v credentialVolume, g *generation) error {
	previous, err := v.publishedName()
	if err != nil {
		return err
	}
	name, err := v.nextName()
	if err != nil {
		return err
	}
	target := filepath.Join(generationsSubdir, name)
	dir := filepath.Join(v.dir, target)
	if err := os.MkdirAll(v.generationsPath(), 0o755); err != nil {
		return fmt.Errorf("create generations directory: %w", err)
	}
	// Mkdir, not MkdirAll: a name in use would carry files this set does not
	// write, and no two generations share a name.
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("create generation directory: %w", err)
	}
	keyMode, err := privateKeyMode(filepath.Join(dir, v.keyName))
	if err != nil {
		return fmt.Errorf("determine key permissions: %w", err)
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		if err := fileutil.WriteAtomic(filepath.Join(dir, name), data, mode); err != nil {
			return fmt.Errorf("write generation %s: %w", name, err)
		}
		return nil
	}
	if err := write(v.keyName, g.KeyPEM, keyMode); err != nil {
		return err
	}
	if err := write(v.caName, g.CAPEM, 0o644); err != nil {
		return err
	}
	if err := write(v.leafName, g.ChainPEM, 0o644); err != nil {
		return err
	}
	if err := replaceSymlink(v.pointerPath(), target); err != nil {
		return fmt.Errorf("publish generation: %w", err)
	}
	// After the flip, so a reader path never resolves to a pointer that names
	// no generation.
	if err := linkReaderPaths(v, target); err != nil {
		return err
	}
	if err := v.pruneGenerations(name, previous); err != nil {
		return err
	}
	slog.Info("credential generation published", "generation", target, "expires", generationExpiry(g))
	return nil
}

// linkReaderPaths points each reader path at the generation just published.
// Hard links, not symlinks through the pointer: the volume root is a
// world-writable sticky tmpfs, where fs.protected_symlinks refuses a symlink to
// every reader whose UID is not the publisher's — the workload container's.
func linkReaderPaths(v credentialVolume, target string) error {
	for _, name := range v.names() {
		if err := replaceLink(filepath.Join(v.dir, name), filepath.Join(v.dir, target, name)); err != nil {
			return fmt.Errorf("link reader path %s: %w", name, err)
		}
	}
	return nil
}

// replaceSymlink points path at target in one rename, so a reader following
// path resolves either the old target or the new one and never nothing.
func replaceSymlink(path, target string) error {
	tmp, err := linkTempPath(path)
	if err != nil {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// replaceLink points path at target's inode in one rename, so a reader opening
// path gets either the old file or the new one and never nothing.
func replaceLink(path, target string) error {
	tmp, err := linkTempPath(path)
	if err != nil {
		return err
	}
	if err := os.Link(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// linkTempPath is the same-directory name a replacement link is created under
// before its rename onto path.
func linkTempPath(path string) (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate link temp name: %w", err)
	}
	name := "." + filepath.Base(path) + "." + hex.EncodeToString(suffix[:]) + ".tmp"
	return filepath.Join(filepath.Dir(path), name), nil
}

// credentials is the pod's credential state: the volume it publishes on, the
// workload instance every leaf must name, and the generation it holds. A key
// belongs to its generation, never to the pod.
type credentials struct {
	volume     credentialVolume
	instanceID string
	current    *generation
}

// loadCredentials reads what the volume holds: the generation a restart serves
// on until its next renewal, or nothing on the pod's first start.
func loadCredentials(v credentialVolume, instanceID string) (*credentials, error) {
	stored, err := storedGeneration(v)
	switch {
	case errors.Is(err, errNoGeneration):
		return &credentials{
			volume:     v,
			instanceID: instanceID,
		}, nil
	case err != nil:
		return nil, err
	default:
		return &credentials{
			volume:     v,
			instanceID: instanceID,
			current:    stored,
		}, nil
	}
}

// adoptStoredGeneration reuses a restart's generation only while it still
// verifies, so a pod runs on credentials it has checked or on none at all: a
// generation naming another workload instance is never resumed.
func (c *credentials) adoptStoredGeneration(now time.Time) error {
	if c.current == nil {
		return nil
	}
	if err := verifyGeneration(c.current, c.instanceID, now); err != nil {
		return fmt.Errorf("published generation: %w", err)
	}
	slog.Info("adopted the published generation", "expires", generationExpiry(c.current))
	return nil
}

// publish is the only way a generation becomes readable: verify it, then flip
// the pointer.
func (c *credentials) publish(g *generation, now time.Time) error {
	if err := verifyGeneration(g, c.instanceID, now); err != nil {
		return err
	}
	if err := publishGeneration(c.volume, g); err != nil {
		return err
	}
	c.current = g
	return nil
}
