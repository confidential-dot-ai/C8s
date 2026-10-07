// Credential generations on the pod's private credential volume, under the
// directory the leaf, key and CA paths share:
//
//	generations/a|b/     one complete credential set, written before it is named
//	current              symlink to the published generation
//	<leaf> <key> <ca>    symlinks through current: the paths readers keep
//
// One rename of current publishes a set, so a reader resolves a whole
// generation or nothing, and that pointer is the notification consumers
// watch.

package getcert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	generationsSubdir = "generations"
	pointerName       = "current"
)

// generationSlots alternate: publication writes the slot the pointer does not
// name, so a reader part-way through the published set keeps its files.
var generationSlots = [2]string{"a", "b"}

var errNoGeneration = errors.New("no generation is published")

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

func (v credentialVolume) names() []string     { return []string{v.leafName, v.keyName, v.caName} }
func (v credentialVolume) pointerPath() string { return filepath.Join(v.dir, pointerName) }

// freeSlot is the slot no reader is resolving: the one the pointer does not
// name. Guessing it could overwrite the published generation, so an unreadable
// pointer, or one naming anything but a slot, is an error.
func (v credentialVolume) freeSlot() (string, error) {
	target, err := os.Readlink(v.pointerPath())
	if errors.Is(err, os.ErrNotExist) {
		return generationSlots[0], nil
	}
	if err != nil {
		return "", fmt.Errorf("read generation pointer: %w", err)
	}
	published := filepath.Base(target)
	if !slices.Contains(generationSlots[:], published) {
		return "", fmt.Errorf("generation pointer names %q, which is not a generation slot", target)
	}
	return otherSlot(published), nil
}

func otherSlot(slot string) string {
	if slot == generationSlots[0] {
		return generationSlots[1]
	}
	return generationSlots[0]
}

// Generation is one credential set: the leaf CDS issued for the pod's key and
// the newest authenticated CA set that leaf chains to.
type Generation struct {
	ChainPEM []byte
	KeyPEM   []byte
	CAPEM    []byte
	Leaf     *x509.Certificate
	Key      *ecdsa.PrivateKey
	CASet    []*x509.Certificate
}

// issuedGeneration is the set CDS just returned: the chain is leaf first with
// its CA set trailing.
func issuedGeneration(chainPEM string, key *ecdsa.PrivateKey, keyPEM []byte) (*Generation, error) {
	caPEM, err := caBundleFromChain([]byte(chainPEM))
	if err != nil {
		return nil, err
	}
	return newGeneration([]byte(chainPEM), keyPEM, caPEM, key)
}

// storedGeneration is the published set, read from the directory the pointer
// names so a flip part-way through cannot mix two generations.
func storedGeneration(v credentialVolume) (*Generation, error) {
	target, err := os.Readlink(v.pointerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNoGeneration
	}
	if err != nil {
		return nil, fmt.Errorf("read generation pointer: %w", err)
	}
	dir := filepath.Join(v.dir, target)
	chainPEM, chainErr := os.ReadFile(filepath.Join(dir, v.leafName))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, v.keyName))
	caPEM, caErr := os.ReadFile(filepath.Join(dir, v.caName))
	if err := errors.Join(chainErr, keyErr, caErr); err != nil {
		return nil, fmt.Errorf("read published generation: %w", err)
	}
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("published generation key: %w", err)
	}
	return newGeneration(chainPEM, keyPEM, caPEM, key)
}

func newGeneration(chainPEM, keyPEM, caPEM []byte, key *ecdsa.PrivateKey) (*Generation, error) {
	leaf, err := certutil.ParseCertificatePEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("generation leaf: %w", err)
	}
	caSet, err := certutil.ParsePEMCertificates(caPEM)
	if err != nil {
		return nil, fmt.Errorf("generation CA set: %w", err)
	}
	return &Generation{ChainPEM: chainPEM, KeyPEM: keyPEM, CAPEM: caPEM, Leaf: leaf, Key: key, CASet: caSet}, nil
}

// generationExpiry is when the set stops being usable. A set without a leaf has
// no expiry.
func generationExpiry(g *Generation) time.Time {
	if g == nil || g.Leaf == nil {
		return time.Time{}
	}
	return g.Leaf.NotAfter
}

// verifyGeneration is the check CDS's response does not get to skip: the leaf
// matches the key it was issued for, names the pod's workload instance, and
// chains to the generation's own CA set at now.
func verifyGeneration(g *Generation, instanceID string, now time.Time) error {
	if !leafMatchesKey(g) {
		return errors.New("leaf public key does not match the pod's private key")
	}
	if err := requireInstanceID(g.Leaf, instanceID); err != nil {
		return err
	}
	return chainIssuer(g, now)
}

func leafMatchesKey(g *Generation) bool {
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

// chainIssuer checks the leaf against the generation's own CA set at now. That
// set is the only anchor a consumer of this generation has.
func chainIssuer(g *Generation, now time.Time) error {
	roots := x509.NewCertPool()
	for _, ca := range g.CASet {
		roots.AddCert(ca)
	}
	if _, err := g.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("leaf does not chain to the generation's CA set: %w", err)
	}
	return nil
}

// publishGeneration writes one generation and renames the pointer onto it, so
// readers move from the whole previous set to the whole new one.
func publishGeneration(v credentialVolume, g *Generation) error {
	slot, err := v.freeSlot()
	if err != nil {
		return err
	}
	target := filepath.Join(generationsSubdir, slot)
	dir := filepath.Join(v.dir, target)
	// Emptied first: a file of the generation two flips old that this set does
	// not write would be read as part of this one.
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("empty generation directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
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
	if err := errors.Join(
		write(v.keyName, g.KeyPEM, keyMode),
		write(v.caName, g.CAPEM, 0o644),
		write(v.leafName, g.ChainPEM, 0o644),
	); err != nil {
		return err
	}
	if err := fileutil.ReplaceSymlink(v.pointerPath(), target); err != nil {
		return fmt.Errorf("publish generation: %w", err)
	}
	// After the flip, so a reader path never resolves to a pointer that names
	// no generation.
	if err := linkReaderPaths(v); err != nil {
		return err
	}
	slog.Info("credential generation published", "generation", target, "expires", generationExpiry(g))
	return nil
}

// linkReaderPaths points each reader path through the pointer, so a reader
// resolves whichever generation is published when it opens the file.
func linkReaderPaths(v credentialVolume) error {
	for _, name := range v.names() {
		if err := fileutil.ReplaceSymlink(filepath.Join(v.dir, name), filepath.Join(pointerName, name)); err != nil {
			return fmt.Errorf("link reader path %s: %w", name, err)
		}
	}
	return nil
}

// credentials is the pod's credential state: the volume it publishes on, the
// workload instance every leaf must name, and the key and generation it holds.
type credentials struct {
	volume     credentialVolume
	instanceID string
	key        *ecdsa.PrivateKey
	keyPEM     []byte
	current    *Generation
}

// loadCredentials reads what the volume holds: the key and generation a restart
// resumes on, or a fresh key on the pod's first start.
func loadCredentials(v credentialVolume, instanceID string) (*credentials, error) {
	stored, err := storedGeneration(v)
	switch {
	case errors.Is(err, errNoGeneration):
		key, keyPEM, err := generateKey()
		if err != nil {
			return nil, err
		}
		return &credentials{volume: v, instanceID: instanceID, key: key, keyPEM: keyPEM}, nil
	case err != nil:
		return nil, err
	default:
		return &credentials{volume: v, instanceID: instanceID, key: stored.Key, keyPEM: stored.KeyPEM, current: stored}, nil
	}
}

// adoptStoredGeneration reuses a restart's generation only while it still
// verifies, so a pod runs on credentials it has checked or on none at all: a
// generation naming another workload instance is never resumed (B4).
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
func (c *credentials) publish(g *Generation, now time.Time) error {
	if err := verifyGeneration(g, c.instanceID, now); err != nil {
		return err
	}
	if err := publishGeneration(c.volume, g); err != nil {
		return err
	}
	c.current = g
	return nil
}
