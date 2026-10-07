// Credential generations on the pod's private credential volume, under the
// directory the leaf, key and CA paths share:
//
//	generations/a|b/     one complete credential set, written before it is named
//	current              symlink to the published generation
//	<leaf> <key> <ca>    symlinks through current: the paths readers keep
//	issuer               the CA key the pod is bound to, written once
//
// One rename of current publishes a set and one removal withdraws it, so a
// reader resolves a whole generation or nothing, and that pointer is the
// notification consumers watch.

package getcert

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	generationsSubdir = "generations"
	pointerName       = "current"
	issuerRecordName  = "issuer"
)

// generationSlots alternate: publication writes the slot the pointer does not
// name, so a reader part-way through the published set keeps its files.
var generationSlots = [2]string{"a", "b"}

var (
	errNoGeneration   = errors.New("no generation is published")
	errNoIssuerRecord = errors.New("no issuer record")
	errUnboundIssuer  = errors.New("certificate is issued under another CA key")

	// errGenerationExpired separates a set that simply ran out from one that
	// does not hold together: only the first is the ordinary end of a
	// generation's life.
	errGenerationExpired = errors.New("generation has expired")

	// errFailClosed is the state a pod cannot leave: it is bound to a CA key
	// but holds no generation it can prove it was already using, so it
	// publishes nothing until the pod is recreated.
	errFailClosed = errors.New("credential state is incomplete; fail closed until the pod is recreated")
)

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
	taken := map[string]bool{generationsSubdir: true, pointerName: true, issuerRecordName: true}
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
func (v credentialVolume) issuerPath() string  { return filepath.Join(v.dir, issuerRecordName) }

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

// generationExpiry is when the set stops being usable: the first NotAfter of
// the leaf and of the CA set it chains to. A set without a leaf has no expiry.
func generationExpiry(g *Generation) time.Time {
	if g == nil || g.Leaf == nil {
		return time.Time{}
	}
	expiry := g.Leaf.NotAfter
	for _, ca := range g.CASet {
		if ca.NotAfter.Before(expiry) {
			expiry = ca.NotAfter
		}
	}
	return expiry
}

// issuerKeyID identifies a CA key: SHA-256 over its SPKI DER, so a CA
// certificate renewed under the same key keeps one identity.
type issuerKeyID string

func issuerKeyIDOf(cert *x509.Certificate) (issuerKeyID, error) {
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal CA public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return issuerKeyID(hex.EncodeToString(sum[:])), nil
}

// verifyGeneration is the check CDS's response does not get to skip: the leaf
// matches the key it was issued for, names the pod's workload instance, and
// chains to the generation's own CA set at now. It returns the issuing CA key.
func verifyGeneration(g *Generation, instanceID string, now time.Time) (issuerKeyID, error) {
	if !leafMatchesKey(g) {
		return "", errors.New("leaf public key does not match the pod's private key")
	}
	if err := requireInstanceID(g.Leaf, instanceID); err != nil {
		return "", err
	}
	issuer, err := chainIssuer(g, now)
	if err != nil {
		return "", err
	}
	return issuerKeyIDOf(issuer)
}

// validateGeneration accepts a generation only under the CA key the pod is
// bound to, so neither a renewal nor a restart adopts a replacement key.
func validateGeneration(g *Generation, instanceID string, bound issuerKeyID, now time.Time) error {
	issuer, err := verifyGeneration(g, instanceID, now)
	if err != nil {
		return err
	}
	if issuer != bound {
		return fmt.Errorf("%w: issued under %s, the pod is bound to %s", errUnboundIssuer, issuer, bound)
	}
	return nil
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

// chainIssuer returns the CA in the generation's own set that the leaf chains
// to at now. That set is the only anchor a consumer of this generation has.
func chainIssuer(g *Generation, now time.Time) (*x509.Certificate, error) {
	if expiry := generationExpiry(g); !expiry.IsZero() && now.After(expiry) {
		return nil, fmt.Errorf("%w at %s", errGenerationExpired, expiry.Format(time.RFC3339))
	}
	roots := x509.NewCertPool()
	for _, ca := range g.CASet {
		roots.AddCert(ca)
	}
	chains, err := g.Leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("leaf does not chain to the generation's CA set: %w", err)
	}
	return chains[0][1], nil
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

// withdrawGeneration removes the pointer, so every reader path dangles and no
// consumer can read the withdrawn set.
func withdrawGeneration(v credentialVolume) error {
	if err := os.Remove(v.pointerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("withdraw generation: %w", err)
	}
	slog.Warn("credential generation withdrawn", "dir", v.dir)
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

// loadIssuerRecord reads the CA key the pod is bound to. The record outlives
// withdrawal, so errNoIssuerRecord means no generation was ever published here.
func loadIssuerRecord(v credentialVolume) (issuerKeyID, error) {
	data, err := os.ReadFile(v.issuerPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", errNoIssuerRecord
	}
	if err != nil {
		return "", fmt.Errorf("read issuer record: %w", err)
	}
	id := issuerKeyID(strings.TrimSpace(string(data)))
	if raw, err := hex.DecodeString(string(id)); err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("issuer record %s is not a CA key fingerprint", v.issuerPath())
	}
	return id, nil
}

func writeIssuerRecord(v credentialVolume, id issuerKeyID) error {
	if err := fileutil.WriteAtomic(v.issuerPath(), []byte(string(id)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write issuer record: %w", err)
	}
	slog.Info("pod bound to CDS CA key", "issuer_key", id)
	return nil
}

// credentials is the pod's credential state: the volume it publishes on, the
// workload instance every leaf must name, the CA key it is bound to, and the
// key and generation it holds.
type credentials struct {
	volume     credentialVolume
	instanceID string
	issuer     issuerKeyID
	key        *ecdsa.PrivateKey
	keyPEM     []byte
	current    *Generation
}

// loadCredentials reads what the volume holds. Neither an issuer record nor a
// published generation is a first bootstrap; any other incomplete state is
// fail-closed, because a pod that cannot show the credentials it was using must
// not re-bind to whichever CA key answers next (R3).
func loadCredentials(v credentialVolume, instanceID string) (*credentials, error) {
	record, recordErr := loadIssuerRecord(v)
	stored, storedErr := storedGeneration(v)
	switch {
	case errors.Is(recordErr, errNoIssuerRecord) && errors.Is(storedErr, errNoGeneration):
		key, keyPEM, err := generateKey()
		if err != nil {
			return nil, err
		}
		return &credentials{volume: v, instanceID: instanceID, key: key, keyPEM: keyPEM}, nil
	case recordErr != nil:
		return nil, fmt.Errorf("%w: issuer record: %w", errFailClosed, recordErr)
	case storedErr != nil:
		return nil, fmt.Errorf("%w: published generation: %w", errFailClosed, storedErr)
	default:
		return &credentials{volume: v, instanceID: instanceID, issuer: record, key: stored.Key, keyPEM: stored.KeyPEM, current: stored}, nil
	}
}

// adoptStoredGeneration keeps a restart's generation only while it still
// validates under the recorded issuer, and withdraws it otherwise: a pod adopts
// its key and credentials only from a generation it can revalidate, so no
// restart publishes under another CA key.
func (c *credentials) adoptStoredGeneration(now time.Time) error {
	if c.current == nil {
		return nil
	}
	err := validateGeneration(c.current, c.instanceID, c.issuer, now)
	if err == nil {
		slog.Info("adopted the published generation", "expires", generationExpiry(c.current))
		return nil
	}
	if withdrawErr := withdrawGeneration(c.volume); withdrawErr != nil {
		return errors.Join(err, withdrawErr)
	}
	return fmt.Errorf("%w: published generation: %w", errFailClosed, err)
}

// publish is the only way a generation becomes readable: validate it, bind the
// pod's issuer at the first publication, then flip the pointer.
func (c *credentials) publish(g *Generation, now time.Time) error {
	issuer, err := verifyGeneration(g, c.instanceID, now)
	if err != nil {
		return err
	}
	if err := c.bindIssuer(issuer); err != nil {
		return err
	}
	if err := publishGeneration(c.volume, g); err != nil {
		return err
	}
	c.current = g
	return nil
}

// bindIssuer records the pod's CA key at its first publication and refuses any
// other key for the pod's lifetime, so a replaced key is never adopted (R3).
func (c *credentials) bindIssuer(issuer issuerKeyID) error {
	if c.issuer == "" {
		if err := writeIssuerRecord(c.volume, issuer); err != nil {
			return err
		}
		c.issuer = issuer
		return nil
	}
	if issuer != c.issuer {
		return fmt.Errorf("%w: issued under %s, the pod is bound to %s", errUnboundIssuer, issuer, c.issuer)
	}
	return nil
}

// withdrawUnusable withdraws the published generation once it stops validating,
// so a failed renewal never leaves an expired set readable (R4).
func (c *credentials) withdrawUnusable(now time.Time) error {
	if c.current == nil {
		return nil
	}
	err := validateGeneration(c.current, c.instanceID, c.issuer, now)
	if err == nil {
		return nil
	}
	slog.Error("published generation is no longer usable, withdrawing it", "error", err)
	if err := withdrawGeneration(c.volume); err != nil {
		return err
	}
	c.current = nil
	return nil
}
