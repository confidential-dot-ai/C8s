// Package credvolume reads the credential volume get-cert publishes on. One
// generation is published at a time behind a pointer; a reader resolves that
// pointer once and reads the generation it names, so the leaf it presents and
// the CA it trusts come from one set.
package credvolume

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PointerName is the pointer get-cert flips onto a published generation.
const PointerName = "current"

// ErrMissingPointer reports a volume that publishes no generation, which is
// how get-cert withdraws one.
var ErrMissingPointer = errors.New("credential generation pointer is missing")

// Volume is the directory get-cert publishes on: its pointer, plus the three
// file names the readers use.
type Volume struct {
	dir                        string
	chainName, keyName, caName string
}

// For requires the three reader paths in one directory under distinct names:
// one pointer covers a generation only if it covers all three.
func For(chainPath, keyPath, caPath string) (Volume, error) {
	paths := []string{chainPath, keyPath, caPath}
	dirs := map[string]bool{}
	names := map[string]bool{}
	for _, path := range paths {
		dirs[filepath.Clean(filepath.Dir(path))] = true
		names[filepath.Base(path)] = true
	}
	if len(dirs) != 1 || len(names) != 3 {
		return Volume{}, fmt.Errorf("the certificate, key and CA paths must name three different files in one directory, not %q", paths)
	}
	return Volume{
		dir:       filepath.Clean(filepath.Dir(chainPath)),
		chainName: filepath.Base(chainPath),
		keyName:   filepath.Base(keyPath),
		caName:    filepath.Base(caPath),
	}, nil
}

// PointerPath is where the pointer at the published generation lives.
func (v Volume) PointerPath() string {
	return filepath.Join(v.dir, PointerName)
}

// Read resolves the pointer once and reads the three files of the generation
// it names, so a publication part-way through cannot mix two generations.
func (v Volume) Read() (Set, error) {
	target, err := os.Readlink(v.PointerPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Set{}, fmt.Errorf("%w: %w", ErrMissingPointer, err)
		}
		return Set{}, fmt.Errorf("resolve the generation pointer: %w", err)
	}
	dir := filepath.Join(v.dir, target)
	chain, err := os.ReadFile(filepath.Join(dir, v.chainName))
	if err != nil {
		return Set{}, fmt.Errorf("read generation %s: %w", target, err)
	}
	key, err := os.ReadFile(filepath.Join(dir, v.keyName))
	if err != nil {
		return Set{}, fmt.Errorf("read generation %s: %w", target, err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, v.caName))
	if err != nil {
		return Set{}, fmt.Errorf("read generation %s: %w", target, err)
	}
	return Set{ChainPEM: chain, KeyPEM: key, CAPEM: ca}, nil
}

// Set is the PEM of one generation, as the pointer named it.
type Set struct {
	ChainPEM, KeyPEM, CAPEM []byte
}

// SameAs reports whether both sets hold the same PEM.
func (s Set) SameAs(other Set) bool {
	return bytes.Equal(s.ChainPEM, other.ChainPEM) &&
		bytes.Equal(s.KeyPEM, other.KeyPEM) &&
		bytes.Equal(s.CAPEM, other.CAPEM)
}
