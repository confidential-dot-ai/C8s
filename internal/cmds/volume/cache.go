package volume

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// CacheSecretBytes is the least secret a cache volume key is derived from:
// the size of every value CDS generates.
const CacheSecretBytes = 32

// cacheKeyInfo separates the volume key from any other use of the secret.
const cacheKeyInfo = "c8s.volume/v1 cache key"

// NewCacheBlob builds the blob for a cache volume from a secret CDS generated
// inside the TEE. No operator ever holds the key, so nothing is escrowed: if
// CDS loses the secret, the next one opens the device to noise, and
// FormatNoFilesystem gives the cache a fresh filesystem.
func NewCacheBlob(secret []byte, rootOwner string) (Blob, error) {
	if len(secret) < CacheSecretBytes {
		return Blob{}, fmt.Errorf("volume: cache secret is %d bytes, want at least %d", len(secret), CacheSecretBytes)
	}
	key, err := hkdf.Key(sha256.New, secret, nil, cacheKeyInfo, KeyBytes)
	if err != nil {
		return Blob{}, err
	}
	defer clear(key)
	b := Blob{
		Type:    BlobType,
		Key:     base64.StdEncoding.EncodeToString(key),
		Mutable: true,
		Format:  &Format{FS: "ext4", When: FormatNoFilesystem, RootOwner: rootOwner},
	}
	if err := b.Validate(); err != nil {
		return Blob{}, err
	}
	return b, nil
}
