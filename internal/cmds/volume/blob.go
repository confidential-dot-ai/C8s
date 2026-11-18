// Package volume implements the `c8s volume` operator CLI: building an
// encrypted block image and putting its key into the CDS secret store.
//
// The image is plain dm-crypt — erofs with a dm-verity tree inside it for an
// immutable volume, writable ext4 for a mutable one. There is deliberately no
// LUKS header: a LUKS2 header is on-disk metadata whose only integrity is an
// unkeyed checksum the host can recompute, and it is parsed as root inside the
// TEE on every open. Plain dm-crypt has no on-disk metadata at all, so every
// parameter comes from the key blob, which travels over the attested channel.
package volume

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// BlobType identifies the key blob's format. It is the first thing checked on
// decode, so a foreign or malformed document fails loudly rather than parsing
// as a blob with zero-valued fields.
const BlobType = "c8s.volume/v1"

// KeyBytes is the XTS key length: two AES-256 keys, matching dm-crypt's
// --key-size 512.
const KeyBytes = 64

// verityHashBytes is the length of a SHA-256 root hash. The hash algorithm is
// fixed rather than carried in the blob — a field with one legal value is a
// field an attacker gets to choose.
const verityHashBytes = 32

// Blob is what the store holds for one volume: everything needed to open it,
// and nothing that could be taken from anywhere else.
//
// Two shapes, and exactly two. An immutable volume (erofs under dm-verity)
// carries Verity: the root hash rides here rather than in an annotation or the
// allowlist entry because it is the integrity anchor, and an anchor the host
// can edit anchors nothing. A mutable volume (ext4 over writable dm-crypt) has
// no integrity anchor to carry — by design, the host can flip bits — so it
// carries the name and key, and Mutable says the opener must not expect a tree.
type Blob struct {
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Key     string  `json:"key"`
	Mutable bool    `json:"mutable,omitempty"`
	Verity  *Verity `json:"verity,omitempty"`
}

// Verity is the geometry needed to open the hash tree without reading a
// superblock off the device. Parsing an on-disk verity superblock would
// reintroduce exactly the host-controlled metadata parse that omitting a LUKS
// header removes, so the opener passes --no-superblock and takes all of this
// from here.
type Verity struct {
	RootHash string `json:"root_hash"`
	Salt     string `json:"salt"`
	// DataBlocks is the number of 4096-byte data blocks the tree covers.
	DataBlocks uint64 `json:"data_blocks"`
	// HashOffset is the byte offset of the hash tree within the image.
	HashOffset uint64 `json:"hash_offset"`
}

// NewBlob builds an immutable blob from a freshly generated key and the verity
// output.
func NewBlob(name string, key []byte, v Verity) (Blob, error) {
	if len(key) != KeyBytes {
		return Blob{}, fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	b := Blob{
		Type:   BlobType,
		Name:   name,
		Key:    base64.StdEncoding.EncodeToString(key),
		Verity: &v,
	}
	if err := b.Validate(); err != nil {
		return Blob{}, err
	}
	return b, nil
}

// NewMutableBlob builds a named blob for a writable volume.
func NewMutableBlob(name string, key []byte) (Blob, error) {
	if len(key) != KeyBytes {
		return Blob{}, fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	b := Blob{
		Type:    BlobType,
		Name:    name,
		Key:     base64.StdEncoding.EncodeToString(key),
		Mutable: true,
	}
	if err := b.Validate(); err != nil {
		return Blob{}, err
	}
	return b, nil
}

// DecodeBlob parses a stored value, rejecting unknown fields so a document
// carrying more than this format describes is an error rather than a blob with
// the extra silently dropped.
func DecodeBlob(raw []byte) (Blob, error) {
	var b Blob
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Blob{}, fmt.Errorf("volume: decode key blob: %w", err)
	}
	if err := b.Validate(); err != nil {
		return Blob{}, err
	}
	return b, nil
}

// Validate checks every field before any of them can reach a command line or a
// device-mapper table. The opener runs privileged, so a field it has not
// checked is a field the caller chose for it.
func (b Blob) Validate() error {
	if b.Type != BlobType {
		return fmt.Errorf("volume: key blob type is %q, want %q", b.Type, BlobType)
	}
	if err := ValidVolumeName(b.Name); err != nil {
		return fmt.Errorf("volume: key blob name: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(b.Key)
	if err != nil {
		return fmt.Errorf("volume: key is not base64: %w", err)
	}
	if len(key) != KeyBytes {
		return fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	// The mode and the tree are one invariant: mutable has no verity to check,
	// immutable cannot open without it. A blob carrying both is refused rather
	// than disambiguated, because which of the two the author meant is
	// unknowable here.
	if b.Mutable {
		if b.Verity != nil {
			return fmt.Errorf("volume: mutable blob must not carry verity geometry")
		}
		return nil
	}
	if b.Verity == nil {
		return fmt.Errorf("volume: immutable blob carries no verity geometry")
	}
	if err := validateHex("root_hash", b.Verity.RootHash, verityHashBytes); err != nil {
		return err
	}
	// veritysetup accepts a range of salt lengths; the only requirement here is
	// that it is hex and non-empty, so it can be passed through unaltered.
	if err := validateHexAny("salt", b.Verity.Salt); err != nil {
		return err
	}
	if b.Verity.DataBlocks == 0 {
		return fmt.Errorf("volume: verity data_blocks is zero")
	}
	if want := b.Verity.DataBlocks * VerityBlockSize; b.Verity.HashOffset != want {
		return fmt.Errorf("volume: verity hash_offset is %d, want %d (data_blocks * %d)",
			b.Verity.HashOffset, want, VerityBlockSize)
	}
	return nil
}

// DecodeKey returns the raw XTS key. Validate has already run, so the only way
// this fails is a caller that built a Blob without it.
func (b Blob) DecodeKey() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b.Key)
	if err != nil || len(key) != KeyBytes {
		return nil, fmt.Errorf("volume: key blob holds no usable key")
	}
	return key, nil
}

// Marshal returns the stored representation.
func (b Blob) Marshal() ([]byte, error) { return json.Marshal(b) }

// validateHex requires lowercase hex of an exact byte length. Lowercase because
// the value is compared and passed through verbatim; accepting both cases would
// make two spellings of one hash.
func validateHex(field, s string, wantBytes int) error {
	if err := validateHexAny(field, s); err != nil {
		return err
	}
	if len(s) != wantBytes*2 {
		return fmt.Errorf("volume: verity %s is %d hex chars, want %d", field, len(s), wantBytes*2)
	}
	return nil
}

func validateHexAny(field, s string) error {
	if s == "" {
		return fmt.Errorf("volume: verity %s is empty", field)
	}
	if s != strings.ToLower(s) {
		return fmt.Errorf("volume: verity %s must be lowercase hex", field)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("volume: verity %s is not hex: %w", field, err)
	}
	return nil
}
