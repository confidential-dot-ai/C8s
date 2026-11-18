package volume

import (
	"strings"
	"testing"
)

func validVerity() Verity {
	return Verity{
		RootHash:   strings.Repeat("ab", verityHashBytes),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 4,
		HashOffset: 4 * VerityBlockSize,
	}
}

func validBlob(t *testing.T) Blob {
	t.Helper()
	b, err := NewBlob("weights", testKey(), validVerity())
	if err != nil {
		t.Fatalf("new blob: %v", err)
	}
	return b
}

func TestBlobRoundTrips(t *testing.T) {
	raw, err := validBlob(t).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "weights" {
		t.Fatalf("name = %q, want weights", got.Name)
	}
	key, err := got.DecodeKey()
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if len(key) != KeyBytes {
		t.Fatalf("key is %d bytes, want %d", len(key), KeyBytes)
	}
	if got.Verity == nil || *got.Verity != validVerity() {
		t.Fatalf("verity: got %+v, want %+v", got.Verity, validVerity())
	}
}

func TestNewBlobRejectsWrongKeyLength(t *testing.T) {
	if _, err := NewBlob("weights", make([]byte, 32), validVerity()); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

// A document carrying more than this format describes is an error: silently
// dropping a field would let a future field be ignored by an old opener.
func TestDecodeBlobRejectsUnknownFields(t *testing.T) {
	if _, err := DecodeBlob([]byte(`{"type":"c8s.volume/v1","key":"","verity":{},"extra":1}`)); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

func TestDecodeBlobRejectsWrongType(t *testing.T) {
	b := validBlob(t)
	b.Type = "c8s.volume/v2"
	raw, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := DecodeBlob(raw); err == nil {
		t.Fatal("accepted a foreign blob type")
	}
}

func TestValidateRejectsMalformedVerity(t *testing.T) {
	cases := map[string]func(*Blob){
		"root hash too short":  func(b *Blob) { b.Verity.RootHash = "abcd" },
		"root hash uppercase":  func(b *Blob) { b.Verity.RootHash = strings.ToUpper(b.Verity.RootHash) },
		"root hash not hex":    func(b *Blob) { b.Verity.RootHash = strings.Repeat("zz", verityHashBytes) },
		"salt empty":           func(b *Blob) { b.Verity.Salt = "" },
		"salt not hex":         func(b *Blob) { b.Verity.Salt = "nothex" },
		"zero data blocks":     func(b *Blob) { b.Verity.DataBlocks = 0 },
		"hash offset mismatch": func(b *Blob) { b.Verity.HashOffset = 1 },
	}
	for name, mutate := range cases {
		b := validBlob(t)
		mutate(&b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// hash_offset is where the opener starts reading the tree. If it disagreed with
// data_blocks the opener would hash the wrong bytes, so the two are checked
// against each other rather than trusted independently.
func TestValidateTiesHashOffsetToDataBlocks(t *testing.T) {
	b := validBlob(t)
	b.Verity.DataBlocks = 9
	b.Verity.HashOffset = 9 * VerityBlockSize
	if err := b.Validate(); err != nil {
		t.Fatalf("consistent geometry rejected: %v", err)
	}
	b.Verity.DataBlocks = 10
	if err := b.Validate(); err == nil {
		t.Fatal("accepted data_blocks that disagree with hash_offset")
	}
}

func TestDecodeKeyFailsOnCorruptKey(t *testing.T) {
	b := validBlob(t)
	b.Key = "not base64"
	if _, err := b.DecodeKey(); err == nil {
		t.Fatal("accepted a non-base64 key")
	}
}

func TestMutableBlobRoundTrips(t *testing.T) {
	b, err := NewMutableBlob("weights", testKey())
	if err != nil {
		t.Fatalf("new mutable blob: %v", err)
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "verity") {
		t.Fatalf("mutable blob names verity: %s", raw)
	}
	got, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Mutable || got.Verity != nil {
		t.Fatalf("decoded %+v, want mutable with no verity", got)
	}
	if got.Name != "weights" {
		t.Fatalf("name = %q, want weights", got.Name)
	}
}

func TestBlobWithoutMutableFieldDecodesImmutable(t *testing.T) {
	raw, err := validBlob(t).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "mutable") {
		t.Fatalf("immutable blob names mutable: %s", raw)
	}
	got, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Mutable {
		t.Fatal("a blob without the field decoded as mutable")
	}
}

// The mode and the tree are one invariant: both present or both absent is a
// blob whose author's intent is unknowable, refused rather than disambiguated.
func TestValidateRejectsModeAndTreeMismatch(t *testing.T) {
	both := validBlob(t)
	both.Mutable = true
	if err := both.Validate(); err == nil {
		t.Error("accepted mutable with verity geometry")
	}

	neither, err := NewMutableBlob("weights", testKey())
	if err != nil {
		t.Fatalf("new mutable blob: %v", err)
	}
	neither.Mutable = false
	if err := neither.Validate(); err == nil {
		t.Error("accepted immutable without verity geometry")
	}
}

func TestNewMutableBlobRejectsWrongKeyLength(t *testing.T) {
	if _, err := NewMutableBlob("weights", make([]byte, 32)); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

func TestBlobRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "Weights", "../weights", strings.Repeat("a", MaxNameLen+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBlob(name, testKey(), validVerity()); err == nil {
				t.Error("immutable constructor accepted an invalid name")
			}
			if _, err := NewMutableBlob(name, testKey()); err == nil {
				t.Error("mutable constructor accepted an invalid name")
			}
			mutable, err := NewMutableBlob("weights", testKey())
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range []Blob{validBlob(t), mutable} {
				b.Name = name
				raw, err := b.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := DecodeBlob(raw); err == nil {
					t.Errorf("decoded an invalid name (mutable=%t)", b.Mutable)
				}
			}
		})
	}
}

func TestDecodeBlobRejectsMissingName(t *testing.T) {
	raw, err := validBlob(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), `"name":"weights",`, ""))
	if _, err := DecodeBlob(raw); err == nil {
		t.Fatal("accepted a nameless blob")
	}
}
