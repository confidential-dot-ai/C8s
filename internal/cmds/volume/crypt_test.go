package volume

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/xts"
)

func sectors(n int) []byte {
	b := make([]byte, n*SectorSize)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func testKey() []byte {
	k := make([]byte, KeyBytes)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestEncryptDecryptRoundTrips(t *testing.T) {
	key := testKey()
	for _, n := range []int{1, 2, 17} {
		plain := sectors(n)
		var ct, back bytes.Buffer
		if err := Encrypt(&ct, bytes.NewReader(plain), key); err != nil {
			t.Fatalf("%d sectors: encrypt: %v", n, err)
		}
		if ct.Len() != len(plain) {
			t.Fatalf("%d sectors: ciphertext is %d bytes, want %d", n, ct.Len(), len(plain))
		}
		if bytes.Equal(ct.Bytes(), plain) {
			t.Fatalf("%d sectors: ciphertext equals plaintext", n)
		}
		if err := Decrypt(&back, bytes.NewReader(ct.Bytes()), key); err != nil {
			t.Fatalf("%d sectors: decrypt: %v", n, err)
		}
		if !bytes.Equal(back.Bytes(), plain) {
			t.Fatalf("%d sectors: round trip differs", n)
		}
	}
}

// Each sector is tweaked by its own index, so identical plaintext sectors must
// not produce identical ciphertext. If this fails the tweak is not advancing
// and the image leaks which blocks are equal.
func TestEncryptTweaksPerSector(t *testing.T) {
	plain := make([]byte, 4*SectorSize) // all zero: every sector identical
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(plain), testKey()); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	out := ct.Bytes()
	first := out[:SectorSize]
	for i := 1; i < 4; i++ {
		if bytes.Equal(first, out[i*SectorSize:(i+1)*SectorSize]) {
			t.Fatalf("sector %d ciphertext equals sector 0: tweak is not advancing", i)
		}
	}
}

// The wire format is "XTS over 512-byte sectors, tweak = sector index", which
// is what dm-crypt aes-xts-plain64 does. Pinning it against the library
// directly means a change in our framing (sector size, tweak origin, ordering)
// fails here rather than as an unopenable volume on a node.
func TestEncryptMatchesRawXTSPerSectorTweak(t *testing.T) {
	key := testKey()
	plain := sectors(3)

	var got bytes.Buffer
	if err := Encrypt(&got, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		t.Fatalf("xts: %v", err)
	}
	want := make([]byte, len(plain))
	for s := range 3 {
		lo, hi := s*SectorSize, (s+1)*SectorSize
		c.Encrypt(want[lo:hi], plain[lo:hi], uint64(s))
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("ciphertext does not match per-sector XTS with the sector index as tweak")
	}
}

// Padding an unaligned payload would change the bytes dm-verity was formatted
// over, so it is refused instead.
func TestEncryptRejectsUnalignedPayload(t *testing.T) {
	var out bytes.Buffer
	err := Encrypt(&out, strings.NewReader(strings.Repeat("x", SectorSize+7)), testKey())
	if !errors.Is(err, ErrUnaligned) {
		t.Fatalf("got %v, want ErrUnaligned", err)
	}
}

func TestEncryptRejectsWrongKeyLength(t *testing.T) {
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(sectors(1)), make([]byte, 32)); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

func TestGenerateKeyIsFreshAndFullLength(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(a) != KeyBytes {
		t.Fatalf("key is %d bytes, want %d", len(a), KeyBytes)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated keys are equal")
	}
}

func TestDecryptWithWrongKeyDoesNotRecoverPlaintext(t *testing.T) {
	plain := sectors(2)
	var ct, back bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(plain), testKey()); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wrong := make([]byte, KeyBytes)
	if err := Decrypt(&back, bytes.NewReader(ct.Bytes()), wrong); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if bytes.Equal(back.Bytes(), plain) {
		t.Fatal("wrong key recovered the plaintext")
	}
}

// The parallel path must be byte-identical to the serial one for every job
// count, including a payload that ends in a partial chunk.
func TestEncryptAtMatchesEncrypt(t *testing.T) {
	key := testKey()
	plain := make([]byte, 3*chunkSize+5*SectorSize)
	if _, err := rand.Read(plain[chunkSize:]); err != nil { // first chunk stays zero
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := Encrypt(&want, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for _, jobs := range []int{1, 2, 3, 8} {
		out, err := os.Create(filepath.Join(t.TempDir(), "img"))
		if err != nil {
			t.Fatal(err)
		}
		if err := EncryptAt(out, bytes.NewReader(plain), key, jobs); err != nil {
			t.Fatalf("jobs=%d: %v", jobs, err)
		}
		got, err := os.ReadFile(out.Name())
		out.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("jobs=%d: output differs from Encrypt", jobs)
		}
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "img"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := EncryptAt(out, bytes.NewReader(plain[:chunkSize+7]), key, 2); !errors.Is(err, ErrUnaligned) {
		t.Fatalf("unaligned payload: err = %v, want ErrUnaligned", err)
	}
}
