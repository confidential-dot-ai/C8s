package volume

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
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

func tempImage(t *testing.T) *os.File {
	t.Helper()
	out, err := os.Create(filepath.Join(t.TempDir(), "img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
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
		if err := encrypt(&ct, bytes.NewReader(plain), key); err != nil {
			t.Fatalf("%d sectors: encrypt: %v", n, err)
		}
		if ct.Len() != len(plain) {
			t.Fatalf("%d sectors: ciphertext is %d bytes, want %d", n, ct.Len(), len(plain))
		}
		if bytes.Equal(ct.Bytes(), plain) {
			t.Fatalf("%d sectors: ciphertext equals plaintext", n)
		}
		if err := decrypt(&back, bytes.NewReader(ct.Bytes()), key); err != nil {
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
	if err := encrypt(&ct, bytes.NewReader(plain), testKey()); err != nil {
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
	if err := encrypt(&got, bytes.NewReader(plain), key); err != nil {
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
	out := tempImage(t)
	err := EncryptAt(t.Context(), out, strings.NewReader(strings.Repeat("x", SectorSize+7)), testKey(), 1)
	if !errors.Is(err, ErrUnaligned) {
		t.Fatalf("got %v, want ErrUnaligned", err)
	}
}

func TestEncryptRejectsWrongKeyLength(t *testing.T) {
	out := tempImage(t)
	if err := EncryptAt(t.Context(), out, bytes.NewReader(sectors(1)), make([]byte, 32), 1); err == nil {
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
	if err := encrypt(&ct, bytes.NewReader(plain), testKey()); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wrong := make([]byte, KeyBytes)
	if err := decrypt(&back, bytes.NewReader(ct.Bytes()), wrong); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if bytes.Equal(back.Bytes(), plain) {
		t.Fatal("wrong key recovered the plaintext")
	}
}

// Cancelling ctx must reach the caller as an error rather than a volume that is
// silently short. Which of the reader's two ready cases wins is a random
// select, so only the verdict is pinned, not how much was written.
func TestEncryptAtStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	plain := make([]byte, 4*chunkSize)
	src := &cancellingReader{
		src:    bytes.NewReader(plain),
		after:  chunkSize,
		cancel: cancel,
	}

	err := EncryptAt(ctx, tempImage(t), src, testKey(), 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// A worker that dies on its first write must not leave the reader blocked
// handing out the rest of a payload larger than the buffer pool.
func TestEncryptAtReportsWriteFailure(t *testing.T) {
	plain := make([]byte, 5*chunkSize)

	err := EncryptAt(t.Context(), failingWriterAt{}, bytes.NewReader(plain), testKey(), 1)
	if !errors.Is(err, errWriteFailed) {
		t.Fatalf("got %v, want errWriteFailed", err)
	}
}

// cancellingReader cancels the encryption once it has served after bytes.
type cancellingReader struct {
	src    io.Reader
	after  int
	read   int
	cancel context.CancelFunc
}

func (r *cancellingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.read += n
	if r.read >= r.after {
		r.cancel()
	}
	return n, err
}

var errWriteFailed = errors.New("image is full")

type failingWriterAt struct{}

func (failingWriterAt) WriteAt(p []byte, off int64) (int, error) {
	return 0, errWriteFailed
}

// The parallel path must be byte-identical to the serial one for every job
// count, including a payload that ends in a partial chunk.
func TestEncryptAtMatchesEncrypt(t *testing.T) {
	key := testKey()
	plain := make([]byte, 3*chunkSize+5*SectorSize)
	if _, err := rand.Read(plain[chunkSize:]); err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := encrypt(&want, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for _, jobs := range []int{1, 2, 3, 8} {
		out, err := os.Create(filepath.Join(t.TempDir(), "img"))
		if err != nil {
			t.Fatal(err)
		}
		if err := EncryptAt(t.Context(), out, bytes.NewReader(plain), key, jobs); err != nil {
			t.Fatalf("jobs=%d: %v", jobs, err)
		}
		got, err := os.ReadFile(out.Name())
		out.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("jobs=%d: output differs from the serial reference", jobs)
		}
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "img"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := EncryptAt(t.Context(), out, bytes.NewReader(plain[:chunkSize+7]), key, 2); !errors.Is(err, ErrUnaligned) {
		t.Fatalf("unaligned payload: err = %v, want ErrUnaligned", err)
	}
}
