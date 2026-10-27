package volume

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/xts"
	"golang.org/x/sync/errgroup"
)

// SectorSize is the dm-crypt sector size, and therefore the unit the XTS tweak
// counts in.
//
// 512 is dm-crypt's default, and the reason to keep it is the tweak. For
// aes-xts-plain64 the IV is the sector index, but with a larger --sector-size
// dm-crypt's numbering depends on whether iv_large_sectors is set — so a
// mismatch between what wrote the image and what opens it yields a volume that
// decrypts to noise with nothing to say why. At 512 there is one numbering and
// no flag to agree on.
const SectorSize = 512

// VerityBlockSize is the dm-verity data block size. Independent of SectorSize:
// verity sits above dm-crypt and counts in its own blocks.
const VerityBlockSize = 4096

// ErrUnaligned reports a payload that is not a whole number of sectors.
var ErrUnaligned = errors.New("volume: payload is not a multiple of the sector size")

// GenerateKey returns a fresh XTS key.
//
// Always fresh, never operator-supplied: AES-XTS is deterministic, so
// re-encrypting a changed directory under a reused key tells the host exactly
// which sectors changed between the two versions.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("volume: generate key: %w", err)
	}
	return key, nil
}

// Encrypt writes the ciphertext of src to dst, one sector at a time, with each
// sector's index as its XTS tweak. This is byte-for-byte what dm-crypt
// aes-xts-plain64 with a 512-bit key produces for the same input, which is what
// lets the image be built without root, a loop device, or cryptsetup.
//
// src must be sector-aligned. Padding it here would change the bytes dm-verity
// was formatted over, so an unaligned payload is refused rather than fixed.
// Builds use EncryptAt, the parallel form.
func Encrypt(dst io.Writer, src io.Reader, key []byte) error {
	return transform(dst, src, key, false)
}

// chunkSize is the unit EncryptAt hands to a worker and writes in one call: a
// whole number of sectors and of 4 KiB pages, large enough that syscalls cost
// nothing next to the cipher.
const chunkSize = 1 << 20

// EncryptAt is Encrypt spread over jobs goroutines, with the same output byte
// for byte. XTS sectors are independent, so each chunk is encrypted with its own
// starting sector as the tweak base and written at its own offset; order does not
// matter. jobs < 1 means one per CPU. Memory is jobs+1 chunks.
func EncryptAt(dst io.WriterAt, src io.Reader, key []byte, jobs int) error {
	if len(key) != KeyBytes {
		return fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	if jobs < 1 {
		jobs = runtime.NumCPU()
	}
	type chunk struct {
		buf []byte
		off int64
	}
	free := make(chan []byte, jobs+1)
	for range jobs + 1 {
		free <- make([]byte, chunkSize)
	}
	work := make(chan chunk)
	g, ctx := errgroup.WithContext(context.Background())
	for range jobs {
		g.Go(func() error {
			cipher, err := xts.NewCipher(aes.NewCipher, key)
			if err != nil {
				return fmt.Errorf("volume: init xts: %w", err)
			}
			for c := range work {
				sector := uint64(c.off / SectorSize)
				for i := 0; i < len(c.buf); i += SectorSize {
					s := c.buf[i : i+SectorSize]
					cipher.Encrypt(s, s, sector)
					sector++
				}
				if _, err := dst.WriteAt(c.buf, c.off); err != nil {
					return fmt.Errorf("volume: write at %d: %w", c.off, err)
				}
				free <- c.buf[:chunkSize]
			}
			return nil
		})
	}
	readErr := func() error {
		defer close(work)
		for off := int64(0); ; {
			var buf []byte
			select {
			case buf = <-free:
			case <-ctx.Done():
				return nil
			}
			n, err := io.ReadFull(src, buf)
			if n%SectorSize != 0 {
				return fmt.Errorf("%w: trailing %d bytes", ErrUnaligned, n%SectorSize)
			}
			if n > 0 {
				select {
				case work <- chunk{buf[:n], off}:
				case <-ctx.Done():
					return nil
				}
				off += int64(n)
			}
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				return nil
			case err != nil:
				return fmt.Errorf("volume: read at %d: %w", off, err)
			}
		}
	}()
	if err := g.Wait(); err != nil {
		return err
	}
	return readErr
}

// Decrypt is Encrypt's inverse, and exists so a build can prove its own output
// round-trips before the plaintext is discarded.
func Decrypt(dst io.Writer, src io.Reader, key []byte) error {
	return transform(dst, src, key, true)
}

func transform(dst io.Writer, src io.Reader, key []byte, decrypt bool) error {
	if len(key) != KeyBytes {
		return fmt.Errorf("volume: key is %d bytes, want %d", len(key), KeyBytes)
	}
	cipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return fmt.Errorf("volume: init xts: %w", err)
	}

	in := make([]byte, SectorSize)
	out := make([]byte, SectorSize)
	for sector := uint64(0); ; sector++ {
		n, err := io.ReadFull(src, in)
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, io.ErrUnexpectedEOF):
			return fmt.Errorf("%w: trailing %d bytes", ErrUnaligned, n)
		case err != nil:
			return fmt.Errorf("volume: read sector %d: %w", sector, err)
		}
		if decrypt {
			cipher.Decrypt(out, in, sector)
		} else {
			cipher.Encrypt(out, in, sector)
		}
		if _, err := dst.Write(out); err != nil {
			return fmt.Errorf("volume: write sector %d: %w", sector, err)
		}
	}
}
